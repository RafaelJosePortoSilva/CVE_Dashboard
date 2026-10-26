"""
DAGs do pipeline de inteligência de CVEs (EPSS + NVD).

- ``cve_daily``: execução diária incremental (EPSS do dia + NVD modificado).
  Na primeira execução, detecta que as tabelas não existem e baixa o histórico
  completo automaticamente.
- ``cve_full_refresh``: execução manual para reconstruir tudo do zero.

O pipeline em si vive em ``src/build_dataset.py`` e é acionado por etapas,
o que mantém o DAG simples e o código testável fora do Airflow.

As tarefas são encadeadas (sem paralelismo) porque o DuckDB permite apenas um
processo com acesso de escrita ao arquivo por vez.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from airflow.providers.standard.operators.bash import BashOperator
from airflow.sdk import DAG, task

PROJECT_DIR = os.getenv("CVE_PROJECT_DIR", "/opt/airflow")
SCRIPT = f"{PROJECT_DIR}/src/build_dataset.py"
PYTHON = os.getenv("CVE_PYTHON", "python")
DB_PATH = f"{PROJECT_DIR}/data/processed/cves.duckdb"

DUCKDB_MEMORY = os.getenv("CVE_DUCKDB_MEMORY_LIMIT", "2GB")
DUCKDB_THREADS = os.getenv("CVE_DUCKDB_THREADS", "2")

MIN_ROWS = int(os.getenv("CVE_MIN_ROWS", "400000"))
MIN_DESCRIPTION_RATIO = float(os.getenv("CVE_MIN_DESCRIPTION_RATIO", "0.99"))
MAX_EPSS_LAG_DAYS = int(os.getenv("CVE_MAX_EPSS_LAG_DAYS", "2"))

DEFAULT_ARGS = {
    "owner": "data-engineering",
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
    "execution_timeout": timedelta(hours=2),
}


def command(stage: str, extra: str = "") -> str:
    """Monta o comando de uma etapa com os limites de memória do DuckDB."""
    return (
        f"{PYTHON} {SCRIPT} --stages {stage} "
        f"--memory-limit {DUCKDB_MEMORY} --threads {DUCKDB_THREADS} {extra}"
    ).strip()


@task(task_id="quality_check", retries=1, retry_delay=timedelta(minutes=2))
def quality_check() -> dict:
    """Falha o DAG se a base final perder cobertura ou ficar desatualizada."""
    import duckdb

    con = duckdb.connect(DB_PATH, read_only=True)
    try:
        total, unique, description_ratio, cvss_ratio, last_epss = con.execute(
            """
            SELECT
                count(*),
                count(DISTINCT cve_id),
                avg(CASE WHEN description IS NOT NULL THEN 1.0 ELSE 0.0 END),
                avg(CASE WHEN cvss_score IS NOT NULL THEN 1.0 ELSE 0.0 END),
                max(epss_date)
            FROM cves_enriched
            """
        ).fetchone()
    finally:
        con.close()

    problems = []
    if total < MIN_ROWS:
        problems.append(f"poucas linhas: {total} (mínimo {MIN_ROWS})")
    if unique != total:
        problems.append(f"{total - unique} CVEs duplicados")
    if (description_ratio or 0) < MIN_DESCRIPTION_RATIO:
        problems.append(
            f"descrições em {description_ratio:.2%} (mínimo {MIN_DESCRIPTION_RATIO:.0%})"
        )

    lag_limit = datetime.now(timezone.utc).date() - timedelta(days=MAX_EPSS_LAG_DAYS)
    if last_epss is None or last_epss < lag_limit:
        problems.append(
            f"EPSS desatualizado: última data {last_epss} (limite {lag_limit})"
        )

    summary = {
        "rows": total,
        "unique_cves": unique,
        "description_ratio": round(description_ratio or 0, 4),
        "cvss_ratio": round(cvss_ratio or 0, 4),
        "last_epss_date": str(last_epss),
    }
    if problems:
        raise ValueError("Qualidade dos dados falhou: " + "; ".join(problems))
    return summary


def build_dag(*, full_refresh: bool) -> DAG:
    dag_id = "cve_full_refresh" if full_refresh else "cve_daily"
    date_range = "2021-04-14" if full_refresh else "{{ data_interval_end | ds }}"

    with DAG(
        dag_id=dag_id,
        description=(
            "Reconstrói a base de CVEs (EPSS + NVD) do zero"
            if full_refresh
            else "Atualiza diariamente a base de CVEs (EPSS + NVD)"
        ),
        schedule=None if full_refresh else "30 14 * * *",
        start_date=datetime(2026, 1, 1),
        catchup=False,
        max_active_runs=1,
        default_args=DEFAULT_ARGS,
        tags=["cve", "epss", "nvd", "duckdb"],
        doc_md=__doc__,
    ) as dag:
        epss_download = BashOperator(
            task_id="epss_download",
            bash_command=command(
                "epss",
                f"--epss-start {date_range} --epss-end {{{{ data_interval_end | ds }}}} "
                f"--workers {os.getenv('CVE_EPSS_WORKERS', '8')}",
            ),
            append_env=True,
            execution_timeout=timedelta(hours=3),
        )

        epss_db = BashOperator(
            task_id="epss_db",
            bash_command=command(
                "epss-db", "--epss-rebuild" if full_refresh else ""
            ),
            append_env=True,
        )

        nvd_download = BashOperator(
            task_id="nvd_download",
            bash_command=command(
                "nvd",
                "--nvd-mode full"
                if full_refresh
                else "--nvd-mode incremental --nvd-lookback-days 3",
            ),
            append_env=True,
            execution_timeout=timedelta(hours=3),
        )

        nvd_db = BashOperator(
            task_id="nvd_db",
            bash_command=command("nvd-db"),
            append_env=True,
        )

        join = BashOperator(
            task_id="join",
            bash_command=command("join"),
            append_env=True,
        )

        export = BashOperator(
            task_id="export",
            bash_command=command("export", "" if full_refresh else "--no-csv"),
            append_env=True,
        )

        apache = BashOperator(
            task_id="enrich_apache_sample",
            bash_command=command("apache"),
            append_env=True,
        )

        checks = quality_check()

        epss_download >> epss_db >> nvd_download >> nvd_db >> join
        join >> export >> apache >> checks

    return dag


cve_daily = build_dag(full_refresh=False)
cve_full_refresh = build_dag(full_refresh=True)
