#!/usr/bin/env python3
"""
Monta a base de CVEs combinando o histórico do EPSS com os dados do NVD.

Etapas (executadas em sequência por padrão):
  epss     baixa os arquivos diários do EPSS para data/raw/epss (cache resumível)
  epss-db  carrega o histórico do EPSS no DuckDB (tabela epss_history)
  nvd      baixa as páginas da API do NVD para data/raw/nvd (cache resumível)
  nvd-db   carrega os CVEs do NVD no DuckDB (tabela nvd_cves)
  join     cria epss_latest, cves_all e cves_enriched
  export   exporta cves_enriched para Parquet/CSV
  apache   enriquece Analytics/apache_cves.csv com o EPSS mais recente

Exemplos:
  python src/build_dataset.py
  python src/build_dataset.py --stages epss,epss-db
  python src/build_dataset.py --stages nvd,nvd-db,join,export
"""
import argparse
import gzip
import sys
import time
from datetime import date
from pathlib import Path

# Permite rodar tanto como `python src/build_dataset.py` quanto
# `python -m src.build_dataset` a partir da raiz do projeto.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import duckdb
import pandas as pd

from src.data.EPSS import EPSS_FIRST_DATE, download_epss_history
from src.data.NVD import fetch_nvd_pages, parse_nvd_page

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "processed" / "cves.duckdb"
EPSS_CACHE = ROOT / "data" / "raw" / "epss"
NVD_CACHE = ROOT / "data" / "raw" / "nvd"
PROCESSED = ROOT / "data" / "processed"


def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def connect(db_path, memory_limit, threads):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = ROOT / "data" / "tmp"
    temp_dir.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect(str(db_path))
    con.execute(f"SET memory_limit='{memory_limit}'")
    con.execute(f"SET threads={threads}")
    con.execute(f"SET temp_directory='{temp_dir.as_posix()}'")
    con.execute("SET preserve_insertion_order=false")
    return con


def stage_epss(args):
    log(f"Baixando EPSS de {args.epss_start} até {args.epss_end}")
    files = download_epss_history(
        start_date=args.epss_start,
        end_date=args.epss_end,
        cache_dir=EPSS_CACHE,
        max_workers=args.workers,
        verbose=True,
    )
    log(f"EPSS: {len(files)} arquivos disponíveis em {EPSS_CACHE}")
    if not files:
        raise SystemExit("Nenhum arquivo do EPSS encontrado.")


def _epss_header(path):
    """Lê o cabeçalho do CSV.gz, ignorando a linha de comentário do EPSS v2+."""
    with gzip.open(path, "rt") as handle:
        header = handle.readline().strip()
        while header.startswith("#"):
            header = handle.readline().strip()
    return [column.strip() for column in header.split(",")]


def stage_epss_db(con):
    files = sorted(EPSS_CACHE.glob("*/*.csv.gz"))
    if not files:
        raise SystemExit("Cache do EPSS vazio; rode a etapa 'epss' primeiro.")
    log(f"Carregando {len(files)} arquivos do EPSS no DuckDB...")

    con.execute("DROP TABLE IF EXISTS epss_history")
    con.execute(
        "CREATE TABLE epss_history ("
        "date DATE, cve VARCHAR, epss DOUBLE, percentile DOUBLE)"
    )

    # Insere um arquivo por vez para manter o uso de memória baixo; os arquivos
    # de 2021 (e início de 2022) não têm a coluna percentile.
    con.execute("BEGIN")
    for index, path in enumerate(files, start=1):
        day = path.name.replace("epss_scores-", "")[:10]
        has_percentile = "percentile" in _epss_header(path)
        percentile = (
            "TRY_CAST(percentile AS DOUBLE)"
            if has_percentile
            else "CAST(NULL AS DOUBLE)"
        )
        con.execute(
            f"""
            INSERT INTO epss_history
            SELECT DATE '{day}', UPPER(TRIM(cve)), CAST(epss AS DOUBLE), {percentile}
            FROM read_csv('{path.as_posix()}', header = true, comment = '#')
            """
        )
        if index % 100 == 0 or index == len(files):
            log(f"  {index}/{len(files)} arquivos")
    con.execute("COMMIT")

    rows = con.execute("SELECT count(*) FROM epss_history").fetchone()[0]
    dates = con.execute("SELECT min(date), max(date) FROM epss_history").fetchone()
    log(f"epss_history: {rows:,} linhas ({dates[0]} a {dates[1]})")


def stage_nvd(args):
    log(f"Baixando NVD de {args.nvd_start} até {args.nvd_end}")
    files = fetch_nvd_pages(
        start_date=args.nvd_start,
        end_date=args.nvd_end,
        cache_dir=NVD_CACHE,
        pause=args.nvd_pause,
        verbose=True,
    )
    log(f"NVD: {len(files)} páginas em cache em {NVD_CACHE}")


def stage_nvd_db(con):
    pages = sorted(NVD_CACHE.glob("pubStart=*/page_*.json"))
    if not pages:
        raise SystemExit("Cache do NVD vazio; rode a etapa 'nvd' primeiro.")
    log(f"Carregando {len(pages)} páginas do NVD no DuckDB...")

    con.execute("DROP TABLE IF EXISTS nvd_cves")
    con.execute(
        """
        CREATE TABLE nvd_cves (
            cve_id VARCHAR,
            published TIMESTAMP,
            last_modified TIMESTAMP,
            vuln_status VARCHAR,
            description VARCHAR,
            cvss_score DOUBLE,
            severity VARCHAR,
            cvss_version VARCHAR,
            cvss_vector VARCHAR,
            cwe_ids VARCHAR,
            reference_count INTEGER,
            "references" VARCHAR,
            cpe_uris VARCHAR
        )
        """
    )

    columns = [
        "cve_id", "published", "last_modified", "vuln_status", "description",
        "cvss_score", "severity", "cvss_version", "cvss_vector", "cwe_ids",
        "reference_count", "references", "cpe_uris",
    ]
    columns_sql = ", ".join(
        f'"{column}"' if column == "references" else column for column in columns
    )
    insert_sql = f"""
        INSERT INTO nvd_cves ({columns_sql})
        SELECT
            cve_id, CAST(published AS TIMESTAMP), CAST(last_modified AS TIMESTAMP),
            vuln_status, description, cvss_score, severity, cvss_version,
            cvss_vector, cwe_ids, reference_count, "references", cpe_uris
        FROM batch
    """

    batch = []
    total = 0
    for index, page in enumerate(pages, start=1):
        batch.extend(parse_nvd_page(page))
        if len(batch) >= 20000 or index == len(pages):
            frame = pd.DataFrame(batch)
            con.register("batch", frame)
            con.execute(insert_sql)
            con.unregister("batch")
            total += len(batch)
            batch = []
            if index % 50 == 0 or index == len(pages):
                log(f"  {index}/{len(pages)} páginas, {total:,} registros")

    con.execute(
        """
        CREATE OR REPLACE TABLE nvd_cves AS
        SELECT * EXCLUDE (rn) FROM (
            SELECT *, row_number() OVER (
                PARTITION BY cve_id ORDER BY last_modified DESC
            ) AS rn
            FROM nvd_cves
        ) WHERE rn = 1
        """
    )
    rows, unique = con.execute(
        "SELECT count(*), count(DISTINCT cve_id) FROM nvd_cves"
    ).fetchone()
    log(f"nvd_cves: {rows:,} linhas ({unique:,} CVEs únicos)")


def stage_join(con):
    log("Consolidando EPSS + NVD...")
    con.execute("DROP TABLE IF EXISTS epss_latest")
    con.execute(
        """
        CREATE TABLE epss_latest AS
        SELECT
            cve,
            arg_max(epss, date) AS epss,
            arg_max(percentile, date) AS percentile,
            max(date) AS epss_date
        FROM epss_history
        GROUP BY cve
        """
    )

    con.execute("DROP TABLE IF EXISTS cves_all")
    con.execute(
        """
        CREATE TABLE cves_all AS
        SELECT
            e.cve AS cve_id,
            n.cve_id IS NOT NULL AS in_nvd,
            n.published,
            n.last_modified,
            n.vuln_status,
            n.description,
            n.cvss_score,
            n.severity,
            n.cvss_version,
            n.cvss_vector,
            n.cwe_ids,
            e.epss,
            e.percentile,
            e.epss_date,
            n.reference_count,
            n."references",
            n.cpe_uris
        FROM epss_latest e
        LEFT JOIN nvd_cves n ON e.cve = n.cve_id
        """
    )

    con.execute("DROP TABLE IF EXISTS cves_enriched")
    con.execute(
        """
        CREATE TABLE cves_enriched AS
        SELECT * EXCLUDE (in_nvd) FROM cves_all WHERE in_nvd
        """
    )

    total, matched = con.execute(
        "SELECT (SELECT count(*) FROM cves_all), (SELECT count(*) FROM cves_enriched)"
    ).fetchone()
    log(f"epss_latest: {total:,} CVEs | com dados no NVD: {matched:,} "
        f"({100 * matched / total:.1f}%)")


def stage_export(con, export_csv=True):
    PROCESSED.mkdir(parents=True, exist_ok=True)
    parquet = PROCESSED / "cves_enriched.parquet"
    log(f"Exportando {parquet}...")
    con.execute(
        f"COPY cves_enriched TO '{parquet.as_posix()}' "
        "(FORMAT PARQUET, COMPRESSION ZSTD)"
    )
    log(f"  {parquet} ({parquet.stat().st_size / 1e6:.1f} MB)")

    if export_csv:
        csv_path = PROCESSED / "cves_enriched.csv"
        log(f"Exportando {csv_path}...")
        con.execute(
            f"COPY cves_enriched TO '{csv_path.as_posix()}' (HEADER, DELIMITER ',')"
        )
        log(f"  {csv_path} ({csv_path.stat().st_size / 1e6:.1f} MB)")


def stage_apache(con):
    source = ROOT / "Analytics" / "apache_cves.csv"
    if not source.exists():
        log("Analytics/apache_cves.csv não encontrado; pulando.")
        return

    apache = pd.read_csv(source)
    apache["cve_id"] = apache["cve_id"].str.upper()
    latest = con.execute("SELECT * FROM epss_latest").fetchdf()
    merged = apache.merge(
        latest, left_on="cve_id", right_on="cve", how="left"
    ).drop(columns="cve")

    output = PROCESSED / "apache_cves_enriched.csv"
    merged.to_csv(output, index=False)
    matched = merged["epss"].notna().sum()
    log(f"apache_cves_enriched.csv: {len(merged)} CVEs, "
        f"{matched} com EPSS ({output})")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--stages",
        default="epss,epss-db,nvd,nvd-db,join,export,apache",
        help="Etapas separadas por vírgula (padrão: todas)",
    )
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--epss-start", default=EPSS_FIRST_DATE.isoformat())
    parser.add_argument("--epss-end", default=date.today().isoformat())
    parser.add_argument("--nvd-start", default="1988-01-01")
    parser.add_argument("--nvd-end", default=date.today().isoformat())
    parser.add_argument("--workers", type=int, default=12,
                        help="Downloads paralelos do EPSS (padrão: 12)")
    parser.add_argument("--nvd-pause", type=float, default=0.7,
                        help="Espera entre requisições ao NVD (padrão: 0.7s)")
    parser.add_argument("--memory-limit", default="2500MB")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--no-csv", action="store_true",
                        help="Exporta apenas Parquet")
    args = parser.parse_args()

    stages = [stage.strip() for stage in args.stages.split(",") if stage.strip()]
    valid = {"epss", "epss-db", "nvd", "nvd-db", "join", "export", "apache"}
    unknown = set(stages) - valid
    if unknown:
        raise SystemExit(f"Etapas inválidas: {', '.join(sorted(unknown))}")

    con = connect(args.db, args.memory_limit, args.threads)
    try:
        if "epss" in stages:
            stage_epss(args)
        if "epss-db" in stages:
            stage_epss_db(con)
        if "nvd" in stages:
            stage_nvd(args)
        if "nvd-db" in stages:
            stage_nvd_db(con)
        if "join" in stages:
            stage_join(con)
        if "export" in stages:
            stage_export(con, export_csv=not args.no_csv)
        if "apache" in stages:
            stage_apache(con)
    finally:
        con.close()

    log(f"Concluído. Banco: {args.db}")


if __name__ == "__main__":
    sys.exit(main())
