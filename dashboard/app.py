"""
Dashboard de CVEs — EPSS + NVD.

Execução:
    streamlit run dashboard/app.py

Lê o banco gerado pelo pipeline em data/processed/cves.duckdb.
"""
from __future__ import annotations

import json
import os
from datetime import date, timedelta
from pathlib import Path

import duckdb
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(
    os.getenv("CVE_DB_PATH", ROOT / "data" / "processed" / "cves.duckdb")
)
APACHE_CSV = Path(
    os.getenv(
        "CVE_APACHE_CSV",
        ROOT / "data" / "processed" / "apache_cves_enriched.csv",
    )
)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "SEM CVSS"]
SEVERITY_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH": "#ff7f0e",
    "MEDIUM": "#e3b505",
    "LOW": "#2ca02c",
    "NONE": "#7f7f7f",
    "SEM CVSS": "#bdbdbd",
}

st.set_page_config(
    page_title="CVE Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.6rem; padding-bottom: 2rem;}
    [data-testid="stMetricValue"] {font-size: 1.55rem;}
    [data-testid="stMetricLabel"] {font-size: 0.85rem;}
    </style>
    """,
    unsafe_allow_html=True,
)


class DatabaseBusy(RuntimeError):
    """O DuckDB está bloqueado por uma escrita do pipeline."""


@st.cache_data(ttl=300, show_spinner=False)
def query(sql: str, params: tuple = ()) -> pd.DataFrame:
    if not DB_PATH.exists():
        raise FileNotFoundError(DB_PATH)

    con = duckdb.connect(str(DB_PATH), read_only=True)
    try:
        return con.execute(sql, list(params)).fetchdf()
    except duckdb.IOException as exc:
        if "lock" in str(exc).lower():
            raise DatabaseBusy(
                "O banco está sendo atualizado pelo pipeline. "
                "Tente novamente em alguns instantes."
            ) from exc
        raise
    finally:
        con.close()


def fmt_int(value) -> str:
    return f"{int(value):,}".replace(",", ".")


def fmt_pct(value) -> str:
    return f"{100 * value:.1f}%".replace(".", ",")


def pct(part, total) -> str:
    return fmt_pct(part / total) if total else "0,0%"


def build_filters(
    start: date,
    end: date,
    severities: list[str],
    min_epss: float,
    min_cvss: float,
    search: str,
) -> tuple[str, tuple]:
    conditions = ["published::DATE BETWEEN ? AND ?"]
    params: list = [start, end]

    if severities:
        parts = []
        if "SEM CVSS" in severities:
            parts.append("severity IS NULL")
        named = [s for s in severities if s != "SEM CVSS"]
        if named:
            parts.append(f"severity IN ({', '.join('?' for _ in named)})")
            params.extend(named)
        conditions.append("(" + " OR ".join(parts) + ")")

    if min_epss > 0:
        conditions.append("epss >= ?")
        params.append(min_epss)

    if min_cvss > 0:
        conditions.append("cvss_score >= ?")
        params.append(min_cvss)

    if search.strip():
        conditions.append("cve_id ILIKE ?")
        params.append(f"%{search.strip()}%")

    return " AND ".join(conditions), tuple(params)


def kpi_cards(kpis: pd.Series) -> None:
    total = int(kpis["total"])
    columns = st.columns(5)
    columns[0].metric("CVEs no filtro", fmt_int(total))
    columns[1].metric(
        "Críticas",
        fmt_int(kpis["critical"]),
        pct(kpis["critical"], total),
    )
    columns[2].metric(
        "EPSS ≥ 10%",
        fmt_int(kpis["high_epss"]),
        pct(kpis["high_epss"], total),
    )
    columns[3].metric(
        "EPSS médio",
        f"{kpis['avg_epss']:.4f}" if pd.notna(kpis["avg_epss"]) else "—",
        help="Probabilidade média de exploração nos próximos 30 dias.",
    )
    columns[4].metric(
        "Publicadas (30 dias)",
        fmt_int(kpis["last_30d"]),
        help="Dentro do período filtrado.",
    )


# ---------------------------------------------------------------------------
# Carregamento inicial
# ---------------------------------------------------------------------------
try:
    meta = query(
        """
        SELECT
            min(published)::DATE AS min_date,
            max(published)::DATE AS max_date,
            max(epss_date) AS epss_date,
            max(last_modified) AS nvd_update,
            count(*) AS total
        FROM cves_enriched
        """
    ).iloc[0]
except FileNotFoundError:
    st.error(
        "Banco não encontrado em "
        f"`{DB_PATH}`. Rode o pipeline primeiro:\n\n"
        "```bash\n./.venv/bin/python src/build_dataset.py\n```"
    )
    st.stop()
except DatabaseBusy as exc:
    st.warning(str(exc))
    st.stop()

if not meta["total"]:
    st.warning("O banco existe, mas `cves_enriched` está vazio.")
    st.stop()

min_date = pd.Timestamp(meta["min_date"]).date()
max_date = pd.Timestamp(meta["max_date"]).date()
default_start = min_date

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("Filtros")

    date_selection = st.date_input(
        "Publicado entre",
        value=(default_start, max_date),
        min_value=min_date,
        max_value=max_date,
        format="DD/MM/YYYY",
    )
    if isinstance(date_selection, (tuple, list)):
        start_date, end_date = (
            date_selection[0],
            date_selection[-1],
        )
    else:
        start_date = end_date = date_selection

    severities = st.multiselect(
        "Severidade",
        options=SEVERITY_ORDER,
        default=SEVERITY_ORDER,
    )
    min_epss = st.slider(
        "EPSS mínimo",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.01,
        format="%.2f",
    )
    min_cvss = st.slider(
        "CVSS mínimo",
        min_value=0.0,
        max_value=10.0,
        value=0.0,
        step=0.5,
    )
    search = st.text_input("Buscar CVE", placeholder="ex.: CVE-2021-44228")

    st.divider()
    if st.button("Recarregar dados", width="stretch"):
        st.cache_data.clear()
        st.rerun()
    st.caption(
        f"Banco: `{DB_PATH.name}`  \n"
        f"EPSS: {meta['epss_date']}  \n"
        f"NVD: {pd.Timestamp(meta['nvd_update']):%d/%m/%Y}"
    )

where, params = build_filters(
    start_date, end_date, severities, min_epss, min_cvss, search
)

st.title("🛡️ CVE Intelligence")
st.caption(
    "EPSS (probabilidade de exploração) combinado com NVD (CVSS, CWE, CPE). "
    f"Base com {fmt_int(meta['total'])} CVEs · EPSS de {meta['epss_date']}."
)

try:
    kpis = query(
        f"""
        SELECT
            count(*) AS total,
            count(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
            count(*) FILTER (WHERE epss >= 0.1) AS high_epss,
            avg(epss) AS avg_epss,
            count(*) FILTER (WHERE published::DATE >= ?) AS last_30d
        FROM cves_enriched
        WHERE {where}
        """,
        (date.today() - timedelta(days=30),) + params,
    ).iloc[0]
except DatabaseBusy as exc:
    st.warning(str(exc))
    st.stop()

kpi_cards(kpis)

if not kpis["total"]:
    st.info("Nenhuma CVE atende aos filtros selecionados.")
    st.stop()

# ---------------------------------------------------------------------------
# Visão geral
# ---------------------------------------------------------------------------
tab_overview, tab_cves, tab_quality, tab_apache = st.tabs(
    ["📊 Visão geral", "🔎 CVEs", "✅ Qualidade dos dados", "🧪 Amostra Apache"]
)

with tab_overview:
    monthly = query(
        f"""
        SELECT date_trunc('month', published) AS mes, count(*) AS cves
        FROM cves_enriched
        WHERE {where}
        GROUP BY 1
        ORDER BY 1
        """,
        params,
    )
    severity = query(
        f"""
        SELECT coalesce(severity, 'SEM CVSS') AS severidade, count(*) AS cves
        FROM cves_enriched
        WHERE {where}
        GROUP BY 1
        """,
        params,
    )
    severity["severidade"] = pd.Categorical(
        severity["severidade"], categories=SEVERITY_ORDER, ordered=True
    )
    severity = severity.sort_values("severidade")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Publicações por mês")
        fig = px.bar(
            monthly,
            x="mes",
            y="cves",
            labels={"mes": "", "cves": "CVEs publicadas"},
            color_discrete_sequence=["#1f77b4"],
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=10, b=0),
            xaxis=dict(tickformat="%m/%Y"),
            height=330,
        )
        st.plotly_chart(fig, width="stretch")

    with right:
        st.subheader("Distribuição por severidade")
        fig = px.pie(
            severity,
            names="severidade",
            values="cves",
            hole=0.55,
            color="severidade",
            color_discrete_map=SEVERITY_COLORS,
            category_orders={"severidade": SEVERITY_ORDER},
        )
        fig.update_traces(textinfo="percent", textposition="inside")
        fig.update_layout(
            margin=dict(l=0, r=0, t=10, b=0),
            showlegend=True,
            height=330,
        )
        st.plotly_chart(fig, width="stretch")

    left, right = st.columns(2)
    with left:
        st.subheader("Top 10 CWEs")
        cwes = query(
            f"""
            SELECT cwe, count(*) AS cves
            FROM (
                SELECT trim(unnest(string_split(cwe_ids, ';'))) AS cwe
                FROM cves_enriched
                WHERE {where} AND cwe_ids IS NOT NULL
            )
            WHERE cwe <> ''
            GROUP BY 1
            ORDER BY 2 DESC
            LIMIT 10
            """,
            params,
        )
        if cwes.empty:
            st.info("Sem dados de CWE para os filtros atuais.")
        else:
            cwes = cwes.sort_values("cves")
            fig = px.bar(
                cwes,
                x="cves",
                y="cwe",
                orientation="h",
                labels={"cves": "CVEs", "cwe": ""},
                color_discrete_sequence=["#2ca02c"],
            )
            fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=320)
            st.plotly_chart(fig, width="stretch")

    with right:
        st.subheader("EPSS × CVSS")
        matrix = query(
            f"""
            SELECT
                round(cvss_score)::INT AS cvss,
                round(epss, 1) AS epss_bucket,
                count(*) AS cves
            FROM cves_enriched
            WHERE {where} AND cvss_score IS NOT NULL AND epss IS NOT NULL
            GROUP BY 1, 2
            ORDER BY 1, 2
            """,
            params,
        )
        if matrix.empty:
            st.info("Sem CVSS e EPSS para os filtros atuais.")
        else:
            pivot = (
                matrix.pivot(index="epss_bucket", columns="cvss", values="cves")
                .fillna(0)
                .sort_index(ascending=False)
            )
            fig = go.Figure(
                go.Heatmap(
                    z=pivot.values,
                    x=[str(c) for c in pivot.columns],
                    y=[f"{v:.1f}" for v in pivot.index],
                    colorscale="Reds",
                    colorbar=dict(title="CVEs"),
                    hovertemplate="CVSS %{x}<br>EPSS %{y}<br>%{z} CVEs<extra></extra>",
                )
            )
            fig.update_layout(
                margin=dict(l=0, r=0, t=10, b=0),
                height=320,
                xaxis_title="CVSS (arredondado)",
                yaxis_title="EPSS",
            )
            st.plotly_chart(fig, width="stretch")

    st.subheader("Top 25 por EPSS")
    top = query(
        f"""
        SELECT
            cve_id,
            published::DATE AS publicado,
            coalesce(severity, 'SEM CVSS') AS severidade,
            cvss_score,
            epss,
            percentile,
            cwe_ids
        FROM cves_enriched
        WHERE {where}
        ORDER BY epss DESC, cvss_score DESC NULLS LAST
        LIMIT 25
        """,
        params,
    )
    st.dataframe(
        top,
        width="stretch",
        hide_index=True,
        column_config={
            "cve_id": st.column_config.TextColumn("CVE"),
            "publicado": st.column_config.DateColumn("Publicado", format="DD/MM/YYYY"),
            "severidade": st.column_config.TextColumn("Severidade"),
            "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "epss": st.column_config.ProgressColumn(
                "EPSS", min_value=0.0, max_value=1.0, format="%.5f"
            ),
            "percentile": st.column_config.ProgressColumn(
                "Percentil", min_value=0.0, max_value=1.0, format="%.5f"
            ),
            "cwe_ids": st.column_config.TextColumn("CWEs"),
        },
    )

# ---------------------------------------------------------------------------
# CVEs e série histórica
# ---------------------------------------------------------------------------
with tab_cves:
    candidates = query(
        f"""
        SELECT cve_id || ' — ' || coalesce(severity, 'SEM CVSS')
               || ' · EPSS ' || printf('%.4f', epss) AS label,
               cve_id
        FROM cves_enriched
        WHERE {where}
        ORDER BY epss DESC
        LIMIT 300
        """,
        params,
    )

    if candidates.empty:
        st.info("Nenhuma CVE para selecionar com os filtros atuais.")
    else:
        selected = st.selectbox(
            "Escolha uma CVE (ordenadas por EPSS)",
            options=candidates["cve_id"].tolist(),
            format_func=lambda cve: candidates.loc[
                candidates["cve_id"] == cve, "label"
            ].iloc[0],
        )
        cve_detail = query(
            "SELECT * FROM cves_enriched WHERE cve_id = ?", (selected,)
        ).iloc[0]

        metrics = st.columns(5)
        metrics[0].metric(
            "EPSS",
            f"{cve_detail['epss']:.5f}",
            help="Probabilidade de exploração nos próximos 30 dias.",
        )
        metrics[1].metric(
            "Percentil",
            f"{cve_detail['percentile']:.4f}"
            if pd.notna(cve_detail["percentile"])
            else "—",
        )
        metrics[2].metric(
            "CVSS",
            f"{cve_detail['cvss_score']:.1f}"
            if pd.notna(cve_detail["cvss_score"])
            else "—",
        )
        metrics[3].metric(
            "Severidade",
            cve_detail["severity"]
            if pd.notna(cve_detail["severity"])
            else "SEM CVSS",
        )
        metrics[4].metric(
            "Publicada",
            pd.Timestamp(cve_detail["published"]).strftime("%d/%m/%Y"),
        )

        st.markdown(f"**{selected}** — {cve_detail['vuln_status'] or ''}")
        st.write(cve_detail["description"] or "Sem descrição.")

        if cve_detail["cwe_ids"]:
            st.markdown(
                "**CWEs:** "
                + " ".join(
                    f"`{cwe}`" for cwe in str(cve_detail["cwe_ids"]).split(";")
                )
            )

        st.subheader("Histórico do EPSS")
        full_history = st.checkbox(
            "Todo o histórico (consulta mais lenta)", value=False
        )
        since = min_date if full_history else max(
            min_date, max_date - timedelta(days=730)
        )
        history = query(
            """
            SELECT date, epss, percentile
            FROM epss_history
            WHERE cve = ? AND date >= ?
            ORDER BY date
            """,
            (selected, since),
        )
        if history.empty:
            st.info("Sem histórico para esta CVE.")
        else:
            fig = go.Figure()
            fig.add_trace(
                go.Scatter(
                    x=history["date"],
                    y=history["epss"],
                    mode="lines",
                    name="EPSS",
                    line=dict(color="#d62728", width=2),
                )
            )
            fig.add_trace(
                go.Scatter(
                    x=history["date"],
                    y=history["percentile"],
                    mode="lines",
                    name="Percentil",
                    line=dict(color="#1f77b4", width=1, dash="dot"),
                    yaxis="y2",
                )
            )
            fig.update_layout(
                margin=dict(l=0, r=0, t=10, b=0),
                height=300,
                yaxis=dict(title="EPSS", range=[0, 1]),
                yaxis2=dict(
                    title="Percentil",
                    overlaying="y",
                    side="right",
                    range=[0, 1],
                    showgrid=False,
                ),
                legend=dict(orientation="h", y=1.1),
            )
            st.plotly_chart(fig, width="stretch")

        references = []
        if cve_detail["references"]:
            try:
                references = json.loads(cve_detail["references"])
            except (TypeError, ValueError):
                references = []

        left, right = st.columns(2)
        with left:
            st.subheader(f"Referências ({len(references)})")
            for url in references[:15]:
                st.markdown(f"- [{url}]({url})")
            if len(references) > 15:
                st.caption(f"+ {len(references) - 15} referências no banco.")
        with right:
            cpes = []
            if cve_detail["cpe_uris"]:
                try:
                    cpes = json.loads(cve_detail["cpe_uris"])
                except (TypeError, ValueError):
                    cpes = []
            with st.expander(f"CPEs afetados ({len(cpes)})"):
                if cpes:
                    st.code("\n".join(cpes))
                else:
                    st.caption("Sem CPEs catalogados.")

# ---------------------------------------------------------------------------
# Qualidade
# ---------------------------------------------------------------------------
with tab_quality:
    coverage = query(
        """
        SELECT
            count(*) AS total,
            avg((description IS NOT NULL)::INT) AS descricao,
            avg((cvss_score IS NOT NULL)::INT) AS cvss,
            avg((cwe_ids IS NOT NULL)::INT) AS cwe,
            avg((cpe_uris IS NOT NULL)::INT) AS cpe,
            avg(("references" IS NOT NULL)::INT) AS referencias,
            max(epss_date) AS epss_date,
            max(last_modified) AS nvd_update
        FROM cves_enriched
        """
    ).iloc[0]

    st.subheader("Cobertura dos campos")
    coverage_columns = st.columns(4)
    for column, label, key in zip(
        coverage_columns,
        ["Descrição", "CVSS", "CWE", "CPE"],
        ["descricao", "cvss", "cwe", "cpe"],
    ):
        with column:
            st.metric(label, fmt_pct(coverage[key]))
            st.progress(float(coverage[key]))

    st.caption(
        f"Referências: {fmt_pct(coverage['referencias'])} · "
        f"Total de CVEs: {fmt_int(coverage['total'])} · "
        f"Atualização NVD: {pd.Timestamp(coverage['nvd_update']):%d/%m/%Y} · "
        f"EPSS: {coverage['epss_date']}"
    )

    counts = query(
        """
        SELECT 'epss_history' AS tabela, count(*) AS linhas FROM epss_history
        UNION ALL SELECT 'epss_latest', count(*) FROM epss_latest
        UNION ALL SELECT 'nvd_cves', count(*) FROM nvd_cves
        UNION ALL SELECT 'cves_enriched', count(*) FROM cves_enriched
        ORDER BY tabela
        """
    )
    counts["linhas"] = counts["linhas"].map(fmt_int)
    st.subheader("Tabelas do banco")
    st.dataframe(counts, width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# Amostra Apache
# ---------------------------------------------------------------------------
with tab_apache:
    st.subheader("Amostra de CVEs do Apache")
    if not APACHE_CSV.exists():
        st.info(
            "Arquivo `apache_cves_enriched.csv` não encontrado. "
            "Rode a etapa `apache` do pipeline."
        )
    else:
        apache = pd.read_csv(APACHE_CSV)
        apache["published"] = pd.to_datetime(
            apache["published"], errors="coerce"
        )

        columns = st.columns(3)
        columns[0].metric("CVEs", len(apache))
        columns[1].metric(
            "EPSS médio",
            f"{apache['epss'].mean():.4f}" if apache["epss"].notna().any() else "—",
        )
        columns[2].metric(
            "Críticas",
            fmt_int((apache["severity"] == "CRITICAL").sum()),
        )

        chart_data = apache.dropna(subset=["epss"]).nlargest(15, "epss")
        fig = px.bar(
            chart_data.sort_values("epss"),
            x="epss",
            y="cve_id",
            orientation="h",
            labels={"epss": "EPSS", "cve_id": ""},
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
        )
        fig.update_layout(
            height=380, margin=dict(l=0, r=0, t=10, b=0), legend_title=""
        )
        st.plotly_chart(fig, width="stretch")

        st.dataframe(
            apache.sort_values("epss", ascending=False)[
                [
                    "cve_id",
                    "published",
                    "severity",
                    "cvss_score",
                    "epss",
                    "percentile",
                ]
            ],
            width="stretch",
            hide_index=True,
            column_config={
                "cve_id": "CVE",
                "published": st.column_config.DateColumn(
                    "Publicado", format="DD/MM/YYYY"
                ),
                "severity": "Severidade",
                "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
                "epss": st.column_config.NumberColumn("EPSS", format="%.5f"),
                "percentile": st.column_config.NumberColumn(
                    "Percentil", format="%.5f"
                ),
            },
        )
