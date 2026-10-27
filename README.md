# CVE Intelligence — EPSS + NVD

Pipeline de dados que baixa o histórico do **EPSS** (probabilidade de exploração)
e os dados do **NVD** (CVSS, CWE, CPE, referências), consolida tudo em
**DuckDB**, orquestra com **Airflow** e disponibiliza um **dashboard Streamlit**.

```
 GitHub: empiricalsec/epss_scores        NVD API 2.0
        (CSV.gz diários)                 (páginas JSON)
              │                              │
              └──────────────┬───────────────┘
                             ▼
                  src/build_dataset.py
                             │
                             ▼
              data/processed/cves.duckdb
                    │                  │
                    ▼                  ▼
            Dashboard Streamlit    Exportações
              (tempo real)         Parquet / CSV
                             ▲
                             │
                     Airflow (diário)
```

## Estado atual da base

| Métrica | Valor |
|---|---|
| Histórico EPSS | 454 milhões de registros (2021-04-14 → hoje) |
| CVEs no NVD | 414,8 mil |
| Base consolidada | 408,6 mil CVEs (100% das CVEs com EPSS) |
| Cobertura | 100% descrição · 95,8% CVSS · 81,7% CWE · 78,8% CPE |
| Tamanho | ~7 GB DuckDB · ~4,5 GB de cache · ~580 MB exportações |

Os números variam a cada execução diária.

## Fontes de dados

**EPSS** — [empiricalsec/epss_scores](https://github.com/empiricalsec/epss_scores)

- Um arquivo `AAAA/epss_scores-AAAA-MM-DD.csv.gz` por dia, a partir de 2021-04-14.
- Colunas: `cve`, `epss`, `percentile` (os primeiros arquivos não têm `percentile`).
- Scores mudam de modelo em 2022-02-04 (v2), 2023-03-07 (v3) e 2025-03-17 (v4).

**NVD** — [API 2.0](https://nvd.nist.gov/developers/vulnerabilities)

- Consultas por data limitadas a **120 dias** por requisição; o pipeline divide o
  intervalo em janelas e pagina de 2.000 em 2.000.
- Rate limit: 5 req/30s sem chave e 50 req/30s com `NVD_API_KEY`.
- A chave é lida de `NVD_API_KEY` (ambiente) ou do arquivo `.env`.

## Estrutura

```
.
├── Analytics/                 # notebooks e amostra original (Apache)
├── airflow/                   # DAGs, imagem e compose do Airflow
│   ├── dags/cve_pipeline.py
│   ├── docker-compose.yaml
│   └── README.md
├── dashboard/                 # app Streamlit + Dockerfile
│   └── app.py
├── data/                      # não versionado
│   ├── raw/                   # cache EPSS e NVD
│   ├── interim/
│   └── processed/             # cves.duckdb, parquet e csv
├── src/
│   ├── build_dataset.py       # orquestração das etapas
│   └── data/
│       ├── EPSS.py            # download/processamento do EPSS
│       └── NVD.py             # download/parsing do NVD
├── requirements.txt
└── README.md
```

## Instalação

Requisitos: Python 3.11+ (testado com 3.14) e ~15 GB de disco livres.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edite .env e informe NVD_API_KEY (recomendado)
```

## Pipeline

O pipeline é dividido em etapas independentes e **idempotentes**:

| Etapa | O que faz |
|---|---|
| `epss` | Baixa os arquivos diários para `data/raw/epss/AAAA/` (pula os já baixados) |
| `epss-db` | Insere no DuckDB apenas as datas ainda não carregadas |
| `nvd` | Baixa páginas do NVD (completo ou incremental) para `data/raw/nvd/` |
| `nvd-db` | Reconstrói `nvd_cves` a partir do cache de páginas |
| `join` | Cria `epss_latest`, `cves_all` e `cves_enriched` |
| `export` | Exporta `cves_enriched` para Parquet e CSV |
| `apache` | Enriquece `Analytics/apache_cves.csv` com o EPSS mais recente |

### Execução completa

```bash
./.venv/bin/python src/build_dataset.py
```

Na primeira execução são baixados ~4,5 GB e o processo leva ~20 minutos.
As execuções seguintes reaproveitam o cache.

### Atualização incremental (recomendada)

```bash
./.venv/bin/python src/build_dataset.py \
    --epss-start 2026-10-26 --epss-end 2026-10-26 \
    --nvd-mode incremental --nvd-lookback-days 3
```

Se as tabelas não existirem, o script detecta e faz a carga completa
automaticamente.

### Opções principais

| Opção | Padrão | Descrição |
|---|---|---|
| `--stages` | todas | Etapas separadas por vírgula |
| `--db` | `data/processed/cves.duckdb` | Caminho do banco |
| `--epss-start` / `--epss-end` | 2021-04-14 / hoje | Intervalo do EPSS |
| `--epss-rebuild` | desligado | Recria `epss_history` do zero |
| `--nvd-mode` | `full` | `full` ou `incremental` |
| `--nvd-lookback-days` | 3 | Janela do modo incremental |
| `--nvd-start` / `--nvd-end` | 1988-01-01 / hoje | Intervalo do NVD completo |
| `--workers` | 12 | Downloads paralelos do EPSS |
| `--nvd-pause` | 0.7 | Espera entre requisições ao NVD |
| `--memory-limit` / `--threads` | 2500MB / 4 | Limites do DuckDB |
| `--no-csv` | desligado | Exporta apenas Parquet |

## Banco de dados

Arquivo: `data/processed/cves.duckdb`.

| Tabela | Linhas aprox. | Conteúdo |
|---|---|---|
| `epss_history` | 454 M | Série diária por CVE (`date`, `cve`, `epss`, `percentile`) |
| `epss_latest` | 408 k | Score mais recente de cada CVE |
| `nvd_cves` | 415 k | Dados do NVD deduplicados por CVE |
| `cves_all` | 408 k | EPSS + NVD (com flag `in_nvd`) |
| `cves_enriched` | 408 k | Somente CVEs presentes nas duas fontes |

### Schema de `cves_enriched`

| Coluna | Tipo | Descrição |
|---|---|---|
| `cve_id` | VARCHAR | Identificador CVE |
| `published` | TIMESTAMP | Data de publicação no NVD |
| `last_modified` | TIMESTAMP | Última modificação no NVD |
| `vuln_status` | VARCHAR | Status (Analyzed, Modified, Rejected...) |
| `description` | VARCHAR | Descrição em inglês |
| `cvss_score` | DOUBLE | Score CVSS (v3.1 > v4.0 > v3.0 > v2) |
| `severity` | VARCHAR | CRITICAL/HIGH/MEDIUM/LOW/NONE |
| `cvss_version` / `cvss_vector` | VARCHAR | Versão e vetor do CVSS |
| `cwe_ids` | VARCHAR | CWEs separadas por `;` |
| `epss` | DOUBLE | Probabilidade de exploração (0–1) |
| `percentile` | DOUBLE | Percentil do score EPSS |
| `epss_date` | DATE | Data do score EPSS |
| `reference_count` | INTEGER | Quantidade de referências |
| `references` | VARCHAR | URLs em JSON |
| `cpe_uris` | VARCHAR | CPEs afetados em JSON |

### Consultas de exemplo

```bash
./.venv/bin/python - <<'PY'
import duckdb
con = duckdb.connect("data/processed/cves.duckdb", read_only=True)

print(con.sql("""
    SELECT cve_id, severity, cvss_score, epss, percentile
    FROM cves_enriched
    ORDER BY epss DESC
    LIMIT 10
"""))

print(con.sql("""
    SELECT date, epss
    FROM epss_history
    WHERE cve = 'CVE-2021-44228'
    ORDER BY date
""").df().tail())
PY
```

Também é possível consultar direto do Parquet, sem abrir o banco:

```sql
SELECT * FROM 'data/processed/cves_enriched.parquet'
WHERE severity = 'CRITICAL' AND epss >= 0.5;
```

## Dashboard

```bash
source .venv/bin/activate
streamlit run dashboard/app.py
```

Abre em <http://localhost:8501>.

Abas:

- **Visão geral** — KPIs, publicações por mês, severidade, top CWEs, heatmap
  EPSS × CVSS e top 25 CVEs por EPSS.
- **CVEs** — detalhe da CVE, histórico do EPSS (2 anos ou completo), referências
  e CPEs.
- **Qualidade dos dados** — cobertura dos campos e contagem das tabelas.
- **Amostra Apache** — as 100 CVEs do arquivo original, enriquecidas com EPSS.

Filtros na barra lateral: período, severidade, EPSS mínimo, CVSS mínimo e busca
por ID. As consultas são cacheadas por 5 minutos; o botão **Recarregar dados**
limpa o cache.

Variáveis de ambiente:

| Variável | Padrão |
|---|---|
| `CVE_DB_PATH` | `data/processed/cves.duckdb` |
| `CVE_APACHE_CSV` | `data/processed/apache_cves_enriched.csv` |

Se o pipeline estiver escrevendo no DuckDB, o dashboard exibe um aviso em vez de
quebrar (o DuckDB permite apenas um escritor por vez).

## Airflow

Instruções completas em [`airflow/README.md`](airflow/README.md).

```bash
cd airflow
cp .env.example .env          # ajuste AIRFLOW_UID e FERNET_KEY
docker compose build
docker compose up -d
docker compose --profile dashboard up -d   # inclui o dashboard na porta 8501
```

DAGs:

| DAG | Agenda | Função |
|---|---|---|
| `cve_daily` | diária, 14:30 UTC | Atualização incremental (EPSS do dia + NVD recente) |
| `cve_full_refresh` | manual | Reconstrói as tabelas a partir do cache |

O `quality_check` ao final falha a DAG se a base perder cobertura ou ficar
desatualizada. As tarefas são sequenciais por causa do lock de escrita do DuckDB.

## Qualidade e limitações

- **NVD**: a API rejeita intervalos > 120 dias; o download completo usa ~290
  páginas. Sem chave, o rate limit torna a carga muito lenta.
- **EPSS**: começa em 2021-04-14; existem 9 dias sem publicação. O `percentile`
  não existe nos primeiros arquivos.
- **CVEs rejeitadas**: o NVD inclui registros com `vuln_status = 'Rejected'`.
  Filtre se necessário.
- **DuckDB**: um único processo com escrita. Não rode o pipeline enquanto outro
  processo escreve no banco; o dashboard lida com isso mostrando um aviso.
- **Atualidade**: os scores EPSS do dia são publicados por volta das 12:55 UTC;
  a DAG roda às 14:30 UTC.
- **Espaço**: o banco cresce ~1,5 GB/ano com o histórico diário do EPSS.

## Manutenção

```bash
# Atualizar dados manualmente
./.venv/bin/python src/build_dataset.py \
    --epss-start "$(date +%F)" --epss-end "$(date +%F)" \
    --nvd-mode incremental

# Reconstruir tudo (mantendo o cache baixado)
./.venv/bin/python src/build_dataset.py --epss-rebuild

# Limpar caches (o próximo run baixa novamente)
rm -rf data/raw/epss data/raw/nvd
```

Para mudanças de schema, rode `cve_full_refresh` no Airflow ou use
`--epss-rebuild` e remova as tabelas do NVD antes de reconstruir.
