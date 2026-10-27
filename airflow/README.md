# Airflow — pipeline de CVEs (EPSS + NVD)

Orquestração do `src/build_dataset.py` com Airflow 3.3.2 e DuckDB.

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ epss_download│──▶│   epss_db    │──▶│ nvd_download │──▶│    nvd_db    │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
                                                                 │
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────▼───────┐
│quality_check │◀──│    apache    │◀──│    export    │◀──│     join     │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

As tarefas são sequenciais de propósito: o DuckDB aceita apenas um processo
com acesso de escrita por vez.

## DAGs

| DAG | Agenda | Comportamento |
|---|---|---|
| `cve_daily` | `30 14 * * *` (UTC) | Baixa o EPSS do dia e as modificações recentes do NVD. Na primeira execução, detecta que as tabelas não existem e baixa o histórico completo. |
| `cve_full_refresh` | manual | Reconstrói as tabelas do zero a partir do cache local (útil após mudanças de schema). |

O EPSS publica os scores por volta das 12:55 UTC, por isso a execução às 14:30.
O NVD é consultado por `lastModStartDate` nos últimos 3 dias.

## Subir o ambiente

Pré-requisitos: Docker + Docker Compose, ~8 GB de RAM e ~30 GB de disco livres.

```bash
cd airflow
cp .env.example .env
# ajuste AIRFLOW_UID (Linux: id -u) e gere uma FERNET_KEY nova
docker compose build
docker compose up -d
docker compose ps
```

Interface do Airflow: <http://localhost:8080> — usuário/senha padrão `airflow` /
`airflow` (configuráveis em `airflow/.env`).

Para subir também o dashboard Streamlit:

```bash
docker compose --profile dashboard up -d
# http://localhost:8501
```

O `AIRFLOW_UID` precisa ser o dono dos arquivos do projeto, senão as tarefas não
conseguem escrever em `data/`. No Linux:

```bash
echo "AIRFLOW_UID=$(id -u)" >> .env
```

### Primeira carga

A forma mais direta é disparar a DAG manual de bootstrap:

```bash
docker compose exec airflow-scheduler airflow dags unpause cve_full_refresh
docker compose exec airflow-scheduler airflow dags trigger cve_full_refresh
```

Ou deixe a `cve_daily` fazer o bootstrap sozinha na primeira execução (leva
~20 minutos e baixa ~4 GB de EPSS + NVD).

### Acompanhar

```bash
docker compose logs -f airflow-scheduler
docker compose exec airflow-scheduler airflow dags list-runs cve_daily
docker compose exec airflow-scheduler airflow tasks states-for-dag-run \
    cve_daily "<run_id>"
```

## Chave da API do NVD

O `docker-compose.yaml` já usa `../.env` (o `.env` da raiz do projeto) como
`env_file`, então a `NVD_API_KEY` chega aos containers automaticamente.

Em produção, prefira um secrets backend do Airflow (Vault, AWS Secrets Manager,
etc.) em vez de arquivo `.env`.

## Rodar sem Docker (opcional)

Airflow 3.3.2 suporta Python 3.14. Use um virtualenv separado do projeto:

```bash
python3 -m venv .venv-airflow
source .venv-airflow/bin/activate
pip install "apache-airflow==3.3.2" duckdb pandas requests

export AIRFLOW_HOME="$HOME/airflow"
export AIRFLOW__CORE__DAGS_FOLDER="$PWD/airflow/dags"
export AIRFLOW__CORE__LOAD_EXAMPLES=False
export CVE_PROJECT_DIR="$PWD"
export NVD_API_KEY="$(grep NVD_API_KEY .env | cut -d= -f2)"

airflow db migrate
airflow standalone   # cria usuário admin e sobe API + scheduler
```

O DAG usa `CVE_PROJECT_DIR` para localizar `src/` e `data/`; no Docker o valor
é `/opt/airflow`.

## Operação

- **Logs por tarefa**: ficam em `airflow/logs/` e na UI.
- **Retries**: 2 tentativas com 5 minutos de intervalo.
- **Idempotência**: downloads usam cache em `data/raw/`; a carga do EPSS insere
  apenas datas novas; o NVD é reconstruído a partir do cache.
- **Qualidade**: a tarefa `quality_check` falha se houver menos de 400 mil CVEs,
  duplicatas, menos de 99% de descrições ou EPSS com atraso > 2 dias. Os limites
  podem ser ajustados por variáveis (`CVE_MIN_ROWS`, `CVE_MIN_DESCRIPTION_RATIO`,
  `CVE_MAX_EPSS_LAG_DAYS`).
- **Concorrência**: não dispare `cve_full_refresh` enquanto `cve_daily` roda; os
  dois escrevem no mesmo DuckDB. Em produção, use um Airflow Pool com 1 slot e
  atribua todas as tarefas a ele.

## Estrutura

```
airflow/
├── Dockerfile            # imagem do Airflow + dependências do pipeline
├── requirements.txt      # duckdb, pandas, requests
├── docker-compose.yaml   # Postgres + apiserver + scheduler + dag-processor
│                         # + dashboard (profile "dashboard")
├── .env.example          # AIRFLOW_UID, FERNET_KEY, credenciais
├── dags/
│   └── cve_pipeline.py   # cve_daily e cve_full_refresh
└── logs/                 # logs das tarefas (não versionar)
```
