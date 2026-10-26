FROM apache/airflow:3.3.2

# Dependências do pipeline de CVEs. Instaladas no site do usuário `airflow`
# para não exigir root.
USER airflow
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt
