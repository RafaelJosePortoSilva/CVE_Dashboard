import json
import os
import time
from datetime import date, datetime, timedelta
from pathlib import Path

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MAX_WINDOW_DAYS = 120


def load_api_key(env_path=".env", variable="NVD_API_KEY"):
    """Obtém a chave do NVD do ambiente ou de um arquivo .env."""
    value = os.getenv(variable)
    if value:
        return value

    path = Path(env_path)
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith(f"{variable}="):
            return line.split("=", 1)[1].strip().strip("'\"") or None
    return None


def _as_date(value, default=None):
    if value is None:
        return default
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def _request(params, api_key, timeout=60, retries=4):
    headers = {"apiKey": api_key} if api_key else {}
    last_error = None

    for attempt in range(retries):
        try:
            response = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=timeout
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                # A API retorna 404 para janelas de datas inválidas (> 120 dias).
                raise ValueError(
                    "NVD retornou 404. Verifique o intervalo de datas "
                    f"(máximo de {NVD_MAX_WINDOW_DAYS} dias)."
                )
            # 403/429/503: rate limit ou instabilidade, tenta de novo com espera.
            last_error = RuntimeError(
                f"NVD {response.status_code}: {response.text[:200]}"
            )
        except requests.RequestException as exc:
            last_error = exc

        if attempt < retries - 1:
            time.sleep(5 * (2**attempt))

    raise RuntimeError(f"Falha ao consultar o NVD: {last_error}") from last_error


def _iter_windows(start, end, window_days=NVD_MAX_WINDOW_DAYS):
    current = start
    while current <= end:
        window_end = min(current + timedelta(days=window_days - 1), end)
        yield current, window_end
        current = window_end + timedelta(days=1)


def fetch_nvd_pages(
    start_date="1988-01-01",
    end_date=None,
    cache_dir="data/raw/nvd",
    api_key=None,
    results_per_page=2000,
    pause=0.7,
    timeout=60,
    retries=4,
    verbose=True,
    last_mod_days=None,
):
    """
    Baixa todas as páginas da API do NVD no intervalo, salvando um JSON por página.

    O NVD limita consultas por data a 120 dias, então o intervalo é dividido em
    janelas. Os arquivos são gravados em
    ``cache_dir/pubStart=AAAA-MM-DD/page_000000.json`` e servem de cache: páginas
    já baixadas não são requisitadas novamente.

    Se ``last_mod_days`` for informado, consulta por data de modificação
    (``lastModStartDate``/``lastModEndDate``) nos últimos N dias, em vez de data
    de publicação. É o modo usado nas execuções incrementais diárias.

    Returns:
        list[pathlib.Path]: Caminhos das páginas em cache.
    """
    if last_mod_days is not None:
        end = _as_date(end_date, date.today())
        start = end - timedelta(days=int(last_mod_days))
        date_field = "lastMod"
        cache_prefix = "lastMod"
    else:
        end = _as_date(end_date, date.today())
        start = _as_date(start_date, date(1988, 1, 1))
        date_field = "pub"
        cache_prefix = "pubStart"

    if start > end:
        raise ValueError("start_date deve ser anterior ou igual a end_date")
    if api_key is None:
        api_key = load_api_key()

    cache = Path(cache_dir)
    saved = []
    requests_made = 0

    def fetch_page(folder, start_index, window_start, window_end):
        nonlocal requests_made
        output = folder / f"page_{start_index:06d}.json"
        if output.exists() and output.stat().st_size > 0:
            return json.loads(output.read_text())

        if requests_made and pause:
            time.sleep(pause)
        payload = _request(
            {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                f"{date_field}StartDate": f"{window_start.isoformat()}T00:00:00.000",
                f"{date_field}EndDate": f"{window_end.isoformat()}T23:59:59.999",
            },
            api_key,
            timeout=timeout,
            retries=retries,
        )
        requests_made += 1
        folder.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload))
        return payload

    for window_start, window_end in _iter_windows(start, end):
        folder = cache / f"{cache_prefix}={window_start.isoformat()}"
        payload = fetch_page(folder, 0, window_start, window_end)
        total = payload.get("totalResults", 0)

        pages = (total + results_per_page - 1) // results_per_page if total else 1
        saved.append(folder / "page_000000.json")

        for page_number in range(1, pages):
            start_index = page_number * results_per_page
            output = folder / f"page_{start_index:06d}.json"
            if not (output.exists() and output.stat().st_size > 0):
                fetch_page(folder, start_index, window_start, window_end)
            saved.append(output)

        if verbose:
            print(
                f"Janela {window_start} -> {window_end}: "
                f"{total} CVEs em {pages} página(s)"
            )

    return saved


def _english(values, default=None):
    for item in values or []:
        if item.get("lang") == "en":
            return item.get("value")
    return default


def _collect_cpe_uris(value, found):
    if isinstance(value, dict):
        if isinstance(value.get("criteria"), str):
            found.add(value["criteria"])
        for key, child in value.items():
            if key != "criteria":
                _collect_cpe_uris(child, found)
    elif isinstance(value, list):
        for child in value:
            _collect_cpe_uris(child, found)


def parse_nvd_vulnerability(item):
    """Extrai os campos de interesse de um item ``vulnerabilities`` do NVD."""
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    metrics = cve.get("metrics", {})
    cvss_score = severity = version = vector = None
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next(
            (entry for entry in entries if entry.get("type") == "Primary"),
            entries[0],
        )
        data = primary.get("cvssData", {})
        cvss_score = data.get("baseScore")
        severity = data.get("baseSeverity") or primary.get("baseSeverity")
        version = data.get("version")
        vector = data.get("vectorString")
        break

    cwes = set()
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value")
            if value and value.startswith("CWE-"):
                cwes.add(value)

    cpes = set()
    _collect_cpe_uris(cve.get("configurations", []), cpes)

    references = [reference.get("url") for reference in cve.get("references", [])]
    references = [url for url in references if url]

    return {
        "cve_id": cve_id.upper(),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": _english(cve.get("descriptions")),
        "cvss_score": cvss_score,
        "severity": severity,
        "cvss_version": version,
        "cvss_vector": vector,
        "cwe_ids": ";".join(sorted(cwes)) or None,
        "reference_count": len(references),
        "references": json.dumps(references) if references else None,
        "cpe_uris": json.dumps(sorted(cpes)) if cpes else None,
    }


def parse_nvd_page(path):
    payload = json.loads(Path(path).read_text())
    rows = []
    for item in payload.get("vulnerabilities", []):
        row = parse_nvd_vulnerability(item)
        if row is not None:
            rows.append(row)
    return rows
