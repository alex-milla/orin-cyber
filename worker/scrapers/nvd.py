"""Cliente para la API pública de NVD (NIST)."""

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _safe_first(lst: list | None) -> dict | None:
    """Devuelve el primer elemento de una lista si es un dict, None en caso contrario."""
    if not lst or not isinstance(lst, list):
        return None
    first = lst[0]
    return first if isinstance(first, dict) else None


def _parse_cve_item(item: dict) -> dict:
    """Convierte una entrada cruda de NVD (item['cve']) en un dict normalizado."""
    cve = item.get("cve") or {} if isinstance(item, dict) else {}

    # Descripción (preferir EN, fallback al primero disponible)
    descriptions = cve.get("descriptions", [])
    desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    if not desc and descriptions:
        desc = descriptions[0].get("value", "")

    # CVSS v3.1 → v3.0 → v4.0 (cascada)
    metrics = cve.get("metrics", {})
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        first = _safe_first(metrics.get(key))
        if first and first.get("cvssData"):
            cvss_data = first["cvssData"]
            break

    score = severity = vector = version = None
    if cvss_data:
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity", "N/A")
        vector = cvss_data.get("vectorString", "")
        version = cvss_data.get("version", "")

    references = [ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")]

    return {
        "cve_id": cve.get("id", "unknown"),
        "description": desc,
        "score": score,
        "severity": severity or "N/A",
        "vector": vector,
        "cvss_version": version,
        "published": cve.get("published", ""),
        "references": references,
    }


def _query_nvd(params: dict) -> list:
    """Wrapper único: rate limit + request + json."""
    logger.debug("NVD query: %s", params)
    try:
        time.sleep(6)
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("vulnerabilities", [])
        logger.info("NVD returned %d CVEs", len(items))
        return items
    except requests.RequestException as exc:
        logger.error("NVD request failed: %s", exc)
        return []


def search_cves(
    keyword: str,
    version: str = "",
    year: str = "",
    severity: str = "",
    max_results: int = 10,
) -> list[dict[str, Any]]:
    """
    Busca CVEs en NVD por palabra clave y filtros opcionales.
    Devuelve una lista de CVEs simplificados.
    """
    params: dict[str, Any] = {
        "keywordSearch": f"{keyword} {version}".strip() if version else keyword,
        "resultsPerPage": min(max_results, 20),
    }

    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"] = f"{year}-12-31T23:59:59.000"

    if severity:
        params["cvssV3Severity"] = severity

    items = _query_nvd(params)
    return [{**_parse_cve_item(i), "references": _parse_cve_item(i)["references"][:5]} for i in items]


def get_cve_by_id(cve_id: str) -> dict | None:
    """Busca un CVE específico por su ID (ej: CVE-2024-3393)."""
    logger.info("NVD query by ID: %s", cve_id)
    items = _query_nvd({"cveId": cve_id.upper()})
    if not items:
        return None
    parsed = _parse_cve_item(items[0])
    parsed["references"] = parsed["references"][:10]
    return parsed
