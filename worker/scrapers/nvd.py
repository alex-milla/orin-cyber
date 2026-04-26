"""Cliente para la API pública de NVD (NIST)."""

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 20),
    }

    if version:
        params["keywordSearch"] = f"{keyword} {version}"

    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"] = f"{year}-12-31T23:59:59.000"

    if severity:
        # NVD usa cvssV3Severity: LOW, MEDIUM, HIGH, CRITICAL
        params["cvssV3Severity"] = severity

    logger.info("NVD query: %s", params)

    try:
        # NVD tiene rate limit estricto; esperar entre peticiones
        time.sleep(6)
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.error("NVD request failed: %s", exc)
        return []

    items = data.get("vulnerabilities", [])
    results = []

    for item in items:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "unknown")
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
        if not cvss:
            cvss = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}

        score = None
        severity_level = "N/A"
        if cvss and "cvssData" in cvss:
            score = cvss["cvssData"].get("baseScore")
            severity_level = cvss["cvssData"].get("baseSeverity", "N/A")

        references = [
            ref.get("url", "")
            for ref in cve.get("references", [])
            if ref.get("url")
        ]

        results.append({
            "cve_id": cve_id,
            "description": desc,
            "score": score,
            "severity": severity_level,
            "published": cve.get("published", ""),
            "references": references[:5],
        })

    logger.info("NVD returned %s CVEs", len(results))
    return results
