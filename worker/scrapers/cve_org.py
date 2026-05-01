"""Cliente para CVE Services API (CVE.org) — fuente canónica del registro CVE.

Documentación: https://cveawg.mitre.org/api-docs/
Este scraper consulta el origen oficial del registro CVE en formato JSON 5.x.
NVD se usa como fuente de enriquecimiento secundaria (véase scrapers/nvd.py).
"""

import logging
from typing import Any, Optional

import requests

from utils.cache import get as cache_get, set as cache_set

logger = logging.getLogger(__name__)

CVE_SERVICES_BASE = "https://cveawg.mitre.org/api/cve"


def _parse_iso_date(iso_str: str | None) -> str:
    """Devuelve YYYY-MM-DD desde un string ISO 8601."""
    if not iso_str:
        return ""
    return iso_str[:10]


def _extract_descriptions(cna: dict) -> dict[str, str]:
    """Extrae descripciones indexadas por idioma."""
    descriptions = {}
    for desc in cna.get("descriptions", []):
        lang = desc.get("lang", "en")
        value = desc.get("value", "").strip()
        if value:
            descriptions[lang] = value
    return descriptions


def _extract_references(cna: dict) -> list[str]:
    """Extrae URLs de referencias."""
    refs = []
    for ref in cna.get("references", []):
        url = ref.get("url", "").strip()
        if url and url not in refs:
            refs.append(url)
    return refs


def _extract_affected(cna: dict) -> list[dict[str, Any]]:
    """Resume productos afectados con vendor, producto y versiones."""
    affected = []
    for entry in cna.get("affected", []):
        vendor = entry.get("vendor", "Unknown")
        product = entry.get("product", "Unknown")
        versions = []
        for v in entry.get("versions", []):
            status = v.get("status", "")
            version = v.get("version", "")
            less_than = v.get("lessThan", "")
            if less_than:
                versions.append(f"{version} < {less_than} ({status})")
            else:
                versions.append(f"{version} ({status})")
        cpes = entry.get("cpes", [])[:5]
        affected.append({
            "vendor": vendor,
            "product": product,
            "versions": versions,
            "cpes": cpes,
            "default_status": entry.get("defaultStatus", ""),
        })
    return affected


def _extract_metrics(cna: dict) -> dict[str, Any] | None:
    """Extrae métricas CVSS publicadas por el CNA si existen."""
    metrics = cna.get("metrics", [])
    if not metrics:
        return None
    for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
        for m in metrics:
            data = m.get(key, {})
            if data and "baseScore" in data:
                return {
                    "version": data.get("version", key.replace("cvssV", "").replace("_", ".")),
                    "base_score": data.get("baseScore"),
                    "base_severity": data.get("baseSeverity", ""),
                    "vector_string": data.get("vectorString", ""),
                }
    return None


def _extract_cwes(cna: dict) -> list[str]:
    """Extrae CWEs desde problemTypes."""
    cwes = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId", "").strip()
            if cwe_id and cwe_id not in cwes:
                cwes.append(cwe_id)
    return cwes


def get_cve_by_id(cve_id: str) -> dict[str, Any] | None:
    """Consulta el registro canónico de un CVE en CVE Services."""
    cve_id = cve_id.upper().strip()
    key = f"cve_org:{cve_id}"
    cached = cache_get(key)
    if cached is not None:
        logger.info("CVE.org cache hit for %s", cve_id)
        return cached

    url = f"{CVE_SERVICES_BASE}/{cve_id}"
    try:
        resp = requests.get(url, timeout=20, headers={"User-Agent": "OrinSec-Worker/1.0"})
        if resp.status_code == 404:
            logger.debug("CVE.org: %s not found", cve_id)
            return None
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.warning("CVE.org request failed for %s: %s", cve_id, exc)
        return None

    cve_metadata = data.get("cveMetadata", {})
    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    descriptions = _extract_descriptions(cna)
    if not descriptions:
        for adp in containers.get("adp", []):
            adp_descs = _extract_descriptions(adp)
            if adp_descs:
                descriptions = adp_descs
                break

    result = {
        "source": "CVE.org",
        "cve_id": cve_metadata.get("cveId", cve_id),
        "state": cve_metadata.get("state", "UNKNOWN"),
        "published": _parse_iso_date(cve_metadata.get("datePublished")),
        "updated": _parse_iso_date(cve_metadata.get("dateUpdated")),
        "assigner": cve_metadata.get("assignerShortName", ""),
        "descriptions": descriptions,
        "description_en": descriptions.get("en", ""),
        "description_es": descriptions.get("es", ""),
        "affected": _extract_affected(cna),
        "references": _extract_references(cna),
        "metrics_cna": _extract_metrics(cna),
        "cwes": _extract_cwes(cna),
        "data_version": data.get("dataVersion", ""),
    }

    cache_set(key, result, ttl_seconds=24 * 3600)
    logger.info("CVE.org: fetched %s (%s)", cve_id, result["state"])
    return result


def get_cve_description(cve_data: dict, language: str = "en") -> str:
    """Devuelve la descripción preferida según idioma, con fallback."""
    descriptions = cve_data.get("descriptions", {})
    lang = language.lower()[:2]
    if lang in descriptions:
        return descriptions[lang]
    if "en" in descriptions:
        return descriptions["en"]
    for desc in descriptions.values():
        return desc
    return "No description available."
