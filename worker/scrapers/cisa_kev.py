"""Cliente para el catálogo CISA KEV (Known Exploited Vulnerabilities)."""

import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://api.cisa.gov/known-exploited-vulnerabilities/catalog"

# Cache en memoria del catálogo completo (se refresca al reiniciar el worker)
_kev_cache: Optional[dict] = None
_kev_load_failed = False


def _load_catalog() -> dict:
    """Carga el catálogo CISA KEV completo."""
    global _kev_cache, _kev_load_failed
    if _kev_cache is not None:
        return _kev_cache
    if _kev_load_failed:
        return {"vulnerabilities": []}

    try:
        resp = requests.get(
            CISA_KEV_URL,
            timeout=30,
            headers={"User-Agent": "OrinSec-Worker/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        _kev_cache = data
        logger.info("CISA KEV catalog loaded: %s entries", len(data.get("vulnerabilities", [])))
        return data
    except Exception as exc:
        logger.warning("CISA KEV catalog load failed: %s", exc)
        _kev_load_failed = True
        _kev_cache = {"vulnerabilities": []}
        return _kev_cache


def get_kev(cve_id: str) -> Optional[dict]:
    """
    Busca un CVE en el catálogo CISA KEV.
    Retorna dict con info del catálogo o None si no está listado.
    """
    catalog = _load_catalog()
    cve_upper = cve_id.upper()

    for vuln in catalog.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        if vuln.get("cveID", "").upper() == cve_upper:
            return {
                "listed": True,
                "vendor": vuln.get("vendorProject", "Unknown"),
                "product": vuln.get("product", "Unknown"),
                "vulnerability": vuln.get("vulnerabilityName", "Unknown"),
                "date_added": vuln.get("dateAdded", "Unknown"),
                "due_date": vuln.get("dueDate", "Unknown"),
                "required_action": vuln.get("requiredAction", "Unknown"),
                "ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            }

    return None
