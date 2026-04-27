"""Cliente para el catálogo CISA KEV (Known Exploited Vulnerabilities)."""

import logging
from typing import Optional

import requests

from utils.cache import get as cache_get, set as cache_set

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

KEV_CACHE_KEY = "cisa:kev:catalog"


def _load_catalog() -> dict:
    """Carga el catálogo CISA KEV completo con cache en disco (TTL 4h)."""
    cached = cache_get(KEV_CACHE_KEY)
    if cached is not None:
        return cached

    try:
        resp = requests.get(
            CISA_KEV_URL,
            timeout=30,
            headers={"User-Agent": "OrinSec-Worker/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        cache_set(KEV_CACHE_KEY, data, ttl_seconds=4 * 3600)  # 4h
        logger.info("CISA KEV catalog refreshed: %s entries", len(data.get("vulnerabilities", [])))
        return data
    except Exception as exc:
        logger.warning("CISA KEV catalog load failed: %s", exc)
        return {"vulnerabilities": []}


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
