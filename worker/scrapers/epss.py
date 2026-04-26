"""Cliente para la API de EPSS (Exploit Prediction Scoring System) de FIRST.org."""

import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def get_epss(cve_id: str) -> Optional[dict]:
    """
    Consulta el EPSS score para un CVE.
    Retorna dict con 'score' (0-1) y 'percentile' (0-1) o None si no existe.
    """
    try:
        resp = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=15,
            headers={"User-Agent": "OrinSec-Worker/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()

        entries = data.get("data") if isinstance(data, dict) else None
        if not entries or not isinstance(entries, list):
            return None
        entry = entries[0]
        if not isinstance(entry, dict):
            return None
        score = float(entry.get("epss", 0))
        percentile = float(entry.get("percentile", 0))

        return {
            "score": score,
            "percentile": percentile,
            "score_percent": round(score * 100, 2),
            "percentile_percent": round(percentile * 100, 2),
        }
    except Exception as exc:
        logger.warning("EPSS query failed for %s: %s", cve_id, exc)
        return None
