"""Scraper para OSV.dev (Open Source Vulnerabilities)."""

import json
import logging
import time
from typing import Any

import requests

from utils.cache import get as cache_get, set as cache_set

logger = logging.getLogger(__name__)
OSV_BASE = "https://api.osv.dev/v1"


def _normalize_severity(raw: str) -> str:
    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "moderate": "MEDIUM",
        "low": "LOW",
    }
    return mapping.get(raw.lower().strip(), raw.upper().strip())


def _extract_fixed_versions(affected: list[dict]) -> list[str]:
    """Extrae versiones 'fixed' de los rangos de afectación."""
    fixed = set()
    for entry in affected:
        for rng in entry.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev and ev["fixed"]:
                    fixed.add(str(ev["fixed"]))
    return sorted(fixed)


def _extract_affected_packages(affected: list[dict]) -> list[dict]:
    """Resume paquetes afectados con ecosistema y versión introducida."""
    packages = []
    for entry in affected:
        pkg = entry.get("package", {})
        if not pkg:
            continue
        introduced = "0"
        for rng in entry.get("ranges", []):
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = str(ev["introduced"])
        packages.append({
            "ecosystem": pkg.get("ecosystem", "Unknown"),
            "name": pkg.get("name", "Unknown"),
            "introduced": introduced,
            "versions": entry.get("versions", [])[:10],  # limitar
        })
    return packages


def query_osv(cve_id: str) -> dict[str, Any] | None:
    """Consulta OSV.dev por CVE ID. Retorna datos normalizados o None."""
    key = f"osv:cve:{cve_id.upper()}"
    cached = cache_get(key)
    if cached:
        logger.info("OSV cache hit for %s", cve_id)
        return cached

    url = f"{OSV_BASE}/vulns/{cve_id.upper()}"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 404:
            logger.debug("OSV: %s not found", cve_id)
            return None
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.warning("OSV request failed for %s: %s", cve_id, exc)
        return None

    affected = data.get("affected", [])
    if not affected:
        logger.debug("OSV: %s has no affected packages", cve_id)
        return None

    # Severity: intentar database_specific primero, luego severity array
    severity = None
    for entry in affected:
        db_sev = entry.get("database_specific", {}).get("severity")
        if db_sev:
            severity = _normalize_severity(db_sev)
            break
    if not severity and data.get("severity"):
        for sev_entry in data["severity"]:
            if sev_entry.get("type", "").upper() == "CVSS_V3":
                severity = sev_entry.get("score", "")
                break

    result = {
        "source": "OSV.dev",
        "aliases": data.get("aliases", []),
        "summary": data.get("summary", ""),
        "details": data.get("details", "")[:500],
        "severity": severity,
        "affected_packages": _extract_affected_packages(affected),
        "fixed_in": _extract_fixed_versions(affected),
        "references": [r.get("url", "") for r in data.get("references", []) if r.get("url")][:5],
    }

    cache_set(key, result, ttl_seconds=12 * 3600)
    return result
