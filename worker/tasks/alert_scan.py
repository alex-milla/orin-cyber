"""Tarea: escaneo de CVEs recientes y generación de alertas."""

import json
import logging
from typing import Any

from tasks.base import BaseTask
from scrapers.nvd import get_recent_cves
from scrapers.epss import get_epss
from scrapers.cisa_kev import get_kev
from scrapers.osv import query_osv
from utils.api_client import ApiClient

logger = logging.getLogger(__name__)

# Mapeo de severidad a nivel numérico para comparación
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _severity_meets(threshold: str | None, actual: str | None) -> bool:
    """Comprueba si una severidad actual cumple o supera el umbral."""
    if not threshold or not actual:
        return True
    return SEVERITY_ORDER.get(actual.upper(), 0) >= SEVERITY_ORDER.get(threshold.upper(), 0)


def _cve_matches(cve: dict, sub: dict) -> bool:
    """Comprueba si un CVE coincide con una suscripción."""
    stype = sub.get("type", "").lower()
    value = sub.get("value", "").lower()
    threshold = sub.get("severity_threshold", "LOW")

    if not value:
        return False

    desc = (cve.get("description") or "").lower()
    severity = cve.get("severity", "")

    if stype == "keyword":
        return value in desc
    if stype == "severity":
        return _severity_meets(value, severity)
    if stype == "product":
        return value in desc
    if stype == "vendor":
        return value in desc
    return False


class AlertScanTask(BaseTask):
    task_type = "alert_scan"

    def __init__(self, config_path: str = None):
        self.api = ApiClient(config_path)

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        hours = int(input_data.get("hours", 48))
        max_results = int(input_data.get("max_results", 50))

        # ── Obtener suscripciones activas ───────────────────────────────
        subscriptions = self.api.get_alert_subscriptions()
        if not subscriptions:
            logger.info("No active alert subscriptions found")
            return {
                "result_html": "<p>No hay suscripciones de alertas activas.</p>",
                "result_text": "No hay suscripciones de alertas activas.",
            }

        logger.info("Alert scan: %d subscriptions, last %d hours", len(subscriptions), hours)

        # ── Buscar CVEs recientes ───────────────────────────────────────
        recent_cves = get_recent_cves(hours=hours, max_results=max_results)
        if not recent_cves:
            return {
                "result_html": "<p>No se encontraron CVEs recientes en el período indicado.</p>",
                "result_text": f"No se encontraron CVEs recientes (últimas {hours}h).",
            }

        # ── Enriquecer y filtrar ────────────────────────────────────────
        matched_alerts = []
        matched_cves = []
        for cve in recent_cves:
            cid = cve.get("cve_id", "unknown")
            matched_subs = []
            for sub in subscriptions:
                if _cve_matches(cve, sub):
                    matched_subs.append(sub)

            if not matched_subs:
                continue

            # Enriquecer
            epss = get_epss(cid)
            kev = get_kev(cid)
            osv = query_osv(cid)

            sub_labels = [f"{s['type']}:{s['value']}" for s in matched_subs]
            alert = {
                "cve_id": cid,
                "title": cve.get("description", "")[:200],
                "severity": cve.get("severity", ""),
                "score": cve.get("score"),
                "epss_score": epss["score"] if epss else None,
                "kev": bool(kev),
                "source": "NVD",
                "matched_subscription": ", ".join(sub_labels),
            }
            matched_alerts.append(alert)
            matched_cves.append({
                "cve": cve,
                "epss": epss,
                "kev": kev,
                "osv": osv,
                "matched_subs": sub_labels,
            })

        # ── Enviar alertas al hosting ───────────────────────────────────
        sent = {"created": 0, "skipped": 0}
        if matched_alerts:
            resp = self.api.send_alerts(matched_alerts)
            if resp:
                sent = resp
                logger.info("Sent %d alerts to hosting (skipped %d)", sent.get("created", 0), sent.get("skipped", 0))
            else:
                logger.warning("Failed to send alerts to hosting")

        # ── Generar resumen ─────────────────────────────────────────────
        total = len(recent_cves)
        matched = len(matched_alerts)
        created = sent.get("created", 0)

        text_lines = [
            f"## Escaneo de Alertas — Últimas {hours}h",
            "",
            f"- CVEs revisados: {total}",
            f"- Coincidencias con suscripciones: {matched}",
            f"- Alertas creadas: {created}",
            "",
        ]
        if matched_cves:
            text_lines.append("### CVEs detectados:")
            for mc in matched_cves:
                c = mc["cve"]
                text_lines.append(f"- **{c['cve_id']}** — {c.get('severity','?')} ({c.get('score','?')}) — {', '.join(mc['matched_subs'])}")
        else:
            text_lines.append("No se detectaron CVEs que coincidan con las suscripciones activas.")

        result_text = "\n".join(text_lines)

        # HTML resumen simple
        html = f"""<div class="cve-report" style="font-family:var(--font-base);max-width:900px;margin:0 auto;">
  <h2>🔔 Escaneo de Alertas</h2>
  <p><strong>Período:</strong> últimas {hours}h | <strong>Revisados:</strong> {total} | <strong>Coincidencias:</strong> {matched} | <strong>Creadas:</strong> {created}</p>
"""
        if matched_cves:
            html += "  <ul>"
            for mc in matched_cves:
                c = mc["cve"]
                html += f"<li><strong>{c['cve_id']}</strong> — {c.get('severity','?')} {c.get('score','') or ''} — {', '.join(mc['matched_subs'])}</li>"
            html += "  </ul>"
        html += "</div>"

        return {
            "result_html": html,
            "result_text": result_text,
        }
