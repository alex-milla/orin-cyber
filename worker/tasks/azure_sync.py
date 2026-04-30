"""Tarea: sincronización de incidentes desde Microsoft Sentinel vía Azure CLI."""

import json
import logging
from typing import Any

from tasks.base import BaseTask
from utils.azure_sentinel import fetch_recent_incidents, get_access_token, check_login_status

logger = logging.getLogger(__name__)


class AzureSyncTask(BaseTask):
    task_type = "azure_sync"

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        workspace_id = input_data.get("workspace_id", "").strip()
        days = int(input_data.get("days", 7))
        incident_id = input_data.get("incident_id", "")

        if not workspace_id:
            return {
                "result_html": "<p>Error: workspace_id requerido.</p>",
                "result_text": "Error: workspace_id requerido.",
            }

        # Verificar login Azure
        login = check_login_status()
        if not login.get("logged_in"):
            return {
                "result_html": (
                    "<p>❌ <strong>No hay sesión activa de Azure CLI.</strong></p>"
                    "<p>Conéctate por SSH a la Orin y ejecuta:</p>"
                    "<pre><code>az login --use-device-code</code></pre>"
                    "<p>Luego introduce el código en tu navegador corporativo y vuelve a intentar la sync.</p>"
                ),
                "result_text": "Error: No hay sesión Azure. Ejecuta 'az login --use-device-code' en la Orin.",
            }

        logger.info("Sincronizando Sentinel workspace=%s days=%s", workspace_id, days)

        # Si se proporciona un incident_id específico, buscar solo ese
        if incident_id:
            from utils.azure_sentinel import query_sentinel
            token = get_access_token()
            kql = f"""SecurityIncident
| where IncidentNumber == "{incident_id}"
| project IncidentNumber, Title, Description, Severity, Status, CreatedTime, AlertIds, Entities
| extend Entities = parse_json(Entities)"""
            result = query_sentinel(workspace_id, kql, token)
        else:
            result = fetch_recent_incidents(workspace_id, days)

        if not result.get("success"):
            error = result.get("error", "Error desconocido")
            return {
                "result_html": f"<p>❌ Error consultando Sentinel: {error}</p>",
                "result_text": f"Error consultando Sentinel: {error}",
            }

        rows = result.get("rows", [])
        if not rows:
            return {
                "result_html": "<p>ℹ️ No se encontraron incidentes en el período especificado.</p>",
                "result_text": "No se encontraron incidentes.",
            }

        # Generar resumen
        html_lines = [
            '<div class="azure-sync-report" style="font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;">',
            f'<h2>🌩️ Sincronización Azure Sentinel</h2>',
            f'<p><strong>Workspace:</strong> <code>{workspace_id}</code></p>',
            f'<p><strong>Período:</strong> últimos {days} días</p>',
            f'<p><strong>Incidentes encontrados:</strong> {len(rows)}</p>',
            '<div style="overflow-x:auto;">',
            '<table style="width:100%;border-collapse:collapse;font-size:.9rem;">',
            '<thead><tr style="background:var(--surface);border-bottom:2px solid var(--primary);">',
            '<th style="text-align:left;padding:.5rem;">Nº</th>',
            '<th style="text-align:left;padding:.5rem;">Título</th>',
            '<th style="text-align:center;padding:.5rem;">Severidad</th>',
            '<th style="text-align:center;padding:.5rem;">Estado</th>',
            '<th style="text-align:left;padding:.5rem;">Creado</th>',
            '</tr></thead><tbody>',
        ]

        text_lines = [
            f"# Sincronización Azure Sentinel",
            f"Workspace: {workspace_id}",
            f"Período: últimos {days} días",
            f"Incidentes: {len(rows)}",
            "",
            "| Nº | Título | Severidad | Estado | Creado |",
            "|---|---|---|---|---|",
        ]

        extracted_incidents = []
        for row in rows:
            inc_num = row.get("IncidentNumber", "N/A")
            inc_title = row.get("Title", "Sin título")
            inc_sev = row.get("Severity", "N/A")
            inc_status = row.get("Status", "N/A")
            inc_created = row.get("CreatedTime", "")
            inc_desc = row.get("Description", "")
            inc_entities = row.get("Entities", "[]")
            inc_alert_ids = row.get("AlertIds", "[]")

            sev_color = {
                "Critical": "#c62828",
                "High": "#f57c00",
                "Medium": "#f9a825",
                "Low": "#2e7d32",
            }.get(inc_sev, "#78909c")

            html_lines.append(
                f'<tr style="border-bottom:1px solid var(--border);">'
                f'<td style="padding:.5rem;"><code>{inc_num}</code></td>'
                f'<td style="padding:.5rem;">{inc_title}</td>'
                f'<td style="padding:.5rem;text-align:center;"><span style="display:inline-block;background:{sev_color};color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.8rem;font-weight:600;">{inc_sev}</span></td>'
                f'<td style="padding:.5rem;text-align:center;">{inc_status}</td>'
                f'<td style="padding:.5rem;font-size:.85rem;color:var(--text-muted);">{inc_created}</td>'
                f'</tr>'
            )

            text_lines.append(f"| {inc_num} | {inc_title} | {inc_sev} | {inc_status} | {inc_created} |")

            extracted_incidents.append({
                "incident_id": f"SENT-{inc_num}",
                "sentinel_number": str(inc_num),
                "title": inc_title,
                "description": inc_desc,
                "severity": inc_sev,
                "status": str(inc_status).lower() if inc_status else "open",
                "created_time": inc_created,
                "raw_data": json.dumps(row, ensure_ascii=False),
            })

        html_lines.extend([
            '</tbody></table></div>',
            f'<p style="margin-top:1rem;color:var(--text-muted);font-size:.85rem;">'
            f'Estos incidentes se han insertado en la base de datos. '
            f'Usa la página <strong>Blue Team</strong> para analizarlos individualmente.</p>',
            '</div>',
        ])

        text_lines.append("")
        text_lines.append("Los incidentes se han insertado en la base de datos.")

        return {
            "result_html": "\n".join(html_lines),
            "result_text": "\n".join(text_lines),
            "azure_sync_extracted": json.dumps(extracted_incidents, ensure_ascii=False),
        }
