"""Tarea: análisis de incidentes Blue Team con extracción de entidades e IOCs."""

import csv
import json
import logging
import os
import re
from datetime import datetime
from typing import Any

from tasks.base import BaseTask
from utils.llm_client import LlmClient
from utils.formatter import markdown_to_html

logger = logging.getLogger(__name__)

PROMPT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts", "incident_analysis.txt")

# Regex para extracción de entidades
_ENTITY_PATTERNS = {
    "ip": re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
    ),
    "domain": re.compile(
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    ),
    "hash_md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "hash_sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "hash_sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email": re.compile(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ),
    "url": re.compile(
        r"https?://[^\s\"<>{}|\^`\[\]]+"
    ),
}


def _extract_entities(text_rows: list[str]) -> dict[str, set[str]]:
    """Extrae entidades de un conjunto de strings usando regex."""
    entities: dict[str, set[str]] = {k: set() for k in _ENTITY_PATTERNS}
    all_text = "\n".join(text_rows)
    for etype, pattern in _ENTITY_PATTERNS.items():
        for match in pattern.finditer(all_text):
            val = match.group(0)
            # Filtrar falsos positivos comunes
            if etype == "domain" and val.lower().endswith(
                (".com", ".org", ".net", ".gov", ".edu")
            ):
                # Permitir dominios comunes si no son TLD solos
                if "." in val[:-4]:
                    entities[etype].add(val.lower())
            elif etype == "ip":
                # Excluir rangos privados comunes si son muy genéricos
                if not val.startswith("127.") and not val.startswith("0."):
                    entities[etype].add(val)
            else:
                entities[etype].add(val)
    return entities


def _parse_csv(csv_data: str) -> list[dict[str, str]]:
    """Parsea CSV a lista de dicts. Intenta Polars primero, fallback a csv."""
    try:
        import polars as pl
        from io import StringIO
        df = pl.read_csv(StringIO(csv_data))
        return [dict(row) for row in df.iter_rows(named=True)]
    except Exception as exc:
        logger.warning("Polars CSV parse failed (%s), falling back to stdlib csv", exc)

    try:
        from io import StringIO
        reader = csv.DictReader(StringIO(csv_data))
        return [row for row in reader if any(v.strip() for v in row.values())]
    except Exception as exc:
        logger.error("CSV parse failed completely: %s", exc)
        return []


def _build_llm_context(incident_id: str, title: str, severity: str, rows: list[dict], entities: dict) -> str:
    """Construye el prompt de contexto para el LLM."""
    lines = [
        f"Incidente: {incident_id}",
        f"Título: {title}",
        f"Severidad: {severity}",
        f"Registros analizados: {len(rows)}",
        "",
        "=== MUESTRA DE REGISTROS ===",
    ]
    for i, row in enumerate(rows[:10]):
        lines.append(f"Fila {i+1}: {json.dumps(row, ensure_ascii=False)}")
    if len(rows) > 10:
        lines.append(f"... y {len(rows) - 10} registros más.")

    lines.append("")
    lines.append("=== ENTIDADES EXTRAÍDAS ===")
    for etype, vals in entities.items():
        if vals:
            lines.append(f"{etype}: {', '.join(sorted(vals)[:20])}")

    return "\n".join(lines)


def _calculate_risk_score(entity_value: str, rows: list[dict], llm_verdict: str | None) -> float:
    """Score simplificado 0.0-1.0 basado en frecuencia y veredicto LLM."""
    score = 0.0
    count = sum(1 for r in rows if entity_value in str(r).lower())
    score += min(count, 10) * 0.03  # hasta 0.3
    if llm_verdict == "True Positive":
        score += 0.4
    elif llm_verdict == "Needs Review":
        score += 0.2
    return min(score, 1.0)


def _render_incident_html(
    incident_id: str,
    title: str,
    severity: str,
    llm_analysis: dict | None,
    entities: dict[str, set[str]],
    rows: list[dict],
) -> str:
    """Genera HTML del informe de incidente."""

    verdict = llm_analysis.get("veredicto", "N/A") if llm_analysis else "N/A"
    confidence = llm_analysis.get("confianza", 0.0) if llm_analysis else 0.0
    mitre_tac = llm_analysis.get("mitre_tactic", "N/A") if llm_analysis else "N/A"
    mitre_tec = llm_analysis.get("mitre_technique", "N/A") if llm_analysis else "N/A"
    justif = llm_analysis.get("justificacion", "") if llm_analysis else ""
    recs = llm_analysis.get("recomendaciones", []) if llm_analysis else []
    risky = llm_analysis.get("entidades_riesgosas", []) if llm_analysis else []
    notes = llm_analysis.get("notas", "") if llm_analysis else ""

    verdict_color = {
        "True Positive": "#c62828",
        "False Positive": "#2e7d32",
        "Needs Review": "#f57c00",
    }.get(verdict, "#78909c")

    severity_color = {
        "CRITICAL": "#c62828",
        "HIGH": "#f57c00",
        "MEDIUM": "#f9a825",
        "LOW": "#2e7d32",
    }.get(severity.upper(), "#78909c")

    html = f'''<div class="incident-report" style="font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:1.5rem;">
    <div style="display:inline-block;border:2px solid var(--primary);padding:.75rem 2rem;border-radius:var(--radius);">
      <span style="font-size:1.2rem;font-weight:700;color:var(--primary);">🛡️ {incident_id}</span>
    </div>
    <p style="margin-top:.5rem;font-size:1.1rem;font-weight:600;">{title}</p>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem;">
    <div style="background:var(--surface);border-radius:var(--radius-sm);padding:1rem;text-align:center;">
      <div style="font-size:.85rem;color:var(--text-muted);">Severidad</div>
      <div style="display:inline-block;background:{severity_color};color:#fff;padding:.25rem .8rem;border-radius:4px;font-weight:700;margin-top:.25rem;">{severity}</div>
    </div>
    <div style="background:var(--surface);border-radius:var(--radius-sm);padding:1rem;text-align:center;">
      <div style="font-size:.85rem;color:var(--text-muted);">Veredicto LLM</div>
      <div style="display:inline-block;background:{verdict_color};color:#fff;padding:.25rem .8rem;border-radius:4px;font-weight:700;margin-top:.25rem;">{verdict}</div>
      <div style="font-size:.8rem;color:var(--text-muted);margin-top:.25rem;">Confianza: {confidence:.0%}</div>
    </div>
  </div>
'''

    # MITRE
    if mitre_tac != "N/A":
        html += f'''<div style="margin:1rem 0;border-left:4px solid var(--accent);padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">
    <div style="font-weight:700;color:var(--primary);margin-bottom:.5rem;">🎯 MITRE ATT&CK</div>
    <div><strong>Tactic:</strong> {mitre_tac}</div>
    <div><strong>Technique:</strong> {mitre_tec}</div>
  </div>
'''

    # Entidades
    html += '<div style="margin:1rem 0;border-left:4px solid var(--accent);padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">\n'
    html += '<div style="font-weight:700;color:var(--primary);margin-bottom:.5rem;">🔍 Entidades Extraídas</div>\n'
    for etype, vals in entities.items():
        if vals:
            label = {"ip": "IPs", "domain": "Dominios", "hash_md5": "MD5", "hash_sha1": "SHA1",
                     "hash_sha256": "SHA256", "email": "Emails", "url": "URLs"}.get(etype, etype)
            display_vals = sorted(vals)[:15]
            extra = f" <em>(+{len(vals) - 15} más)</em>" if len(vals) > 15 else ""
            html += f'<div style="margin:.25rem 0;"><strong>{label}:</strong> <code>{"</code> <code>".join(display_vals)}</code>{extra}</div>\n'
    html += '</div>\n'

    # Justificación
    if justif:
        html += '<div style="margin:1rem 0;border-left:4px solid var(--accent);padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">\n'
        html += '<div style="font-weight:700;color:var(--primary);margin-bottom:.5rem;">📝 Justificación del Análisis</div>\n'
        html += f'<div style="line-height:1.6;">{markdown_to_html(justif)}</div>\n'
        html += '</div>\n'

    # Entidades riesgosas
    if risky:
        html += '<div style="margin:1rem 0;border-left:4px solid #c62828;padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">\n'
        html += '<div style="font-weight:700;color:#c62828;margin-bottom:.5rem;">⚠️ Entidades de Alto Riesgo</div>\n'
        html += '<ul style="margin:0;padding-left:1.2rem;">\n'
        for r in risky:
            html += f'<li>{r}</li>\n'
        html += '</ul>\n</div>\n'

    # Recomendaciones
    if recs:
        html += '<div style="margin:1rem 0;border-left:4px solid #2e7d32;padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">\n'
        html += '<div style="font-weight:700;color:#2e7d32;margin-bottom:.5rem;">✅ Recomendaciones</div>\n'
        html += '<ul style="margin:0;padding-left:1.2rem;">\n'
        for rec in recs:
            html += f'<li>{rec}</li>\n'
        html += '</ul>\n</div>\n'

    # Notas
    if notes:
        html += '<div style="margin:1rem 0;border-left:4px solid var(--accent);padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">\n'
        html += '<div style="font-weight:700;color:var(--primary);margin-bottom:.5rem;">📌 Notas</div>\n'
        html += f'<div style="line-height:1.6;">{markdown_to_html(notes)}</div>\n'
        html += '</div>\n'

    # Stats
    html += f'''<div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--text-muted);font-size:.85rem;">
    Registros analizados: {len(rows)} · Entidades únicas: {sum(len(v) for v in entities.values())}
  </div>
</div>'''

    return html


class IncidentAnalysisTask(BaseTask):
    task_type = "incident_analysis"

    def __init__(self, config_path: str = None):
        self.llm = LlmClient(config_path)
        with open(PROMPT_PATH, "r", encoding="utf-8") as f:
            self.prompt_template = f.read()

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        incident_id = input_data.get("incident_id", "UNKNOWN")
        title = input_data.get("title", "Sin título")
        severity = input_data.get("severity", "Medium")
        csv_data = input_data.get("csv_data", "")

        logger.info("Analizando incidente %s — %s", incident_id, title)

        if not csv_data:
            return {
                "result_html": "<p>Error: No se proporcionaron datos CSV.</p>",
                "result_text": "Error: No se proporcionaron datos CSV.",
            }

        rows = _parse_csv(csv_data)
        if not rows:
            return {
                "result_html": "<p>Error: No se pudieron parsear los datos CSV.</p>",
                "result_text": "Error: No se pudieron parsear los datos CSV.",
            }

        # Extraer entidades de todos los campos del CSV
        all_values = []
        for row in rows:
            for val in row.values():
                all_values.append(str(val))
        entities = _extract_entities(all_values)

        # Contexto para LLM
        context = _build_llm_context(incident_id, title, severity, rows, entities)

        # Llamar al LLM
        llm_analysis = None
        try:
            llm_analysis = self.llm.chat_json(
                system_prompt=self.prompt_template,
                user_prompt=context,
            )
            logger.info("LLM analysis received for %s: verdict=%s", incident_id,
                        llm_analysis.get("veredicto") if llm_analysis else "N/A")
        except Exception as exc:
            logger.warning("LLM call failed for %s: %s", incident_id, exc)

        # Generar informe HTML
        html = _render_incident_html(incident_id, title, severity, llm_analysis, entities, rows)

        # Generar texto plano (Markdown)
        lines = [
            f"# Incidente: {incident_id}",
            f"**Título:** {title}",
            f"**Severidad:** {severity}",
            f"**Veredicto LLM:** {llm_analysis.get('veredicto', 'N/A') if llm_analysis else 'N/A'}",
            f"**Confianza:** {llm_analysis.get('confianza', 0.0) if llm_analysis else 0.0:.0%}",
            "",
        ]
        if llm_analysis:
            lines.append(f"**MITRE Tactic:** {llm_analysis.get('mitre_tactic', 'N/A')}")
            lines.append(f"**MITRE Technique:** {llm_analysis.get('mitre_technique', 'N/A')}")
            lines.append("")
            justif = llm_analysis.get("justificacion", "")
            if justif:
                lines.append("## Justificación")
                lines.append(justif)
                lines.append("")
            risky = llm_analysis.get("entidades_riesgosas", [])
            if risky:
                lines.append("## Entidades de Alto Riesgo")
                for r in risky:
                    lines.append(f"- {r}")
                lines.append("")
            recs = llm_analysis.get("recomendaciones", [])
            if recs:
                lines.append("## Recomendaciones")
                for rec in recs:
                    lines.append(f"- {rec}")
                lines.append("")
            notes = llm_analysis.get("notas", "")
            if notes:
                lines.append(f"## Notas\n{notes}")
                lines.append("")

        lines.append("## Entidades Extraídas")
        for etype, vals in entities.items():
            if vals:
                label = {"ip": "IPs", "domain": "Dominios", "hash_md5": "MD5", "hash_sha1": "SHA1",
                         "hash_sha256": "SHA256", "email": "Emails", "url": "URLs"}.get(etype, etype)
                lines.append(f"**{label}:** {', '.join(sorted(vals)[:20])}")
        lines.append("")
        lines.append(f"*Registros analizados: {len(rows)}*")

        text = "\n".join(lines)

        verdict = llm_analysis.get("veredicto") if llm_analysis else None
        mitre_tac = llm_analysis.get("mitre_tactic") if llm_analysis else None

        return {
            "result_html": html,
            "result_text": text,
            "blue_team_verdict": verdict,
            "blue_team_mitre_tactic": mitre_tac,
        }
