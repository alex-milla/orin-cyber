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
from utils.osint_client import get_osint_summary, enrich_ioc
from utils.azure_sentinel import generate_hunting_kql, generate_entity_hunting_kql

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


def _build_llm_context(
    incident_id: str,
    title: str,
    severity: str,
    rows: list[dict],
    entities: dict,
    osint_data: dict,
    config_path: str | None = None,
) -> str:
    """Construye el prompt de contexto para el LLM, enriquecido con OSINT."""
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

    # OSINT para entidades clave
    osint_lines = []
    for etype, vals in entities.items():
        if not vals or etype not in ("ip", "domain", "hash_sha256", "hash_md5", "url"):
            continue
        for val in sorted(vals)[:5]:
            ioc_type = {"ip": "ip", "domain": "domain", "hash_sha256": "hash", "hash_md5": "hash", "url": "url"}.get(etype)
            if ioc_type:
                osint_lines.append(get_osint_summary(val, ioc_type, config_path))

    if osint_lines:
        lines.append("")
        lines.append("=== INTELIGENCIA OSINT ===")
        lines.extend(osint_lines)

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
    osint_data: dict[str, dict],
    hunting_queries: list[dict],
) -> str:
    """Genera HTML del informe de incidente."""

    verdict = llm_analysis.get("veredicto", "N/A") if llm_analysis else "N/A"
    confidence = llm_analysis.get("confianza", 0.0) if llm_analysis else 0.0
    classification = llm_analysis.get("clasificacion", "N/A") if llm_analysis else "N/A"
    class_conf = llm_analysis.get("confianza_clasificacion", 0.0) if llm_analysis else 0.0
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

    class_color = {
        "DIRIGIDO": "#c62828",
        "GENERICO": "#1976d2",
    }.get(classification, "#78909c")

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

  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:1.5rem;">
    <div style="background:var(--surface);border-radius:var(--radius-sm);padding:1rem;text-align:center;">
      <div style="font-size:.85rem;color:var(--text-muted);">Severidad</div>
      <div style="display:inline-block;background:{severity_color};color:#fff;padding:.25rem .8rem;border-radius:4px;font-weight:700;margin-top:.25rem;">{severity}</div>
    </div>
    <div style="background:var(--surface);border-radius:var(--radius-sm);padding:1rem;text-align:center;">
      <div style="font-size:.85rem;color:var(--text-muted);">Veredicto LLM</div>
      <div style="display:inline-block;background:{verdict_color};color:#fff;padding:.25rem .8rem;border-radius:4px;font-weight:700;margin-top:.25rem;">{verdict}</div>
      <div style="font-size:.8rem;color:var(--text-muted);margin-top:.25rem;">Confianza: {confidence:.0%}</div>
    </div>
    <div style="background:var(--surface);border-radius:var(--radius-sm);padding:1rem;text-align:center;">
      <div style="font-size:.85rem;color:var(--text-muted);">Clasificación</div>
      <div style="display:inline-block;background:{class_color};color:#fff;padding:.25rem .8rem;border-radius:4px;font-weight:700;margin-top:.25rem;">{classification}</div>
      <div style="font-size:.8rem;color:var(--text-muted);margin-top:.25rem;">Confianza: {class_conf:.0%}</div>
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
    # Hunting queries
    if hunting_queries:
        html += '<div style="margin:1rem 0;border-left:4px solid #6a1b9a;padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">\n'
        html += '<div style="font-weight:700;color:#6a1b9a;margin-bottom:.5rem;">🔎 Queries KQL de Hunting</div>\n'
        for hq in hunting_queries:
            html += f'<details style="margin:.5rem 0;"><summary style="cursor:pointer;font-weight:600;">{hq["type"].upper()}: <code>{hq["target"]}</code></summary>\n'
            html += f'<pre style="background:var(--bg);padding:.75rem;border-radius:var(--radius-sm);overflow-x:auto;font-size:.8rem;margin-top:.5rem;"><code>{hq["kql"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")}</code></pre></details>\n'
        html += '</div>\n'

    # OSINT section
    if osint_data:
        html += '<div style="margin:1rem 0;border-left:4px solid #1976d2;padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">\n'
        html += '<div style="font-weight:700;color:#1976d2;margin-bottom:.5rem;">🌐 Inteligencia OSINT</div>\n'
        html += '<table style="width:100%;font-size:.85rem;border-collapse:collapse;">\n'
        html += '<thead><tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;padding:.3rem;">IOC</th><th style="text-align:left;padding:.3rem;">Tipo</th><th style="text-align:center;padding:.3rem;">VT</th><th style="text-align:center;padding:.3rem;">AbuseIPDB</th><th style="text-align:center;padding:.3rem;">URLhaus</th><th style="text-align:center;padding:.3rem;">OTX</th></tr></thead>\n'
        html += '<tbody>\n'
        for key, data in osint_data.items():
            parts = key.split(":", 1)
            ioc_type = parts[0] if len(parts) > 0 else "?"
            ioc_val = parts[1] if len(parts) > 1 else key
            vt = data.get("vt")
            abuse = data.get("abuseipdb")
            uh = data.get("urlhaus")
            otx = data.get("otx")

            vt_str = f"{vt['malicious']}/{vt['total']}" if vt and vt.get("found") else "—"
            abuse_str = f"{abuse['score']}/100" if abuse and abuse.get("found") else "—"
            uh_str = "⚠️" if uh and uh.get("found") else "—"
            otx_str = f"{otx['pulse_count']}" if otx and otx.get("found") else "—"

            html += f'<tr style="border-bottom:1px solid var(--border);"><td style="padding:.3rem;"><code>{ioc_val}</code></td><td style="padding:.3rem;">{ioc_type}</td><td style="text-align:center;padding:.3rem;">{vt_str}</td><td style="text-align:center;padding:.3rem;">{abuse_str}</td><td style="text-align:center;padding:.3rem;">{uh_str}</td><td style="text-align:center;padding:.3rem;">{otx_str}</td></tr>\n'
        html += '</tbody></table>\n</div>\n'

    html += f'''<div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--text-muted);font-size:.85rem;">
    Registros analizados: {len(rows)} · Entidades únicas: {sum(len(v) for v in entities.values())}
  </div>
</div>'''

    return html


def _is_sentinel_obfuscated_csv(rows: list[dict]) -> bool:
    """Detecta si el CSV tiene la estructura del export Sentinel ofuscado."""
    if not rows:
        return False
    required = {"userhash", "userdomain", "entitytype"}
    headers_lower = {k.lower() for k in rows[0].keys()}
    return required.issubset(headers_lower)


def _parse_sentinel_obfuscated_rows(rows: list[dict]) -> list[dict]:
    """
    Normaliza las filas del CSV ofuscado de Sentinel.
    Devuelve lista de dicts con claves normalizadas.
    """
    normalized = []
    for row in rows:
        # Normalizar claves a lowercase
        r = {k.lower(): v for k, v in row.items()}

        def parse_json_array(val: str) -> list:
            val = val.strip() if val else ""
            if not val:
                return []
            try:
                result = json.loads(val)
                return result if isinstance(result, list) else [val]
            except Exception:
                return [x.strip().strip('"\'') for x in val.strip('[]').split(',') if x.strip()]

        normalized.append({
            "user_hash":    r.get("userhash", ""),
            "user_domain":  r.get("userdomain", ""),
            "subject":      r.get("subject", ""),
            "entity_type":  r.get("entitytype", "user"),
            "severity":     r.get("severity", "high"),
            "countries":    parse_json_array(r.get("countries", "")),
            "cities":       parse_json_array(r.get("cities", "")),
            "ips":          parse_json_array(r.get("ips", "")),
            "apps":         parse_json_array(r.get("apps", "")),
            "first_seen":   r.get("firstseen", ""),
            "last_seen":    r.get("lastseen", ""),
            "login_count":  r.get("logincount", "0"),
        })
    return normalized


def _build_sentinel_obfuscated_context(
    incident_id: str,
    title: str,
    severity: str,
    normalized_rows: list[dict],
) -> str:
    """
    Construye el prompt para el LLM con datos del CSV Sentinel ofuscado.
    Los usuarios están identificados por hash, no por nombre.
    """
    lines = [
        f"Incidente: {incident_id}",
        f"Título: {title}",
        f"Severidad: {severity}",
        f"Tipo de análisis: Logins desde países no habituales (fuera de ES)",
        f"Registros analizados: {len(normalized_rows)}",
        "",
        "NOTA IMPORTANTE: Los usuarios están ofuscados por privacidad.",
        "El campo UserHash es el identificador único del usuario (SHA256 del UPN).",
        "No intentes deducir el nombre del usuario.",
        "",
        "=== REGISTROS ===",
    ]

    for i, row in enumerate(normalized_rows):
        lines.append(f"\nUsuario {i+1}:")
        lines.append(f"  Hash:          {row['user_hash']}")
        lines.append(f"  Dominio:       {row['user_domain']}")
        lines.append(f"  Países:        {', '.join(row['countries'])}")
        lines.append(f"  Ciudades:      {', '.join(row['cities'])}")
        lines.append(f"  IPs:           {', '.join(row['ips'])}")
        lines.append(f"  Apps usadas:   {', '.join(row['apps'])}")
        lines.append(f"  Primer login:  {row['first_seen']}")
        lines.append(f"  Último login:  {row['last_seen']}")
        lines.append(f"  Total logins:  {row['login_count']}")

    lines.append("")
    lines.append("=== ANÁLISIS SOLICITADO ===")
    lines.append(
        "Para cada usuario, evalúa si el login desde un país no habitual es sospechoso "
        "o puede ser legítimo (viaje de trabajo, VPN, Andorra como país fronterizo, etc.). "
        "Considera el país, las IPs, las apps usadas y la frecuencia."
    )

    return "\n".join(lines)


class IncidentAnalysisTask(BaseTask):
    task_type = "incident_analysis"

    def __init__(self, config_path: str = None):
        self.config_path = config_path
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

        # ── NUEVO: detectar CSV de Sentinel ofuscado ──────────────────────
        if _is_sentinel_obfuscated_csv(rows):
            logger.info("CSV detectado como Sentinel ofuscado para incidente %s", incident_id)
            normalized = _parse_sentinel_obfuscated_rows(rows)
            context = _build_sentinel_obfuscated_context(incident_id, title, severity, normalized)

            # Extraer IPs para OSINT (las IPs sí están en claro)
            all_ips = []
            for r in normalized:
                all_ips.extend(r["ips"])
            all_ips = list(set(all_ips))[:10]

            osint_data = {}
            for ip in all_ips:
                osint_data[f"ip:{ip}"] = enrich_ioc(ip, "ip", self.config_path)

            if osint_data:
                context += "\n\n=== OSINT IPs ===\n"
                for key, data in osint_data.items():
                    context += f"{key}: {json.dumps(data, ensure_ascii=False)}\n"

            # Llamar al LLM con el contexto estructurado
            llm_analysis = None
            try:
                llm_analysis = self.llm.chat_json(
                    system_prompt=self.prompt_template,
                    user_prompt=context,
                )
            except Exception as exc:
                logger.warning("LLM call failed for %s: %s", incident_id, exc)

            # Generar KQL de hunting para cada IP detectada
            hunting_queries = []
            for ip in all_ips[:5]:
                kql = generate_hunting_kql(ip, "ip")
                hunting_queries.append({"target": ip, "type": "ip", "kql": kql})

            # Generar informe con los datos normalizados
            return self._build_sentinel_report(
                incident_id, title, severity,
                normalized, llm_analysis, hunting_queries, osint_data
            )
        # ── FIN NUEVO ────────────────────────────────────────────────────

        # Extraer entidades de todos los campos del CSV
        all_values = []
        for row in rows:
            for val in row.values():
                all_values.append(str(val))
        entities = _extract_entities(all_values)

        # Consultar OSINT para entidades clave
        osint_data: dict[str, dict] = {}
        for etype, vals in entities.items():
            if not vals or etype not in ("ip", "domain", "hash_sha256", "hash_md5", "url"):
                continue
            for val in sorted(vals)[:5]:
                ioc_type = {"ip": "ip", "domain": "domain", "hash_sha256": "hash", "hash_md5": "hash", "url": "url"}.get(etype)
                if ioc_type:
                    osint_data[f"{ioc_type}:{val}"] = enrich_ioc(val, ioc_type, self.config_path)

        # Contexto para LLM
        context = _build_llm_context(incident_id, title, severity, rows, entities, osint_data, self.config_path)

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

        # Generar queries KQL de hunting para entidades extraídas
        hunting_queries: list[dict] = []
        for etype, vals in entities.items():
            if not vals or etype not in ("ip", "domain", "hash_sha256", "hash_md5", "url", "email"):
                continue
            for val in sorted(vals)[:3]:
                ioc_type = {"ip": "ip", "domain": "domain", "hash_sha256": "hash", "hash_md5": "hash", "url": "url", "email": "user"}.get(etype)
                if ioc_type == "user":
                    kql = generate_entity_hunting_kql(val, "user")
                    hunting_queries.append({"target": val, "type": "user", "kql": kql})
                elif ioc_type:
                    kql = generate_hunting_kql(val, ioc_type)
                    hunting_queries.append({"target": val, "type": ioc_type, "kql": kql})

        # Generar informe HTML
        html = _render_incident_html(incident_id, title, severity, llm_analysis, entities, rows, osint_data, hunting_queries)

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
        classification = llm_analysis.get("clasificacion") if llm_analysis else None

        return {
            "result_html": html,
            "result_text": text,
            "blue_team_verdict": verdict,
            "blue_team_mitre_tactic": mitre_tac,
            "blue_team_classification": classification,
        }

    def _build_sentinel_report(
        self,
        incident_id: str,
        title: str,
        severity: str,
        normalized_rows: list[dict],
        llm_analysis: dict | None,
        hunting_queries: list[dict],
        osint_data: dict,
    ) -> dict[str, str]:
        """Genera el informe HTML para CSV de Sentinel ofuscado."""

        verdict      = llm_analysis.get("veredicto", "NEEDS REVIEW") if llm_analysis else "NEEDS REVIEW"
        summary      = llm_analysis.get("resumen", "")               if llm_analysis else ""
        mitre        = llm_analysis.get("mitre_tecnicas", [])         if llm_analysis else []
        recomendaciones = llm_analysis.get("recomendaciones", [])     if llm_analysis else []

        # Mapear veredicto a valores esperados por el sistema
        verdict_map = {
            "MALICIOSO": "True Positive",
            "SOSPECHOSO": "Needs Review",
            "NEEDS REVIEW": "Needs Review",
            "BENIGNO": "False Positive",
        }
        system_verdict = verdict_map.get(verdict.upper(), "Needs Review")

        # Construir tabla de usuarios
        users_rows_html = ""
        for row in normalized_rows:
            countries_str = ", ".join(row["countries"])
            ips_str       = ", ".join(row["ips"][:3])
            users_rows_html += f"""
            <tr>
                <td><code style="font-size:.75rem;">{row["user_hash"][:20]}…</code><br>
                    <small style="color:var(--text-muted);">{row["user_domain"]}</small></td>
                <td>{countries_str}</td>
                <td style="font-size:.8rem;">{ips_str}</td>
                <td>{row["login_count"]}</td>
                <td><small>{row["first_seen"][:10] if row["first_seen"] else "—"}</small></td>
            </tr>"""

        # KQL de hunting
        kql_sections = ""
        for q in hunting_queries:
            kql_sections += f"""
            <div style="margin-bottom:1rem;">
                <strong>IP: {q["target"]}</strong>
                <pre style="background:var(--surface-2);padding:.75rem;border-radius:var(--radius-sm);
                            font-size:.8rem;overflow-x:auto;margin:.5rem 0;">{q["kql"]}</pre>
            </div>"""

        mitre_html = ""
        for t in (mitre if isinstance(mitre, list) else [mitre]):
            mitre_html += f'<span class="badge" style="margin:.2rem;">{t}</span>'

        rec_html = ""
        for r in (recomendaciones if isinstance(recomendaciones, list) else [recomendaciones]):
            rec_html += f"<li>{r}</li>"

        verdict_color = {
            "MALICIOSO": "severity-critical",
            "SOSPECHOSO": "severity-high",
            "NEEDS REVIEW": "severity-medium",
            "BENIGNO": "severity-low",
        }.get(verdict.upper(), "severity-medium")

        html = f"""
        <div style="font-family:var(--font-mono,monospace);">

        <!-- KPIs -->
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem;">
            <div style="background:var(--surface-2);padding:1rem;border-radius:var(--radius);">
                <div style="font-size:.75rem;color:var(--text-muted);">USUARIOS AFECTADOS</div>
                <div style="font-size:2rem;font-weight:700;">{len(normalized_rows)}</div>
            </div>
            <div style="background:var(--surface-2);padding:1rem;border-radius:var(--radius);">
                <div style="font-size:.75rem;color:var(--text-muted);">PAÍSES DETECTADOS</div>
                <div style="font-size:2rem;font-weight:700;">
                    {len(set(c for r in normalized_rows for c in r["countries"]))}
                </div>
            </div>
            <div style="background:var(--surface-2);padding:1rem;border-radius:var(--radius);">
                <div style="font-size:.75rem;color:var(--text-muted);">VEREDICTO</div>
                <div><span class="badge {verdict_color}" style="font-size:1rem;">{verdict}</span></div>
            </div>
        </div>

        <!-- Aviso privacidad -->
        <div style="background:var(--surface-2);border-left:3px solid var(--accent);
                    padding:.75rem 1rem;border-radius:var(--radius-sm);margin-bottom:1.5rem;
                    font-size:.85rem;">
            🔒 <strong>Datos ofuscados:</strong> Los usuarios están identificados por hash SHA256.
            Para desofuscar un caso específico, ejecuta la query de desofuscación en Sentinel.
        </div>

        <!-- Resumen LLM -->
        <h3 style="margin:0 0 .5rem;">Análisis del LLM</h3>
        <p style="margin-bottom:1rem;">{summary or "Sin análisis disponible."}</p>

        <!-- MITRE -->
        {f'<div style="margin-bottom:1rem;"><strong>MITRE ATT&amp;CK:</strong><br>{mitre_html}</div>' if mitre_html else ""}

        <!-- Recomendaciones -->
        {f'<h3>Recomendaciones</h3><ul>{rec_html}</ul>' if rec_html else ""}

        <!-- Tabla de usuarios -->
        <h3 style="margin:1.5rem 0 .5rem;">Detalle por usuario</h3>
        <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:.85rem;">
                <thead>
                    <tr style="background:var(--surface-2);">
                        <th style="padding:.5rem;text-align:left;">Usuario (hash)</th>
                        <th style="padding:.5rem;text-align:left;">Países</th>
                        <th style="padding:.5rem;text-align:left;">IPs</th>
                        <th style="padding:.5rem;text-align:left;">Logins</th>
                        <th style="padding:.5rem;text-align:left;">Primer login</th>
                    </tr>
                </thead>
                <tbody>{users_rows_html}</tbody>
            </table>
        </div>

        <!-- KQL Hunting -->
        {f'<h3 style="margin:1.5rem 0 .5rem;">KQL Hunting (por IP)</h3>{kql_sections}' if kql_sections else ""}

        </div>"""

        # Texto plano para result_text
        text_lines = [
            f"Incidente: {incident_id} — {title}",
            f"Veredicto: {verdict}",
            f"Usuarios afectados: {len(normalized_rows)}",
            f"Resumen: {summary}",
            "",
        ]
        for row in normalized_rows:
            text_lines.append(
                f"- hash:{row['user_hash'][:16]}… ({row['user_domain']}) "
                f"→ {', '.join(row['countries'])} | IPs: {', '.join(row['ips'][:3])}"
            )

        return {
            "result_html": html,
            "result_text": "\n".join(text_lines),
            "blue_team_verdict": system_verdict,
            "blue_team_mitre_tactic": None,
            "blue_team_classification": None,
        }
