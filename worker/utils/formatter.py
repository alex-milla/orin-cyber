"""Formateo de resultados para HTML y texto plano."""

import re


def markdown_to_html(text: str) -> str:
    """Convierte markdown básico a HTML seguro y compacto."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    text = re.sub(r"^### (.+)$", r"<h3>\1</h3>", text, flags=re.MULTILINE)
    text = re.sub(r"^## (.+)$", r"<h2>\1</h2>", text, flags=re.MULTILINE)
    text = re.sub(r"^# (.+)$", r"<h1>\1</h1>", text, flags=re.MULTILINE)

    text = re.sub(r"\*\*\*(.+?)\*\*\*", r"<strong><em>\1</em></strong>", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)

    # Procesar listas
    lines = text.split("\n")
    new_lines = []
    in_list = False
    list_type = None
    for line in lines:
        sline = line.strip()
        if sline.startswith("- ") or sline.startswith("* "):
            if not in_list or list_type != 'ul':
                if in_list:
                    new_lines.append(f"</{list_type}>")
                new_lines.append("<ul>")
                in_list = True
                list_type = 'ul'
            item = sline[2:]
            new_lines.append(f"<li>{item}</li>")
        elif re.match(r"^\d+\.\s", sline):
            if not in_list or list_type != 'ol':
                if in_list:
                    new_lines.append(f"</{list_type}>")
                new_lines.append("<ol>")
                in_list = True
                list_type = 'ol'
            item = re.sub(r"^\d+\.\s", "", sline)
            new_lines.append(f"<li>{item}</li>")
        else:
            if in_list:
                new_lines.append(f"</{list_type}>")
                in_list = False
                list_type = None
            new_lines.append(line)
    if in_list:
        new_lines.append(f"</{list_type}>")
    text = "\n".join(new_lines)

    # Párrafos
    paragraphs = []
    current_para = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if current_para:
                paragraphs.append("<p>" + "<br>\n".join(current_para) + "</p>")
                current_para = []
            paragraphs.append("")
        elif stripped.startswith("<"):
            if current_para:
                paragraphs.append("<p>" + "<br>\n".join(current_para) + "</p>")
                current_para = []
            paragraphs.append(stripped)
        else:
            current_para.append(stripped)
    if current_para:
        paragraphs.append("<p>" + "<br>\n".join(current_para) + "</p>")

    text = "\n".join(paragraphs)

    # Enlaces markdown
    text = re.sub(
        r'\[([^\]]+)\]\(([^)]+)\)',
        r'<a href="\2" target="_blank" rel="noopener">\1</a>',
        text,
    )

    return text


def _severity_badge(severity: str) -> str:
    color = {
        "CRITICAL": "#c62828",
        "HIGH": "#f57c00",
        "MEDIUM": "#f9a825",
        "LOW": "#2e7d32",
    }.get(severity.upper(), "#78909c")
    return f'<span style="display:inline-block;background:{color};color:#fff;padding:.2rem .6rem;border-radius:4px;font-size:.85rem;font-weight:600;">{severity}</span>'


def _priority_badge(priority: str) -> str:
    color = {"A+": "#c62828", "A": "#f57c00", "B": "#f9a825", "C": "#1976d2", "D": "#78909c"}.get(priority, "#78909c")
    return f'<span style="display:inline-block;background:{color};color:#fff;padding:.25rem .8rem;border-radius:4px;font-size:1.1rem;font-weight:700;">{priority}</span>'


def _section(title: str, content: str, icon: str = "") -> str:
    return f'''<div style="margin:1.25rem 0;border-left:4px solid var(--accent);padding:.75rem 1rem;background:var(--surface);border-radius:0 var(--radius-sm) var(--radius-sm) 0;">
  <div style="font-weight:700;color:var(--primary);margin-bottom:.5rem;font-size:1.05rem;">{icon} {title}</div>
  <div style="line-height:1.6;">{content}</div>
</div>'''


def render_cve_report_text(report_text: str, cve_data: dict | None = None) -> str:
    """Convierte un informe en texto plano con box-drawing a HTML que preserve el formato.

    El texto se envuelve en un bloque <pre> con estilos CSS para mantener la alineación
    de los caracteres de dibujo de cajas, mientras que las URLs se hacen clicables.
    """
    if not report_text:
        return "<p>Sin contenido.</p>"

    # Escapar HTML
    html = report_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Convertir URLs a enlaces clickeables dentro del texto plano
    html = re.sub(
        r'(https?://[^\s\)\]\>\"\'\`]+)',
        r'<a href="\1" target="_blank" rel="noopener" style="color:var(--primary);text-decoration:underline;">\1</a>',
        html,
    )

    cve_id = cve_data.get("cve_id", "") if cve_data else ""
    severity = cve_data.get("severity", "") if cve_data else ""
    score = cve_data.get("score") if cve_data else None

    # Badge de severidad opcional arriba del reporte
    badge_html = ""
    if severity and severity != "N/A":
        badge_html = f'<div style="margin-bottom:.5rem;">{_severity_badge(severity)}</div>'

    return f'''<div class="cve-report" style="font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:1rem;">
    {badge_html}
  </div>
  <pre style="white-space:pre-wrap;word-wrap:break-word;font-family:'Consolas','Monaco','Courier New',monospace;font-size:.95rem;line-height:1.5;background:var(--bg);padding:1.25rem;border-radius:var(--radius);border:1px solid var(--border);overflow-x:auto;">{html}</pre>
</div>'''


def render_cve_report_batch(enriched: list) -> str:
    """Genera HTML comparativo para múltiples CVEs (modo batch)."""
    if not enriched:
        return "<p>No hay datos para mostrar.</p>"

    html = '''<div class="cve-report" style="font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:1.5rem;">
    <div style="display:inline-block;border:2px solid var(--primary);padding:.75rem 2rem;border-radius:var(--radius);">
      <span style="font-size:1.4rem;font-weight:700;color:var(--primary);">Batch CVE Report</span>
    </div>
    <p style="color:var(--text-muted);margin-top:.5rem;">''' + str(len(enriched)) + ''' CVEs analizados</p>
  </div>
'''

    # Tabla comparativa
    html += '''<div style="overflow-x:auto;margin-bottom:1.5rem;">
  <table style="width:100%;border-collapse:collapse;font-size:.9rem;">
    <thead>
      <tr style="background:var(--surface);border-bottom:2px solid var(--primary);">
        <th style="text-align:left;padding:.5rem;">CVE ID</th>
        <th style="text-align:center;padding:.5rem;">CVSS</th>
        <th style="text-align:center;padding:.5rem;">EPSS</th>
        <th style="text-align:center;padding:.5rem;">CISA KEV</th>
        <th style="text-align:center;padding:.5rem;">OSV Pkgs</th>
        <th style="text-align:center;padding:.5rem;">Priority</th>
      </tr>
    </thead>
    <tbody>
'''
    for entry in enriched:
        cve = entry.get("cve", {})
        epss = entry.get("epss")
        kev = entry.get("kev")
        osv = entry.get("osv")
        priority = entry.get("priority", "D")
        cid = cve.get("cve_id", "Unknown")
        score = cve.get("score", "N/A")
        sev = cve.get("severity", "N/A")
        epss_pct = epss["score_percent"] if epss else "N/A"
        kev_mark = "✅" if kev else "—"
        osv_count = len(osv["affected_packages"]) if osv else 0
        html += f'''      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:.5rem;font-weight:600;">{cid}</td>
        <td style="padding:.5rem;text-align:center;">{score} {_severity_badge(sev)}</td>
        <td style="padding:.5rem;text-align:center;">{epss_pct}%</td>
        <td style="padding:.5rem;text-align:center;">{kev_mark}</td>
        <td style="padding:.5rem;text-align:center;">{osv_count}</td>
        <td style="padding:.5rem;text-align:center;">{_priority_badge(priority)}</td>
      </tr>
'''
    html += '''    </tbody>
  </table>
</div>
'''

    # Detalle individual
    for entry in enriched:
        cve = entry.get("cve", {})
        epss = entry.get("epss")
        kev = entry.get("kev")
        osv = entry.get("osv")
        priority = entry.get("priority", "D")
        cid = cve.get("cve_id", "Unknown")
        desc = cve.get("description", "Sin descripción")
        score = cve.get("score")
        sev = cve.get("severity", "N/A")
        published = cve.get("published", "")[:10]

        rows = f"""
          <div style="display:grid;grid-template-columns:120px 1fr;gap:.5rem;">
            <div style="color:var(--text-muted);font-weight:600;">Publicado:</div>
            <div>{published or 'Desconocido'}</div>
            <div style="color:var(--text-muted);font-weight:600;">Base Score:</div>
            <div>{score if score is not None else 'N/A'} {_severity_badge(sev)}</div>
            <div style="color:var(--text-muted);font-weight:600;">EPSS:</div>
            <div>{epss['score_percent'] if epss else 'N/A'}% (percentil {epss['percentile_percent'] if epss else 'N/A'}%)</div>
          </div>
          <div style="margin-top:.5rem;">{desc[:300]}{'...' if len(desc) > 300 else ''}</div>
        """
        if osv and osv.get("fixed_in"):
            rows += f"<div style='margin-top:.5rem;color:var(--primary);font-weight:600;'>Fixed in: {', '.join(osv['fixed_in'])}</div>"
        if kev:
            rows += f"<div style='margin-top:.25rem;color:var(--error);font-weight:600;'>⚠️ Listado en CISA KEV — {kev.get('required_action', '')}</div>"
        html += _section(f"🔍 {cid}", rows)

    html += '''<p class="small" style="color:var(--text-muted);margin-top:1rem;">
*Modo batch: datos objetivos de CVE.org, NVD, EPSS, CISA KEV y OSV.dev. El análisis detallado del LLM está disponible para búsquedas individuales.*
</p></div>'''
    return html


def wrap_html_document(body_html: str, title: str = "Informe OrinSec") -> str:
    """Envuelve contenido HTML en un documento mínimo."""
    return f"""<div class="orin-report">
  <h1>{title}</h1>
  {body_html}
  <hr>
  <p class="small" style="color:#666;">Generado por OrinSec — IA local asistida</p>
</div>"""
