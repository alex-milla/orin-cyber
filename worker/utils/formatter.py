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


def render_cve_html(entry: dict, llm_texts: dict, language: str = "es") -> str:
    """Genera HTML visual determinístico similar al resultado del chat."""
    cve = entry["cve"]
    epss = entry.get("epss")
    kev = entry.get("kev")
    github = entry.get("github")
    osv = entry.get("osv")
    priority = entry.get("priority", "D")

    cve_id = cve.get("cve_id", "Unknown")
    published = cve.get("published", "N/A")
    score = cve.get("score")
    severity = cve.get("severity", "N/A")
    vector = cve.get("vector", "N/A")
    # Preferir descripción del LLM (traducción), luego datos oficiales
    description = llm_texts.get("description", "") or cve.get("description", "No data found")
    refs = cve.get("references", [])

    score_str = str(score) if score is not None else "N/A"
    sev_badge = _severity_badge(severity) if severity != "N/A" else ""

    # ── Header box-drawing ──────────────────────────────────────────────
    html = f'''<div class="cve-report" style="font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;padding:1rem;">
  <div style="text-align:center;margin-bottom:1.5rem;">
    <pre style="display:inline-block;text-align:left;margin:0 auto;font-family:'Consolas','Monaco','Courier New',monospace;font-size:1.1rem;line-height:1.4;background:var(--bg);padding:.5rem 1rem;border-radius:var(--radius);border:1px solid var(--border);">╔══════════════════════════╗
║ CVE ID: {cve_id:<20} ║
╚══════════════════════════╝</pre>
  </div>
'''

    # ── Vulnerability Information ───────────────────────────────────────
    info_rows = f"""
      <div style="display:grid;grid-template-columns:140px 1fr;gap:.4rem;align-items:start;">
        <div style="color:var(--text-muted);font-weight:600;">📅 Published:</div>
        <div>{published}</div>
        <div style="color:var(--text-muted);font-weight:600;">🔺 Base Score:</div>
        <div>{score_str} {sev_badge}</div>
        <div style="color:var(--text-muted);font-weight:600;">⚙️ Vector:</div>
        <div><code style="font-size:.85rem;background:var(--bg);padding:.1rem .4rem;border-radius:4px;">{vector}</code></div>
        <div style="color:var(--text-muted);font-weight:600;">📝 Description:</div>
        <div>{description}</div>
      </div>
    """
    html += _section("Vulnerability information", info_rows, "🔍")

    # ── Public Exploits ─────────────────────────────────────────────────
    if github and isinstance(github, list) and len(github) > 0:
        exploit_content = "<ul style='margin:0;padding-left:1.2rem;'>"
        for repo in github[:5]:
            name = repo.get("name", "Unknown")
            url = repo.get("url", "#")
            exploit_content += f"<li><a href='{url}' target='_blank' rel='noopener' style='color:var(--primary);text-decoration:underline;'>{name}</a></li>"
        exploit_content += "</ul>"
        exploit_total = len(github)
    else:
        exploit_content = "<p class='small'>No exploits found</p>"
        exploit_total = "N/A"
    exploit_rows = f"""
      <div style="display:grid;grid-template-columns:140px 1fr;gap:.4rem;">
        <div style="color:var(--text-muted);font-weight:600;">🔎 Total:</div>
        <div>{exploit_total}</div>
        <div style="color:var(--text-muted);font-weight:600;">📝 Lista:</div>
        <div>{exploit_content}</div>
      </div>
    """
    html += _section("Public Exploits", exploit_rows, "🎯")

    # ── EPSS ────────────────────────────────────────────────────────────
    if epss:
        epss_content = f"📊 EPSS Score: <strong>{epss['score_percent']}%</strong> Probability of exploitation."
    else:
        epss_content = "📊 EPSS Score: N/A"
    html += _section("Exploit Prediction Score (EPSS)", f"<p style='margin:0;'>{epss_content}</p>", "📊")

    # ── CISA KEV ────────────────────────────────────────────────────────
    if kev:
        kev_content = f"""
          <div style="display:grid;grid-template-columns:140px 1fr;gap:.4rem;">
            <div style="color:var(--text-muted);font-weight:600;">🛡️ Sí/No:</div>
            <div><span style="color:var(--error);font-weight:700;">✅ LISTED</span></div>
            <div style="color:var(--text-muted);font-weight:600;">🏢 Vendor:</div>
            <div>{kev.get('vendor', 'N/A')}</div>
            <div style="color:var(--text-muted);font-weight:600;">📦 Product:</div>
            <div>{kev.get('product', 'N/A')}</div>
            <div style="color:var(--text-muted);font-weight:600;">📅 Added:</div>
            <div>{kev.get('date_added', 'N/A')}</div>
            <div style="color:var(--text-muted);font-weight:600;">🔒 Ransomware:</div>
            <div>{kev.get('ransomware', 'N/A')}</div>
          </div>
        """
    else:
        kev_content = "<p style='margin:0;'>🛡️ Sí/No: <span style='color:var(--error);font-weight:700;'>❌ No data found</span></p>"
    html += _section("CISA KEV Catalog", kev_content, "🛡️")

    # ── AI Analysis ─────────────────────────────────────────────────────
    llm_analysis = llm_texts.get("analysis", "")
    if llm_analysis:
        analysis_html = markdown_to_html(llm_analysis)
    else:
        analysis_html = "<p class='small'>[No AI analysis available]</p>"
    html += _section("AI-Powered Risk Assessment", analysis_html, "🤖")

    # ── Priority ────────────────────────────────────────────────────────
    if language == "es":
        urgency_text = {
            "A+": "Requiere parche inmediato.",
            "A": "Requiere parche urgente.",
            "B": "Requiere parche programado.",
            "C": "Requiere parche planificado.",
            "D": "Bajo riesgo, parche opcional.",
        }.get(priority, "Requiere parche.")
    else:
        urgency_text = {
            "A+": "Immediate patching required.",
            "A": "Urgent patching required.",
            "B": "Scheduled patching required.",
            "C": "Planned patching required.",
            "D": "Low risk, optional patch.",
        }.get(priority, "Patching required.")

    priority_content = f"""
      <div style="display:grid;grid-template-columns:140px 1fr;gap:.4rem;align-items:center;">
        <div style="color:var(--text-muted);font-weight:600;">⚠️ Priority:</div>
        <div>{_priority_badge(priority)}</div>
        <div style="color:var(--text-muted);font-weight:600;">🚨 Urgencia:</div>
        <div>{urgency_text}</div>
      </div>
    """
    html += _section("Patching Priority Rating", priority_content, "⚠️")

    # ── References ──────────────────────────────────────────────────────
    if refs:
        ref_content = "<ul style='margin:0;padding-left:1.2rem;'>"
        for url in refs[:10]:
            ref_content += f"<li><a href='{url}' target='_blank' rel='noopener' style='color:var(--primary);text-decoration:underline;'>🔗 {url}</a></li>"
        ref_content += "</ul>"
    else:
        ref_content = "<p class='small'>N/A</p>"
    html += _section("Further References", ref_content, "🔗")

    # ── Notas ───────────────────────────────────────────────────────────
    if language == "es":
        notes = f"""
          <ul style='margin:0;padding-left:1.2rem;'>
            <li><strong>Descripción:</strong> Basada en datos oficiales de CVE.org y NVD.</li>
            <li><strong>EPSS:</strong> Basado en datos de FIRST.org.</li>
            <li><strong>CISA KEV:</strong> Consultado en el catálogo de vulnerabilidades conocidas de CISA.</li>
            <li><strong>Parche Prioridad:</strong> Determinada por CVSS Base Score + EPSS + CISA KEV.</li>
          </ul>
        """
    else:
        notes = f"""
          <ul style='margin:0;padding-left:1.2rem;'>
            <li><strong>Description:</strong> Based on official CVE.org and NVD data.</li>
            <li><strong>EPSS:</strong> Based on FIRST.org data.</li>
            <li><strong>CISA KEV:</strong> Queried from CISA Known Exploited Vulnerabilities catalog.</li>
            <li><strong>Patch Priority:</strong> Determined by CVSS Base Score + EPSS + CISA KEV.</li>
          </ul>
        """
    html += _section("Notas", notes, "📝")

    html += '</div>'
    return html


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
