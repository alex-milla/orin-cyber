"""Formateo de resultados para HTML y texto plano."""

import re


def markdown_to_html(text: str) -> str:
    """Convierte markdown básico a HTML seguro."""
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
    for line in lines:
        if line.strip().startswith("- ") or line.strip().startswith("* "):
            if not in_list:
                new_lines.append("<ul>")
                in_list = True
            item = line.strip()[2:]
            new_lines.append(f"<li>{item}</li>")
        else:
            if in_list:
                new_lines.append("</ul>")
                in_list = False
            new_lines.append(line)
    if in_list:
        new_lines.append("</ul>")
    text = "\n".join(new_lines)

    def para_repl(match):
        line = match.group(0)
        if line.startswith("<"):
            return line
        return f"<p>{line}</p>"

    text = re.sub(r"^(?!<)(.+)$", para_repl, text, flags=re.MULTILINE)
    text = text.replace("\n\n", "\n")

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


def render_cve_report(enriched: list, llm_text: str) -> str:
    """Genera HTML con estilo SploitScan-like desde datos estructurados."""
    if not enriched:
        return "<p>No hay datos para mostrar.</p>"

    # Tomamos el primer CVE (modo lookup por ID) o todos (modo búsqueda)
    first = enriched[0]
    if not isinstance(first, dict):
        return "<p>Error interno: entrada de datos inválida.</p>"
    cve = first.get("cve") or {}
    epss = first.get("epss")
    kev = first.get("kev")
    github = first.get("github")
    priority = first.get("priority", "D")

    cve_id = cve.get("cve_id", "Unknown")
    desc = cve.get("description_es") or cve.get("description", "Sin descripción")
    score = cve.get("score")
    severity = cve.get("severity", "N/A")
    vector = cve.get("vector", "")
    cvss_ver = cve.get("cvss_version", "")
    published = cve.get("published", "")[:10]  # YYYY-MM-DD
    refs = cve.get("references", [])

    # ── Header ──────────────────────────────────────────────────────────
    html = f'''<div class="cve-report" style="font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:1.5rem;">
    <div style="display:inline-block;border:2px solid var(--primary);padding:.75rem 2rem;border-radius:var(--radius);">
      <span style="font-size:1.4rem;font-weight:700;color:var(--primary);">CVE ID: {cve_id}</span>
    </div>
  </div>
'''

    # ── Información base ────────────────────────────────────────────────
    info_rows = f"""
      <div style="display:grid;grid-template-columns:120px 1fr;gap:.5rem;">
        <div style="color:var(--text-muted);font-weight:600;">Publicado:</div>
        <div>{published or 'Desconocido'}</div>
        <div style="color:var(--text-muted);font-weight:600;">Base Score:</div>
        <div>{score if score is not None else 'N/A'} {_severity_badge(severity)}</div>
        <div style="color:var(--text-muted);font-weight:600;">Vector:</div>
        <div><code style="font-size:.85rem;">{vector or 'N/A'}</code> <span style="color:var(--text-muted);">{cvss_ver}</span></div>
      </div>
      <div style="margin-top:.75rem;padding-top:.75rem;border-top:1px solid var(--border);">
        {desc}
      </div>
    """
    html += _section("🔍 Vulnerability Information", info_rows)

    # ── GitHub Exploits ─────────────────────────────────────────────────
    if github and any(isinstance(r, dict) for r in github):
        gh_rows = "<ul style='margin:0;padding-left:1.2rem;'>"
        for repo in github:
            if not isinstance(repo, dict):
                continue
            url = repo.get('url') or '#'
            name = repo.get('name') or 'Unknown'
            gh_rows += f"<li><a href='{url}' target='_blank' rel='noopener' style='color:var(--primary);text-decoration:underline;'>{name}</a></li>"
        gh_rows += "</ul>"
        html += _section(f"💣 Public Exploits (Total: {len(github)})", gh_rows)

    # ── EPSS ────────────────────────────────────────────────────────────
    if epss:
        epss_rows = f"""
          <div style="display:flex;align-items:center;gap:1rem;">
            <div style="flex:1;background:var(--bg);border-radius:var(--radius-sm);padding:.75rem;">
              <div style="font-size:1.5rem;font-weight:700;color:var(--primary);">{epss['score_percent']}%</div>
              <div style="font-size:.85rem;color:var(--text-muted);">Probabilidad de explotación</div>
            </div>
            <div style="flex:1;background:var(--bg);border-radius:var(--radius-sm);padding:.75rem;">
              <div style="font-size:1.5rem;font-weight:700;color:var(--primary);">{epss['percentile_percent']}%</div>
              <div style="font-size:.85rem;color:var(--text-muted);">Percentil</div>
            </div>
          </div>
        """
        html += _section("♾️ Exploit Prediction Score (EPSS)", epss_rows)
    else:
        html += _section("♾️ Exploit Prediction Score (EPSS)", "<p class='small'>Datos EPSS no disponibles.</p>")

    # ── CISA KEV ────────────────────────────────────────────────────────
    if kev:
        kev_rows = f"""
          <div style="display:grid;grid-template-columns:120px 1fr;gap:.5rem;">
            <div style="color:var(--text-muted);font-weight:600;">Listado:</div>
            <div><span style="color:var(--error);font-weight:700;">✅ SÍ</span> — CISA KEV Catalog</div>
            <div style="color:var(--text-muted);font-weight:600;">Vendor:</div>
            <div>{kev.get('vendor', 'Unknown')}</div>
            <div style="color:var(--text-muted);font-weight:600;">Producto:</div>
            <div>{kev.get('product', 'Unknown')}</div>
            <div style="color:var(--text-muted);font-weight:600;">Añadido:</div>
            <div>{kev.get('date_added', 'Unknown')}</div>
            <div style="color:var(--text-muted);font-weight:600;">Ransomware:</div>
            <div>{kev.get('ransomware', 'Unknown')}</div>
            <div style="color:var(--text-muted);font-weight:600;">Acción requerida:</div>
            <div>{kev.get('required_action', 'Unknown')}</div>
          </div>
        """
        html += _section("🛡️ CISA KEV Catalog", kev_rows)
    else:
        html += _section("🛡️ CISA KEV Catalog", "<p class='small'>No listado en CISA KEV.</p>")

    # ── LLM Analysis ────────────────────────────────────────────────────
    if llm_text:
        llm_html = markdown_to_html(llm_text)
        html += _section("🤖 AI-Powered Risk Assessment", llm_html)

    # ── Patching Priority ───────────────────────────────────────────────
    html += _section("⚠️ Patching Priority Rating", f"<div style='margin:.5rem 0;'>{_priority_badge(priority)}</div>")

    # ── References ──────────────────────────────────────────────────────
    if refs:
        ref_rows = "<ul style='margin:0;padding-left:1.2rem;'>"
        for ref in refs:
            ref_rows += f"<li><a href='{ref}' target='_blank' rel='noopener'>{ref}</a></li>"
        ref_rows += "</ul>"
        html += _section("📚 Further References", ref_rows)

    html += "</div>"
    return html


def wrap_html_document(body_html: str, title: str = "Informe OrinSec") -> str:
    """Envuelve contenido HTML en un documento mínimo."""
    return f"""<div class="orin-report">
  <h1>{title}</h1>
  {body_html}
  <hr>
  <p class="small" style="color:#666;">Generado por OrinSec — IA local asistida</p>
</div>"""
