"""Formateo de resultados para HTML y texto plano."""

import re


def markdown_to_html(text: str) -> str:
    """Convierte markdown básico a HTML seguro."""
    # Escapar HTML primero
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Headers
    text = re.sub(r"^### (.+)$", r"<h3>\1</h3>", text, flags=re.MULTILINE)
    text = re.sub(r"^## (.+)$", r"<h2>\1</h2>", text, flags=re.MULTILINE)
    text = re.sub(r"^# (.+)$", r"<h1>\1</h1>", text, flags=re.MULTILINE)

    # Bold / italic
    text = re.sub(r"\*\*\*(.+?)\*\*\*", r"<strong><em>\1</em></strong>", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)

    # Listas
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

    # Párrafos (líneas no vacías que no empiecen con <)
    def para_repl(match):
        line = match.group(0)
        if line.startswith("<"):
            return line
        return f"<p>{line}</p>"

    text = re.sub(r"^(?!<)(.+)$", para_repl, text, flags=re.MULTILINE)

    # Saltos de línea restantes
    text = text.replace("\n\n", "\n")

    # Enlaces [texto](url)
    text = re.sub(
        r'\[([^\]]+)\]\(([^)]+)\)',
        r'<a href="\2" target="_blank" rel="noopener">\1</a>',
        text,
    )

    return text


def wrap_html_document(body_html: str, title: str = "Informe OrinSec") -> str:
    """Envuelve contenido HTML en un documento mínimo."""
    return f"""<div class="orin-report">
  <h1>{title}</h1>
  {body_html}
  <hr>
  <p class="small" style="color:#666;">Generado por OrinSec — IA local asistida</p>
</div>"""
