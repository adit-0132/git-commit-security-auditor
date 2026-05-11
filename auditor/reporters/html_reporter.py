from __future__ import annotations

import html as _html
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Report

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def write_html_report(report: Report, output_path: Path) -> None:
    """Render the HTML report from the Jinja2 template and write to output_path."""
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["markdown"] = _markdown_to_html

    template = env.get_template("report.html.j2")
    html_content = template.render(report=report)
    output_path.write_text(html_content, encoding="utf-8")


def _markdown_to_html(md_text: str) -> str:
    """Convert Markdown text to HTML, with fallback to escaped preformatted text."""
    try:
        import markdown

        return markdown.markdown(md_text, extensions=["fenced_code", "nl2br"])
    except ImportError:
        return f'<pre class="ai-explanation">{_html.escape(md_text)}</pre>'
