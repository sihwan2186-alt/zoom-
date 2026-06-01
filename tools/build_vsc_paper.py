from __future__ import annotations

from html import escape
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PAPER_DIR = ROOT / "paper"
SOURCE = PAPER_DIR / "paper_draft.md"
MARKDOWN_OUTPUT = PAPER_DIR / "paper_preview.md"
HTML_OUTPUT = PAPER_DIR / "paper_preview.html"


STYLE = """
body {
  color: #1f2933;
  font-family: "Malgun Gothic", "Apple SD Gothic Neo", Arial, sans-serif;
  line-height: 1.65;
  margin: 40px auto;
  max-width: 980px;
  padding: 0 24px;
}
h1 {
  font-size: 1.45rem;
  line-height: 1.35;
  margin: 0.9rem 0;
  text-align: center;
}
h2 {
  border-bottom: 1px solid #d9e2ec;
  font-size: 1.2rem;
  margin-top: 2rem;
  padding-bottom: 0.35rem;
}
h3 {
  font-size: 1rem;
  margin-top: 1.4rem;
}
p {
  margin: 0.65rem 0;
}
.caption {
  font-size: 0.92rem;
  font-weight: 700;
  margin: 0.9rem 0 0.25rem;
  text-align: center;
}
table {
  border-collapse: collapse;
  font-size: 0.92rem;
  margin: 0.8rem 0 1.2rem;
  width: 100%;
}
th, td {
  border: 1px solid #bcccdc;
  padding: 0.45rem 0.55rem;
  vertical-align: top;
}
th {
  background: #eef5fb;
  font-weight: 700;
  text-align: center;
}
img {
  border: 1px solid #d9e2ec;
  display: block;
  margin: 0.8rem auto 1.2rem;
  max-width: 760px;
  width: 100%;
}
code {
  background: #f0f4f8;
  border-radius: 4px;
  padding: 0.05rem 0.25rem;
}
""".strip()


def inline_markup(text: str) -> str:
    escaped = escape(text)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)


def is_table_separator(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("|") and set(
        stripped.replace("|", "").replace(":", "").replace("-", "").strip()
    ) == set()


def split_table_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def render_image(line: str) -> str | None:
    match = re.fullmatch(r"!\[([^\]]*)\]\(([^)]+)\)", line.strip())
    if not match:
        return None
    alt_text, source = match.groups()
    return f'<img src="{escape(source)}" alt="{escape(alt_text)}">'


def render_table(lines: list[str], start: int) -> tuple[str, int]:
    headers = split_table_row(lines[start])
    rows: list[list[str]] = []
    index = start + 2
    while index < len(lines) and lines[index].strip().startswith("|"):
        rows.append(split_table_row(lines[index]))
        index += 1

    output = ["<table>", "<thead><tr>"]
    for header in headers:
        output.append(f"<th>{inline_markup(header)}</th>")
    output.append("</tr></thead>")
    output.append("<tbody>")
    for row in rows:
        output.append("<tr>")
        for cell in row:
            output.append(f"<td>{inline_markup(cell)}</td>")
        output.append("</tr>")
    output.append("</tbody></table>")
    return "\n".join(output), index


def markdown_to_html(markdown: str) -> str:
    lines = markdown.splitlines()
    html: list[str] = []
    index = 0

    while index < len(lines):
        line = lines[index].rstrip()
        stripped = line.strip()
        if not stripped:
            index += 1
            continue

        if stripped.startswith("|") and index + 1 < len(lines) and is_table_separator(lines[index + 1]):
            table_html, index = render_table(lines, index)
            html.append(table_html)
            continue
        image_html = render_image(stripped)
        if image_html is not None:
            html.append(image_html)
            index += 1
            continue
        if stripped.startswith("[그림 ") or stripped.startswith("[Figure "):
            html.append(f'<p class="caption">{inline_markup(stripped)}</p>')
            index += 1
            continue
        if stripped.startswith("# "):
            html.append(f"<h1>{inline_markup(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            html.append(f"<h2>{inline_markup(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            html.append(f"<h3>{inline_markup(stripped[4:])}</h3>")
        elif stripped.startswith("- "):
            items = []
            while index < len(lines) and lines[index].strip().startswith("- "):
                items.append(f"<li>{inline_markup(lines[index].strip()[2:])}</li>")
                index += 1
            html.append("<ul>\n" + "\n".join(items) + "\n</ul>")
            continue
        else:
            html.append(f"<p>{inline_markup(stripped)}</p>")
        index += 1

    return "\n".join(html)


def build() -> None:
    markdown = SOURCE.read_text(encoding="utf-8")
    MARKDOWN_OUTPUT.write_text(markdown, encoding="utf-8")
    body = markdown_to_html(markdown)
    html = (
        "<!doctype html>\n"
        "<html lang=\"ko\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "  <title>STRIDE-ZAP 논문 미리보기</title>\n"
        f"  <style>{STYLE}</style>\n"
        "</head>\n"
        "<body>\n"
        f"{body}\n"
        "</body>\n"
        "</html>\n"
    )
    HTML_OUTPUT.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    build()
