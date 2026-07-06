"""Report rendering helpers."""

from __future__ import annotations

import csv
import io
from typing import Any

from .serialization import canonical_json, to_plain


def render_json(value: Any) -> str:
    """Render deterministic pretty JSON."""

    return canonical_json(value)


def render_markdown(title: str, value: Any) -> str:
    """Render a small deterministic Markdown report."""

    return f"# {title}\n\n```json\n{canonical_json(value)}\n```\n"


def render_csv(rows: list[dict[str, Any]]) -> str:
    """Render CSV while escaping spreadsheet formulas."""

    if not rows:
        return ""
    output = io.StringIO()
    fieldnames = sorted(rows[0])
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        safe = {}
        for key, value in row.items():
            text = str(to_plain(value))
            safe[key] = "'" + text if text.startswith(("=", "+", "-", "@")) else text
        writer.writerow(safe)
    return output.getvalue()
