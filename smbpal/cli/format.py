"""Output rendering: aligned columns for people, JSON for everything else."""

from __future__ import annotations

import json
from typing import Any, Sequence


def render_table(rows: Sequence[dict[str, Any]], columns: Sequence[str]) -> str:
    """Left-aligned, space-separated columns — no borders, so `awk` still works."""
    if not rows:
        return ""
    headers = [column.upper().replace("_", " ") for column in columns]
    cells = [[_cell(row.get(column)) for column in columns] for row in rows]
    widths = [
        max(len(header), *(len(row[i]) for row in cells))
        for i, header in enumerate(headers)
    ]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip()]
    for row in cells:
        lines.append("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
    return "\n".join(lines)


def render_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) or "-"
    text = str(value)
    return text if text else "-"
