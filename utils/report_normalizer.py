from __future__ import annotations

from typing import Iterable


def dedupe_lines(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        line = (line or "").strip()
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out
