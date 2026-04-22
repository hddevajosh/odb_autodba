from __future__ import annotations

import re
from typing import Any


SQL_ID_RE = re.compile(r"\b(?=[0-9a-z]{8,13}\b)(?=.*\d)[0-9a-z]+\b", re.IGNORECASE)
ORA_RE = re.compile(r"\bORA-\d{4,5}\b", re.IGNORECASE)


def extract_sql_id(text: str) -> str | None:
    match = SQL_ID_RE.search(text or "")
    return match.group(0).lower() if match else None


def extract_ora_code(text: str) -> str | None:
    match = ORA_RE.search(text or "")
    return match.group(0).upper() if match else None


def looks_like_history_request(text: str) -> bool:
    lowered = (text or "").lower()
    return any(
        token in lowered
        for token in (
            "history",
            "historical",
            "trend",
            "trends",
            "yesterday",
            "last run",
            "previous run",
            "changed",
            "from beginning",
            "all days",
            "last 7 days",
            "days ago",
            "over time",
        )
    )


def wants_sql_id_analysis(text: str) -> bool:
    lowered = (text or "").lower()
    return "sql_id" in lowered or "sql id" in lowered or (extract_sql_id(lowered) is not None and any(ch.isdigit() for ch in lowered))


def annotate_top_sql(rows: list[Any]) -> list[str]:
    out = []
    for row in rows[:3]:
        sql_id = getattr(row, "sql_id", None) or row.get("sql_id")
        ela = getattr(row, "elapsed_s", None) if hasattr(row, "elapsed_s") else row.get("elapsed_s")
        cpu = getattr(row, "cpu_s", None) if hasattr(row, "cpu_s") else row.get("cpu_s")
        out.append(f"SQL_ID {sql_id} elapsed={ela}s cpu={cpu}s")
    return out
