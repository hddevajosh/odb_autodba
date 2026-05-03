from __future__ import annotations

import re
from typing import Any

from odb_autodba.history.metric_catalog import METRIC_CATALOG


SQL_ID_RE = re.compile(r"\b(?=[0-9a-z]{8,13}\b)(?=.*\d)[0-9a-z]+\b", re.IGNORECASE)
ORA_RE = re.compile(r"\bORA-\d{4,5}\b", re.IGNORECASE)
SQL_ID_EXPLICIT_RE = re.compile(
    r"""
    \bsql[\s_-]*id\b
    \s*(?:=|:)?\s*
    (?P<sql_id>[0-9a-z]{8,13})\b
    """,
    re.IGNORECASE | re.VERBOSE,
)
SQL_ID_COMMAND_PREFIX_RE = re.compile(
    r"""
    ^\s*
    (?:
        (?:please\s+)?
        (?:
            analy[sz]e
            |check
            |investigate
        )\b
        [^.\n]*
        \bsql[\s_-]*id\b
        |
        sql[\s_-]*id\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

AGGREGATION_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("avg", ("average", "avg", "mean")),
    ("min", ("minimum", "min", "lowest", "least")),
    ("max", ("maximum", "max", "highest", "peak")),
    ("count", ("how many times", "count", "number of times")),
    ("any", ("were there any", "any", "did it happen", "did .* happen")),
    ("latest", ("latest", "current from last saved", "from last saved report", "last saved report")),
    ("trend", ("trend", "trending", "changed", "grew", "improved", "worsened", "over time")),
)

TIME_WINDOW_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("today", ("today",)),
    ("yesterday", ("yesterday",)),
    ("last_24_hours", ("last 24 hours", "past 24 hours", "last day")),
    ("this_week", ("this week",)),
    ("last_week", ("last week",)),
    ("all", ("all history", "all health checks", "all health check reports", "all health reports", "overall", "from beginning", "since beginning")),
)

LIVE_NOW_TOKENS: tuple[str, ...] = (
    " now",
    "right now",
    "currently",
    "at the moment",
    "live",
)

HISTORY_CONTEXT_TOKENS: tuple[str, ...] = (
    "history",
    "historical",
    "saved",
    "last week",
    "this week",
    "yesterday",
    "today",
    "last 24",
    "last ",
    "past ",
)


def extract_sql_id(text: str) -> str | None:
    match = SQL_ID_RE.search(text or "")
    return match.group(0).lower() if match else None


def extract_ora_code(text: str) -> str | None:
    match = ORA_RE.search(text or "")
    return match.group(0).upper() if match else None


def detect_sql_id_analysis_intent(prompt: str) -> str | None:
    text = prompt or ""
    if not SQL_ID_COMMAND_PREFIX_RE.search(text):
        return None
    match = SQL_ID_EXPLICIT_RE.search(text)
    if not match:
        return None
    sql_id = (match.group("sql_id") or "").strip().lower()
    return sql_id or None


def detect_history_metric_question_intent(prompt: str) -> bool:
    return detect_history_metric_question(prompt) is not None


def detect_history_metric_question(prompt: str) -> dict[str, Any] | None:
    lowered = " ".join((prompt or "").strip().lower().split())
    if not lowered:
        return None

    if "show historical trends" in lowered or "oracle historical trend analysis" in lowered:
        return None

    metric_family, requested_fields = _detect_metric_family(lowered)
    if metric_family is None:
        return None

    if _looks_like_live_now_query(lowered) and not _contains_explicit_history_scope(lowered):
        return None

    aggregation = _detect_aggregation(lowered)
    has_usage_hint = any(token in lowered for token in ("usage", "consumption", "overall"))
    has_history_scope = _contains_explicit_history_scope(lowered)
    has_question_shape = any(
        token in lowered
        for token in (
            "what is",
            "what has been",
            "were there any",
            "how many",
            "did ",
            "?",
        )
    )
    if aggregation is None and has_usage_hint:
        aggregation = "avg"
    if aggregation is None and not has_history_scope and not has_question_shape:
        return None
    if aggregation is None and metric_family == "active_sessions":
        # Avoid stealing normal live session prompts like "show active sessions".
        return None
    if aggregation is None:
        aggregation = "latest"

    time_window = _detect_time_window(lowered)
    entity_filter = _detect_entity_filter(lowered, metric_family)

    payload: dict[str, Any] = {
        "metric_family": metric_family,
        "requested_fields": requested_fields,
        "aggregation": aggregation,
        "time_window": time_window,
        "entity_filter": entity_filter,
        # Backward compatibility for older call sites/tests.
        "metric": metric_family,
    }
    return payload


def _detect_aggregation(lowered: str) -> str | None:
    if "did it happen" in lowered:
        return "any"
    if "were there any" in lowered:
        return "any"
    if "how many times" in lowered:
        return "count"
    for canonical, variants in AGGREGATION_PATTERNS:
        for token in variants:
            if token == "did .* happen":
                if re.search(r"\bdid\b.+\bhappen\b", lowered):
                    return canonical
            elif token in lowered:
                return canonical
    return None


def _detect_metric_family(lowered: str) -> tuple[str | None, list[str]]:
    best_match: tuple[str | None, list[str], int] = (None, [], -1)
    for spec in METRIC_CATALOG:
        for alias in sorted(spec.aliases, key=len, reverse=True):
            if alias in lowered:
                score = len(alias)
                if score > best_match[2]:
                    best_match = (spec.key, list(spec.fields), score)
                break

    # ORA/TNS shorthand support.
    if best_match[0] is None and ("ora-" in lowered or "ora errors" in lowered or "tns" in lowered):
        for spec in METRIC_CATALOG:
            if spec.key == "alerts":
                return spec.key, list(spec.fields)

    # Generic "usage" hints for CPU/memory.
    if best_match[0] is None and "usage" in lowered:
        if "cpu" in lowered:
            return "cpu", ["host_cpu_pct", "container_cpu_pct", "top_cpu_sql_cpu_s"]
        if any(token in lowered for token in ("memory", "pga", "sga")):
            return "memory", ["host_memory_pct", "container_memory_pct"]

    return best_match[0], best_match[1]


def _detect_time_window(lowered: str) -> dict[str, Any]:
    for label, patterns in TIME_WINDOW_PATTERNS:
        if any(pattern in lowered for pattern in patterns):
            return {"label": label, "raw": lowered}

    hours_match = re.search(r"\blast\s+(\d+)\s+hours?\b", lowered)
    if hours_match:
        hours = max(int(hours_match.group(1)), 1)
        return {"label": "last_n_hours", "hours": hours, "raw": lowered}

    days_match = re.search(r"\blast\s+(\d+)\s+days?\b", lowered)
    if days_match:
        days = max(int(days_match.group(1)), 1)
        return {"label": "last_n_days", "days": days, "raw": lowered}

    return {"label": "all", "raw": lowered}


def _contains_explicit_history_scope(lowered: str) -> bool:
    return any(token in lowered for token in HISTORY_CONTEXT_TOKENS)


def _looks_like_live_now_query(lowered: str) -> bool:
    return any(token in lowered for token in LIVE_NOW_TOKENS)


def _detect_entity_filter(lowered: str, metric_family: str) -> str | None:
    if metric_family == "tablespace":
        match = re.search(r"\btablespace\s+([a-z0-9_$#]+)\b", lowered)
        if match:
            return match.group(1).upper()
    return None


def detect_awr_analysis_intent(prompt: str) -> bool:
    lowered = (prompt or "").strip().lower()
    if not lowered:
        return False
    awr_tokens = (
        "analyze awr",
        "awr report",
        "awr between snapshots",
        "snapshot analysis",
        "analyze awr between snapshots",
    )
    return any(token in lowered for token in awr_tokens)


def detect_blocking_analysis_intent(prompt: str) -> bool:
    lowered = (prompt or "").strip().lower()
    if not lowered:
        return False
    if any(token in lowered for token in ("yesterday", "last week", "history", "historical", "last 24", "last ")):
        return False
    return any(
        token in lowered
        for token in (
            "blocking lock",
            "blocking locks",
            "blocking session",
            "blocking sessions",
            "show blocking",
            "blocker",
            "blocked session",
            "lock contention",
        )
    )


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
    return detect_sql_id_analysis_intent(text) is not None


def looks_like_active_sessions_request(text: str) -> bool:
    lowered = (text or "").lower()
    return any(
        token in lowered
        for token in (
            "show active sessions",
            "active sessions",
            "active session",
            "running sessions",
            "current sessions",
            "show sessions",
        )
    )


def annotate_top_sql(rows: list[Any]) -> list[str]:
    out = []
    for row in rows[:3]:
        sql_id = getattr(row, "sql_id", None) or row.get("sql_id")
        ela = getattr(row, "elapsed_s", None) if hasattr(row, "elapsed_s") else row.get("elapsed_s")
        cpu = getattr(row, "cpu_s", None) if hasattr(row, "cpu_s") else row.get("cpu_s")
        out.append(f"SQL_ID {sql_id} elapsed={ela}s cpu={cpu}s")
    return out
