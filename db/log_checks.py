from __future__ import annotations

from collections import Counter

from odb_autodba.db.logs import get_recent_alert_log_errors
from odb_autodba.models.schemas import ListenerErrorRow, OraErrorRow


def collect_alert_error_summary(limit: int = 20) -> list[OraErrorRow]:
    rows = get_recent_alert_log_errors(limit)
    if not rows:
        return []
    counts = Counter(str(row.get("message_text", "")).strip() for row in rows if row.get("message_text"))
    return [OraErrorRow(message=msg, count=count, matched_pattern=_best_pattern(msg)) for msg, count in counts.most_common(10)]


def collect_listener_error_summary(limit: int = 10) -> list[ListenerErrorRow]:
    errors = [row for row in get_recent_alert_log_errors(limit * 2) if "tns-" in str(row.get("message_text", "")).lower()]
    counts = Counter(str(row.get("message_text", "")).strip() for row in errors if row.get("message_text"))
    return [ListenerErrorRow(message=msg, count=count) for msg, count in counts.most_common(limit)]


def _best_pattern(message: str) -> str | None:
    upper = message.upper()
    for token in upper.split():
        if token.startswith("ORA-"):
            return token.rstrip(":")
    return None
