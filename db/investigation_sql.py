from __future__ import annotations

import re
from time import perf_counter

from odb_autodba.db.connection import db_connection
from odb_autodba.models.schemas import SQLExecutionResult, SQLValidationResult

FORBIDDEN_KEYWORDS = (
    "INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "ALTER", "DROP", "TRUNCATE",
    "GRANT", "REVOKE", "BEGIN", "DECLARE", "EXEC", "CALL", "COMMIT", "ROLLBACK"
)


def validate_investigation_sql(sql: str) -> SQLValidationResult:
    normalized = " ".join((sql or "").strip().split())
    if not normalized:
        return SQLValidationResult(ok=False, reason="SQL is required.")
    masked = _mask_literals(normalized)
    if ";" in masked.rstrip(";"):
        return SQLValidationResult(ok=False, reason="Only a single statement is allowed.")
    if not re.match(r"^(select|with)\b", normalized, flags=re.IGNORECASE):
        return SQLValidationResult(ok=False, reason="Investigation SQL must start with SELECT or WITH.")
    for keyword in FORBIDDEN_KEYWORDS:
        if re.search(rf"\b{keyword}\b", masked, flags=re.IGNORECASE):
            return SQLValidationResult(ok=False, reason=f"{keyword} is not allowed in investigation SQL.")
    normalized = normalized[:-1].strip() if normalized.endswith(";") else normalized
    return SQLValidationResult(ok=True, normalized_sql=normalized)


def execute_investigation_sql(sql: str, *, row_limit: int = 100) -> SQLExecutionResult:
    started = perf_counter()
    try:
        with db_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql)
            cols = [d[0].lower() for d in (cur.description or [])]
            fetched = cur.fetchmany(max(int(row_limit), 1) + 1)
            truncated = len(fetched) > row_limit
            rows = [
                {cols[i]: _value(row[i]) for i in range(len(cols))}
                for row in fetched[:row_limit]
            ]
            return SQLExecutionResult(
                status="success",
                elapsed_ms=int((perf_counter() - started) * 1000),
                columns=cols,
                rows=rows,
                row_count=len(rows),
                truncated=truncated,
            )
    except Exception as exc:
        return SQLExecutionResult(status="error", elapsed_ms=int((perf_counter() - started) * 1000), error=str(exc))


def _mask_literals(sql: str) -> str:
    return re.sub(r"'([^']|'')*'", "''", sql)


def _value(value):
    if hasattr(value, 'read'):
        try:
            return value.read()
        except Exception:
            return str(value)
    return value
