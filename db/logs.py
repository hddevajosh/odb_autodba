from __future__ import annotations

from odb_autodba.db.connection import fetch_all


def get_recent_alert_log_errors(limit: int = 20) -> list[dict]:
    queries = [
        """
        select originating_timestamp as log_time, message_text
        from x$dbgalertext
        where regexp_like(message_text, 'ORA-|TNS-', 'i')
        order by originating_timestamp desc fetch first :lim rows only
        """,
        """
        select originating_timestamp as log_time, message_text
        from v$diag_alert_ext
        where regexp_like(message_text, 'ORA-|TNS-', 'i')
        order by originating_timestamp desc fetch first :lim rows only
        """,
    ]
    for sql in queries:
        try:
            return fetch_all(sql, {"lim": int(limit)})
        except Exception:
            continue
    return []
