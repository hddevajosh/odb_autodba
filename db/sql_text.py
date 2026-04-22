from __future__ import annotations

from odb_autodba.db.connection import fetch_one


def get_sql_text(sql_id: str) -> str | None:
    row = fetch_one(
        """
        select dbms_lob.substr(sql_fulltext, 4000, 1) as sql_text
        from v$sql
        where sql_id = :sql_id
        order by last_active_time desc
        fetch first 1 rows only
        """,
        {"sql_id": sql_id},
    )
    if row and row.get("sql_text"):
        return str(row["sql_text"])
    row = fetch_one(
        """
        select substr(sql_text, 1, 1000) as sql_text
        from v$sqlarea
        where sql_id = :sql_id
        fetch first 1 rows only
        """,
        {"sql_id": sql_id},
    )
    if row and row.get("sql_text"):
        return str(row["sql_text"])
    row = fetch_one(
        """
        select dbms_lob.substr(sql_text, 4000, 1) as sql_text
        from dba_hist_sqltext
        where sql_id = :sql_id
        fetch first 1 rows only
        """,
        {"sql_id": sql_id},
    )
    return str(row["sql_text"]) if row and row.get("sql_text") else None
