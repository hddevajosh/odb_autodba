from __future__ import annotations

from typing import Any

from odb_autodba.db.connection import fetch_one


TABLESPACE_INFO_SQL = """
select bigfile
from dba_tablespaces
where tablespace_name = :ts
"""

TABLESPACE_BIGFILE_DATAFILE_SQL = """
select file_id
from dba_data_files
where tablespace_name = :ts
order by file_id
fetch first 1 rows only
"""


def build_clear_blocking_lock_sql(*, sid: int | None, serial_num: int | None, inst_id: int | None = None) -> str:
    if sid is None or serial_num is None:
        raise ValueError("sid and serial_num are required for clear_blocking_lock action.")
    if inst_id is not None:
        return f"ALTER SYSTEM KILL SESSION '{int(sid)},{int(serial_num)},@{int(inst_id)}' IMMEDIATE"
    return f"ALTER SYSTEM KILL SESSION '{int(sid)},{int(serial_num)}' IMMEDIATE"


def build_extend_tablespace_sql(
    *,
    tablespace_name: str,
    initial_gb: int = 1,
    next_mb: int = 256,
    max_gb: int = 32,
    bigfile_hint: bool | None = None,
) -> tuple[str, list[str]]:
    notes: list[str] = []
    ts = str(tablespace_name or "").strip().upper()
    if not ts:
        raise ValueError("tablespace_name is required for extend_tablespace action.")

    is_bigfile: bool | None = bigfile_hint
    file_id: int | None = None
    try:
        row = fetch_one(TABLESPACE_INFO_SQL, {"ts": ts}) or {}
        if row:
            is_bigfile = str(row.get("bigfile") or "").upper() == "YES"
    except Exception as exc:
        notes.append(f"Unable to query dba_tablespaces for {ts}: {exc}")

    if is_bigfile:
        try:
            row = fetch_one(TABLESPACE_BIGFILE_DATAFILE_SQL, {"ts": ts}) or {}
            file_id = _as_int(row.get("file_id"))
        except Exception as exc:
            notes.append(f"Unable to query dba_data_files for BIGFILE tablespace {ts}: {exc}")
        if file_id is not None:
            sql = f"ALTER DATABASE DATAFILE {file_id} AUTOEXTEND ON NEXT {int(next_mb)}M MAXSIZE {int(max_gb)}G"
            return sql, notes
        notes.append("Falling back to ALTER TABLESPACE ADD DATAFILE because BIGFILE file_id is unavailable.")

    sql = f"ALTER TABLESPACE {ts} ADD DATAFILE SIZE {int(initial_gb)}G AUTOEXTEND ON NEXT {int(next_mb)}M MAXSIZE {int(max_gb)}G"
    return sql, notes


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None
