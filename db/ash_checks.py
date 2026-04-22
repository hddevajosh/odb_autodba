from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from odb_autodba.db.connection import fetch_all


def is_ash_available() -> bool:
    try:
        fetch_all("select 1 as x from v$active_session_history where rownum = 1")
        return True
    except Exception:
        return False


def get_recent_ash_hotspots(hours: int = 4) -> list[dict]:
    return fetch_all(
        """
        select * from (
            select nvl(event, 'ON CPU') as event, sql_id, count(*) as samples
            from v$active_session_history
            where sample_time > sysdate - (:hours/24)
            group by nvl(event, 'ON CPU'), sql_id
            order by samples desc
        ) where rownum <= 10
        """,
        {"hours": int(hours)},
    )


def get_ash_window_state(
    *,
    begin_time: datetime | str | None,
    end_time: datetime | str | None,
    begin_snap_id: int | None = None,
    end_snap_id: int | None = None,
    dbid: int | None = None,
    prefer_awr: bool = True,
) -> dict[str, Any]:
    begin_dt = _coerce_dt(begin_time)
    end_dt = _coerce_dt(end_time)
    window_seconds = _window_seconds(begin_dt, end_dt)

    if prefer_awr and begin_snap_id is not None and end_snap_id is not None and end_snap_id >= begin_snap_id:
        try:
            return _ash_state_from_dba_hist(begin_snap_id=begin_snap_id, end_snap_id=end_snap_id, dbid=dbid, window_seconds=window_seconds)
        except Exception:
            pass

    if begin_dt is None or end_dt is None:
        return {
            "source": None,
            "available": False,
            "notes": ["ASH window mapping was incomplete; no ASH state collected."],
            "aas_proxy": None,
            "top_sql": [],
            "wait_profile": [],
            "blocking": [],
        }

    try:
        return _ash_state_from_v_ash(begin_dt=begin_dt, end_dt=end_dt, window_seconds=window_seconds)
    except Exception as exc:
        return {
            "source": None,
            "available": False,
            "notes": [f"ASH collection failed: {exc}"],
            "aas_proxy": None,
            "top_sql": [],
            "wait_profile": [],
            "blocking": [],
        }


def _ash_state_from_dba_hist(*, begin_snap_id: int, end_snap_id: int, dbid: int | None, window_seconds: float | None) -> dict[str, Any]:
    binds = {"begin_snap_id": int(begin_snap_id), "end_snap_id": int(end_snap_id), "dbid": dbid}
    sample_count_row = fetch_all(
        """
        select count(*) as sample_count
        from dba_hist_active_sess_history
        where snap_id > :begin_snap_id
          and snap_id <= :end_snap_id
          and (:dbid is null or dbid = :dbid)
        """,
        binds,
    )
    sample_count = int((sample_count_row[0] or {}).get("sample_count") or 0)

    top_sql = fetch_all(
        """
        select * from (
            select nvl(sql_id, '(none)') as sql_id, count(*) as samples
            from dba_hist_active_sess_history
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
              and (:dbid is null or dbid = :dbid)
            group by nvl(sql_id, '(none)')
            order by samples desc
        ) where rownum <= 5
        """,
        binds,
    )

    wait_profile = fetch_all(
        """
        select * from (
            select nvl(event, 'ON CPU') as event,
                   nvl(wait_class, 'CPU') as wait_class,
                   count(*) as samples
            from dba_hist_active_sess_history
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
              and (:dbid is null or dbid = :dbid)
            group by nvl(event, 'ON CPU'), nvl(wait_class, 'CPU')
            order by samples desc
        ) where rownum <= 8
        """,
        binds,
    )

    blocking = fetch_all(
        """
        select * from (
            select blocking_inst_id,
                   blocking_session,
                   count(*) as samples
            from dba_hist_active_sess_history
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
              and (:dbid is null or dbid = :dbid)
              and blocking_session is not null
            group by blocking_inst_id, blocking_session
            order by samples desc
        ) where rownum <= 5
        """,
        binds,
    )

    return {
        "source": "dba_hist_active_sess_history",
        "available": True,
        "notes": [],
        "aas_proxy": _aas_proxy(sample_count, window_seconds),
        "top_sql": top_sql,
        "wait_profile": wait_profile,
        "blocking": blocking,
    }


def _ash_state_from_v_ash(*, begin_dt: datetime, end_dt: datetime, window_seconds: float | None) -> dict[str, Any]:
    binds = {"begin_time": begin_dt, "end_time": end_dt}
    sample_count_row = fetch_all(
        """
        select count(*) as sample_count
        from v$active_session_history
        where sample_time >= :begin_time
          and sample_time < :end_time
        """,
        binds,
    )
    sample_count = int((sample_count_row[0] or {}).get("sample_count") or 0)

    top_sql = fetch_all(
        """
        select * from (
            select nvl(sql_id, '(none)') as sql_id, count(*) as samples
            from v$active_session_history
            where sample_time >= :begin_time
              and sample_time < :end_time
            group by nvl(sql_id, '(none)')
            order by samples desc
        ) where rownum <= 5
        """,
        binds,
    )

    wait_profile = fetch_all(
        """
        select * from (
            select nvl(event, 'ON CPU') as event,
                   nvl(wait_class, 'CPU') as wait_class,
                   count(*) as samples
            from v$active_session_history
            where sample_time >= :begin_time
              and sample_time < :end_time
            group by nvl(event, 'ON CPU'), nvl(wait_class, 'CPU')
            order by samples desc
        ) where rownum <= 8
        """,
        binds,
    )

    blocking = fetch_all(
        """
        select * from (
            select blocking_inst_id,
                   blocking_session,
                   count(*) as samples
            from v$active_session_history
            where sample_time >= :begin_time
              and sample_time < :end_time
              and blocking_session is not null
            group by blocking_inst_id, blocking_session
            order by samples desc
        ) where rownum <= 5
        """,
        binds,
    )

    return {
        "source": "v$active_session_history",
        "available": True,
        "notes": [],
        "aas_proxy": _aas_proxy(sample_count, window_seconds),
        "top_sql": top_sql,
        "wait_profile": wait_profile,
        "blocking": blocking,
    }


def _aas_proxy(sample_count: int, window_seconds: float | None) -> float | None:
    if sample_count <= 0 or not window_seconds:
        return None
    return round(float(sample_count) / float(window_seconds), 4)


def _coerce_dt(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except Exception:
        return None


def _window_seconds(begin_dt: datetime | None, end_dt: datetime | None) -> float | None:
    if begin_dt is None or end_dt is None:
        return None
    seconds = (end_dt - begin_dt).total_seconds()
    if seconds <= 0:
        return None
    return seconds
