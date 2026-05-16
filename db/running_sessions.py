from __future__ import annotations

from typing import Any

from odb_autodba.db.connection import fetch_all, fetch_one
from odb_autodba.models.schemas import BlockingChain, HostProcessRow, SessionProcessCorrelationRow, SessionRow


ACTIVE_SESSIONS_SQL = """
select s.inst_id,
       s.sid,
       s.serial# as serial_num,
       s.username,
       s.status,
       s.sql_id,
       s.prev_sql_id,
       s.module,
       s.action,
       s.program,
       s.machine,
       s.event,
       s.wait_class,
       s.state,
       s.seconds_in_wait,
       s.last_call_et,
       s.blocking_instance,
       s.blocking_session,
       s.final_blocking_instance,
       s.final_blocking_session,
       case
           when s.status = 'ACTIVE' and nvl(s.wait_class,'?') <> 'Idle'
                then 'TRUE_ACTIVE_NON_IDLE'
           when s.status = 'ACTIVE' and nvl(s.wait_class,'?') = 'Idle'
                then 'ACTIVE_IDLE_WAITING'
           when s.blocking_session is not null or s.final_blocking_session is not null
                then 'BLOCKED'
           else 'OTHER'
       end as activity_class
from gv$session s
where s.type = 'USER'
  and s.username is not null
  and (
       s.status = 'ACTIVE'
       or s.blocking_session is not null
       or s.final_blocking_session is not null
  )
order by
       case
           when s.blocking_session is not null or s.final_blocking_session is not null then 1
           when s.status = 'ACTIVE' and nvl(s.wait_class,'?') <> 'Idle' then 2
           when s.status = 'ACTIVE' and nvl(s.wait_class,'?') = 'Idle' then 3
           else 4
       end,
       s.inst_id,
       s.sid
"""

ACTIVE_SESSION_SUMMARY_SQL = """
select count(*) as active_total,
       sum(case when status='ACTIVE' and nvl(wait_class,'?') <> 'Idle' then 1 else 0 end) as true_active_non_idle,
       sum(case when status='ACTIVE' and nvl(wait_class,'?') = 'Idle' then 1 else 0 end) as active_idle_waiting,
       sum(case when blocking_session is not null or final_blocking_session is not null then 1 else 0 end) as blocked_sessions,
       sum(case when state = 'ON CPU' then 1 else 0 end) as on_cpu_sessions
from gv$session
where type='USER'
  and username is not null
  and (
       status='ACTIVE'
       or blocking_session is not null
       or final_blocking_session is not null
  )
"""

BLOCKING_SQL = """
with blocked as (
    select s.inst_id as blocked_inst_id,
           s.sid as blocked_sid,
           s.serial# as blocked_serial,
           s.username as blocked_user,
           s.sql_id as blocked_sql_id,
           s.module as blocked_module,
           s.program as blocked_program,
           s.event as blocked_event,
           s.wait_class as blocked_wait_class,
           s.seconds_in_wait as blocked_seconds_in_wait,
           s.blocking_instance as blocker_inst_id,
           s.blocking_session as blocker_sid,
           s.final_blocking_instance,
           s.final_blocking_session,
           s.row_wait_obj#,
           s.row_wait_file#,
           s.row_wait_block#,
           s.row_wait_row#
    from gv$session s
    where s.type = 'USER'
      and s.username is not null
      and (s.blocking_session is not null or s.final_blocking_session is not null)
),
blocker as (
    select s.inst_id,
           s.sid,
           s.serial#,
           s.username,
           s.sql_id,
           s.prev_sql_id,
           s.module,
           s.program,
           s.machine,
           s.status,
           s.event,
           s.wait_class,
           s.seconds_in_wait,
           s.taddr,
           case
               when s.type = 'BACKGROUND'
                    or regexp_like(nvl(s.program,'x'), '\\((DBW|CKPT|LGWR|PMON|SMON|MMON|MMNL|ARC|RVWR|CJQ|VKTM|LREG|MMAN|DBRM|GEN|DIAG|VKRM)[0-9]*\\)')
               then 'BACKGROUND_PROCESS'
               when s.username is null
               then 'UNKNOWN_OR_BACKGROUND'
               when s.status = 'INACTIVE' and s.taddr is not null
               then 'IDLE_IN_TRANSACTION_BLOCKER'
               else 'FOREGROUND_SESSION'
           end as blocker_classification
    from gv$session s
),
txn as (
    select inst_id,
           ses_addr,
           start_date,
           used_ublk,
           used_urec
    from gv$transaction
)
select b.blocked_inst_id,
       b.blocked_sid,
       b.blocked_serial,
       b.blocked_user,
       b.blocked_sql_id,
       b.blocked_module,
       b.blocked_program,
       b.blocked_event as event,
       b.blocked_wait_class as wait_class,
       b.blocked_seconds_in_wait as seconds_in_wait,
       nvl(b.blocker_inst_id, b.final_blocking_instance) as blocker_inst_id,
       nvl(b.blocker_sid, b.final_blocking_session) as blocker_sid,
       bl.serial# as blocker_serial,
       bl.username as blocker_user,
       bl.sql_id as blocker_sql_id,
       bl.prev_sql_id as blocker_prev_sql_id,
       bl.module as blocker_module,
       bl.program as blocker_program,
       bl.machine as blocker_machine,
       bl.status as blocker_status,
       bl.event as blocker_event,
       bl.wait_class as blocker_wait_class,
       bl.seconds_in_wait as blocker_seconds_in_wait,
       bl.blocker_classification,
       o.owner as object_owner,
       o.object_name,
       o.object_type,
       to_char(t.start_date, 'YYYY-MM-DD HH24:MI:SS') as blocker_txn_start_date,
       round((sysdate - t.start_date) * 24 * 60, 2) as blocker_txn_age_min,
       t.used_ublk as blocker_undo_blocks,
       t.used_urec as blocker_undo_records,
       count(*) over (partition by nvl(b.blocker_inst_id, b.final_blocking_instance), nvl(b.blocker_sid, b.final_blocking_session)) as blocked_session_count,
       max(nvl(b.blocked_seconds_in_wait, 0)) over (partition by nvl(b.blocker_inst_id, b.final_blocking_instance), nvl(b.blocker_sid, b.final_blocking_session)) as max_blocked_wait_seconds,
       case
           when b.blocked_seconds_in_wait >= 60
                and b.blocked_wait_class in ('Application','Concurrency')
                and bl.blocker_classification in ('FOREGROUND_SESSION','IDLE_IN_TRANSACTION_BLOCKER')
           then 'CRITICAL'
           when b.blocked_seconds_in_wait >= 10
                and b.blocked_wait_class in ('Application','Concurrency','Configuration')
                and nvl(bl.blocker_classification, '?') <> 'BACKGROUND_PROCESS'
           then 'WARNING'
           else 'INFO'
       end as blocking_severity,
       case
           when b.blocked_seconds_in_wait < 10 then 'transient_or_moving_block'
           when bl.blocker_classification = 'BACKGROUND_PROCESS' then 'background_process_not_application_blocker'
           when b.blocked_wait_class = 'Idle' then 'idle_wait_not_blocking_pressure'
           when bl.blocker_classification = 'IDLE_IN_TRANSACTION_BLOCKER' then 'idle_transaction_blocker'
           else 'foreground_blocking_chain'
       end as blocking_reason
from blocked b
left join blocker bl
       on bl.inst_id = nvl(b.blocker_inst_id, b.final_blocking_instance)
      and bl.sid = nvl(b.blocker_sid, b.final_blocking_session)
left join txn t
       on t.inst_id = bl.inst_id
      and t.ses_addr = bl.taddr
left join dba_objects o
       on o.object_id = b.row_wait_obj#
order by
       case
           when b.blocked_seconds_in_wait >= 60 then 1
           when b.blocked_seconds_in_wait >= 10 then 2
           else 3
       end,
       b.blocked_seconds_in_wait desc
"""

SPID_TO_SESSION_SQL = """
with temp_usage as (
    select u.inst_id,
           u.session_addr,
           round(sum(u.blocks * ts.block_size) / 1024 / 1024, 2) as temp_used_mb
    from gv$tempseg_usage u
    join dba_tablespaces ts
      on ts.tablespace_name = u.tablespace
    group by u.inst_id, u.session_addr
)
select p.spid,
       p.spid as os_pid,
       s.inst_id,
       s.sid,
       s.serial# as serial_num,
       s.username,
       s.status,
       s.sql_id,
       s.event,
       s.wait_class,
       s.module,
       s.program,
       s.machine,
       s.osuser,
       round(p.pga_used_mem / 1024 / 1024, 2) as pga_used_mb,
       round(p.pga_alloc_mem / 1024 / 1024, 2) as pga_alloc_mb,
       tu.temp_used_mb,
       to_char(s.logon_time, 'YYYY-MM-DD HH24:MI:SS') as logon_time
from gv$process p
left join gv$session s
  on s.inst_id = p.inst_id
 and s.paddr = p.addr
left join temp_usage tu
  on tu.inst_id = s.inst_id
 and tu.session_addr = s.saddr
where p.spid = :spid
"""

TOP_SESSION_RESOURCE_SQL = """
with temp_usage as (
    select u.inst_id,
           u.session_addr,
           round(sum(u.blocks * ts.block_size) / 1024 / 1024, 2) as temp_used_mb
    from gv$tempseg_usage u
    join dba_tablespaces ts
      on ts.tablespace_name = u.tablespace
    group by u.inst_id, u.session_addr
)
select * from (
    select s.inst_id,
           s.sid,
           s.serial# as serial_num,
           nvl(s.username, '-') as username,
           nvl(s.status, '-') as status,
           nvl(s.sql_id, '-') as sql_id,
           nvl(s.module, '-') as module,
           nvl(s.program, '-') as program,
           nvl(s.machine, '-') as machine,
           nvl(s.osuser, '-') as osuser,
           nvl(s.event, '-') as event,
           nvl(s.wait_class, '-') as wait_class,
           p.spid,
           round(p.pga_used_mem / 1024 / 1024, 2) as pga_used_mb,
           round(p.pga_alloc_mem / 1024 / 1024, 2) as pga_alloc_mb,
           nvl(tu.temp_used_mb, 0) as temp_used_mb,
           round(ss.value / 100, 2) as cpu_seconds
    from gv$session s
    join gv$process p
      on p.inst_id = s.inst_id
     and p.addr = s.paddr
    left join temp_usage tu
      on tu.inst_id = s.inst_id
     and tu.session_addr = s.saddr
    left join gv$sesstat ss
      on ss.inst_id = s.inst_id
     and ss.sid = s.sid
    left join gv$statname sn
      on sn.inst_id = ss.inst_id
     and sn.statistic# = ss.statistic#
    where s.type = 'USER'
      and s.username is not null
      and (sn.name = 'CPU used by this session' or sn.name is null)
    order by nvl(ss.value, 0) desc, nvl(p.pga_used_mem, 0) desc
)
where rownum <= :lim
"""


def get_running_sessions_inventory() -> list[SessionRow]:
    return [SessionRow(**row) for row in fetch_all(ACTIVE_SESSIONS_SQL)]


def get_active_session_summary() -> dict[str, int]:
    row = fetch_one(ACTIVE_SESSION_SUMMARY_SQL) or {}
    return {
        "active_total": _as_int(row.get("active_total")) or 0,
        "true_active_non_idle": _as_int(row.get("true_active_non_idle")) or 0,
        "active_idle_waiting": _as_int(row.get("active_idle_waiting")) or 0,
        "blocked_sessions": _as_int(row.get("blocked_sessions")) or 0,
        "on_cpu_sessions": _as_int(row.get("on_cpu_sessions")) or 0,
    }


def get_blocking_chains() -> list[BlockingChain]:
    rows = _fetch_blocking_rows()
    chains: list[BlockingChain] = []
    for row in rows:
        out = dict(row)
        out["blocker_classification"] = _normalize_blocker_classification(out.get("blocker_classification"))
        out["evidence_complete"] = _is_evidence_complete(out)
        chains.append(BlockingChain(**out))
    return chains


def map_spid_to_session(spid: str | int | None) -> list[SessionProcessCorrelationRow]:
    if spid is None or str(spid).strip() == "":
        return []
    try:
        rows = fetch_all(SPID_TO_SESSION_SQL, {"spid": str(spid).strip()})
    except Exception:
        return []
    correlations: list[SessionProcessCorrelationRow] = []
    for row in rows:
        if row.get("sid") is None:
            continue
        correlations.append(SessionProcessCorrelationRow(**row))
    return correlations


def map_top_processes_to_sessions(process_rows: list[HostProcessRow]) -> tuple[list[HostProcessRow], int, list[str]]:
    if not process_rows:
        return [], 0, []
    mapped_rows: list[HostProcessRow] = []
    mapped_count = 0
    notes: list[str] = []
    for process in process_rows:
        row = process if isinstance(process, HostProcessRow) else HostProcessRow.model_validate(process)
        should_attempt = row.process_group in {"oracle_foreground", "oracle_background", "oracle_fg", "oracle_bg"} or "oracle" in str(row.process_name or "").lower()
        if not should_attempt:
            mapped_rows.append(row.model_copy(update={"session_correlations": []}))
            continue
        spid = row.spid or row.pid
        correlations = map_spid_to_session(spid)
        if correlations:
            mapped_count += 1
        mapped_rows.append(row.model_copy(update={"session_correlations": correlations}))
    if mapped_count == 0 and any(row.process_group in {"oracle_foreground", "oracle_background", "oracle_fg", "oracle_bg"} for row in mapped_rows):
        notes.append("Oracle process-to-session correlation returned no rows for sampled SPIDs.")
    return mapped_rows, mapped_count, notes


def get_top_session_resource_candidates(limit: int = 10) -> list[dict[str, Any]]:
    try:
        return fetch_all(TOP_SESSION_RESOURCE_SQL, {"lim": int(limit)})
    except Exception:
        return []


def _fetch_blocking_rows() -> list[dict[str, Any]]:
    try:
        return fetch_all(BLOCKING_SQL)
    except Exception:
        return []


def _is_evidence_complete(row: dict[str, Any]) -> bool:
    required = (
        row.get("blocker_inst_id"),
        row.get("blocker_sid"),
        row.get("blocker_serial"),
        row.get("blocker_user"),
        row.get("blocker_program"),
        row.get("blocker_module"),
        row.get("blocked_session_count"),
        row.get("max_blocked_wait_seconds"),
        row.get("blocking_severity"),
        row.get("blocking_reason"),
    )
    return all(value not in (None, "") for value in required)


def _normalize_blocker_classification(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text == "FOREGROUND_SESSION":
        return "foreground_session"
    if text == "IDLE_IN_TRANSACTION_BLOCKER":
        return "idle_in_transaction_blocker"
    if text == "BACKGROUND_PROCESS":
        return "background_process"
    if text == "UNKNOWN_OR_BACKGROUND":
        return "unknown_or_background"
    return "unknown"


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(float(value))
    except Exception:
        return None
