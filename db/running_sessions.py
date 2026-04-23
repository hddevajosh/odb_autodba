from __future__ import annotations

from typing import Any

from odb_autodba.db.connection import fetch_all
from odb_autodba.models.schemas import BlockingChain, HostProcessRow, SessionProcessCorrelationRow, SessionRow


ACTIVE_SESSIONS_SQL = """
select inst_id, sid, serial# as serial_num, username, status, sql_id, event, wait_class,
       module, program, machine, seconds_in_wait, last_call_et,
       blocking_instance, blocking_session
from gv$session
where type = 'USER'
  and username is not null
  and status = 'ACTIVE'
order by last_call_et desc
fetch first 25 rows only
"""

BLOCKING_SQL = """
with lock_map as (
    select l.inst_id,
           l.sid,
           max(case when l.request = 0 then l.type end) as held_lock_type,
           max(case when l.request = 0 then l.lmode end) as held_lock_mode,
           max(case when l.request > 0 then l.type end) as requested_lock_type,
           max(case when l.request > 0 then l.request end) as requested_lock_mode
    from gv$lock l
    group by l.inst_id, l.sid
),
tx_map as (
    select t.inst_id, t.ses_addr
    from gv$transaction t
),
sql_text_map as (
    select q.inst_id, q.sql_id, max(substr(q.sql_text, 1, 200)) as sql_text_sample
    from gv$sql q
    where q.sql_id is not null
    group by q.inst_id, q.sql_id
)
select b.inst_id as blocked_inst_id,
       b.sid as blocked_sid,
       b.serial# as blocked_serial,
       nvl(b.username, '-') as blocked_user,
       b.status as blocked_status,
       nvl(b.sql_id, '-') as blocked_sql_id,
       bs.sql_text_sample as blocked_sql_text,
       nvl(b.event, '-') as event,
       nvl(b.wait_class, '-') as wait_class,
       nvl(b.seconds_in_wait, 0) as seconds_in_wait,
       b.blocking_session as blocked_blocking_session,
       b.blocking_instance as blocked_blocking_instance,
       b.final_blocking_session as blocked_final_blocking_session,
       b.final_blocking_instance as blocked_final_blocking_instance,
       nvl(b.program, '-') as blocked_program,
       nvl(b.module, '-') as blocked_module,
       nvl(b.machine, '-') as blocked_machine,
       nvl(b.osuser, '-') as blocked_osuser,
       to_char(b.logon_time, 'YYYY-MM-DD HH24:MI:SS') as blocked_logon_time,
       nvl(b.last_call_et, 0) as blocked_last_call_et,
       b.row_wait_obj# as blocked_row_wait_obj,
       b.row_wait_file# as blocked_row_wait_file,
       b.row_wait_block# as blocked_row_wait_block,
       b.row_wait_row# as blocked_row_wait_row,
       bp.spid as blocked_spid,
       s.inst_id as blocker_inst_id,
       s.sid as blocker_sid,
       s.serial# as blocker_serial,
       nvl(s.username, '-') as blocker_user,
       s.status as blocker_status,
       nvl(s.sql_id, '-') as blocker_sql_id,
       ss.sql_text_sample as blocker_sql_text,
       nvl(s.event, '-') as blocker_event,
       nvl(s.wait_class, '-') as blocker_wait_class,
       nvl(s.seconds_in_wait, 0) as blocker_seconds_in_wait,
       s.blocking_session as blocker_blocking_session,
       s.blocking_instance as blocker_blocking_instance,
       s.final_blocking_session as blocker_final_blocking_session,
       s.final_blocking_instance as blocker_final_blocking_instance,
       nvl(s.program, '-') as blocker_program,
       nvl(s.module, '-') as blocker_module,
       nvl(s.machine, '-') as blocker_machine,
       nvl(s.osuser, '-') as blocker_osuser,
       to_char(s.logon_time, 'YYYY-MM-DD HH24:MI:SS') as blocker_logon_time,
       nvl(s.last_call_et, 0) as blocker_last_call_et,
       s.row_wait_obj# as blocker_row_wait_obj,
       s.row_wait_file# as blocker_row_wait_file,
       s.row_wait_block# as blocker_row_wait_block,
       s.row_wait_row# as blocker_row_wait_row,
       sp.spid as blocker_spid,
       case when tx.ses_addr is not null then 1 else 0 end as blocker_has_transaction,
       case
           when tx.ses_addr is not null
             and s.status = 'INACTIVE'
             and nvl(s.last_call_et, 0) >= 60
           then 1
           else 0
       end as blocker_idle_in_transaction,
       lm.held_lock_type,
       lm.held_lock_mode,
       lm.requested_lock_type,
       lm.requested_lock_mode,
       count(*) over (partition by s.inst_id, s.sid, s.serial#) as blocked_session_count,
       max(nvl(b.seconds_in_wait, 0)) over (partition by s.inst_id, s.sid, s.serial#) as max_blocked_wait_seconds,
       o.owner as object_owner,
       o.object_name,
       o.object_type
from gv$session b
join gv$session s
  on s.inst_id = b.blocking_instance
 and s.sid = b.blocking_session
left join gv$process bp
  on bp.inst_id = b.inst_id
 and bp.addr = b.paddr
left join gv$process sp
  on sp.inst_id = s.inst_id
 and sp.addr = s.paddr
left join lock_map lm
  on lm.inst_id = s.inst_id
 and lm.sid = s.sid
left join tx_map tx
  on tx.inst_id = s.inst_id
 and tx.ses_addr = s.saddr
left join sql_text_map bs
  on bs.inst_id = b.inst_id
 and bs.sql_id = b.sql_id
left join sql_text_map ss
  on ss.inst_id = s.inst_id
 and ss.sql_id = s.sql_id
left join dba_objects o
  on o.object_id = b.row_wait_obj#
where b.blocking_session is not null
order by nvl(b.seconds_in_wait, 0) desc
"""

BLOCKING_SQL_FALLBACK = """
select b.inst_id as blocked_inst_id,
       b.sid as blocked_sid,
       b.serial# as blocked_serial,
       nvl(b.username, '-') as blocked_user,
       b.status as blocked_status,
       nvl(b.sql_id, '-') as blocked_sql_id,
       cast(null as varchar2(200)) as blocked_sql_text,
       nvl(b.event, '-') as event,
       nvl(b.wait_class, '-') as wait_class,
       nvl(b.seconds_in_wait, 0) as seconds_in_wait,
       b.blocking_session as blocked_blocking_session,
       b.blocking_instance as blocked_blocking_instance,
       cast(null as number) as blocked_final_blocking_session,
       cast(null as number) as blocked_final_blocking_instance,
       nvl(b.program, '-') as blocked_program,
       nvl(b.module, '-') as blocked_module,
       nvl(b.machine, '-') as blocked_machine,
       nvl(b.osuser, '-') as blocked_osuser,
       to_char(b.logon_time, 'YYYY-MM-DD HH24:MI:SS') as blocked_logon_time,
       nvl(b.last_call_et, 0) as blocked_last_call_et,
       b.row_wait_obj# as blocked_row_wait_obj,
       b.row_wait_file# as blocked_row_wait_file,
       b.row_wait_block# as blocked_row_wait_block,
       b.row_wait_row# as blocked_row_wait_row,
       cast(null as varchar2(20)) as blocked_spid,
       s.inst_id as blocker_inst_id,
       s.sid as blocker_sid,
       s.serial# as blocker_serial,
       nvl(s.username, '-') as blocker_user,
       s.status as blocker_status,
       nvl(s.sql_id, '-') as blocker_sql_id,
       cast(null as varchar2(200)) as blocker_sql_text,
       nvl(s.event, '-') as blocker_event,
       nvl(s.wait_class, '-') as blocker_wait_class,
       nvl(s.seconds_in_wait, 0) as blocker_seconds_in_wait,
       s.blocking_session as blocker_blocking_session,
       s.blocking_instance as blocker_blocking_instance,
       cast(null as number) as blocker_final_blocking_session,
       cast(null as number) as blocker_final_blocking_instance,
       nvl(s.program, '-') as blocker_program,
       nvl(s.module, '-') as blocker_module,
       nvl(s.machine, '-') as blocker_machine,
       nvl(s.osuser, '-') as blocker_osuser,
       to_char(s.logon_time, 'YYYY-MM-DD HH24:MI:SS') as blocker_logon_time,
       nvl(s.last_call_et, 0) as blocker_last_call_et,
       s.row_wait_obj# as blocker_row_wait_obj,
       s.row_wait_file# as blocker_row_wait_file,
       s.row_wait_block# as blocker_row_wait_block,
       s.row_wait_row# as blocker_row_wait_row,
       cast(null as varchar2(20)) as blocker_spid,
       cast(null as number) as blocker_has_transaction,
       cast(null as number) as blocker_idle_in_transaction,
       cast(null as varchar2(4)) as held_lock_type,
       cast(null as number) as held_lock_mode,
       cast(null as varchar2(4)) as requested_lock_type,
       cast(null as number) as requested_lock_mode,
       count(*) over (partition by s.inst_id, s.sid, s.serial#) as blocked_session_count,
       max(nvl(b.seconds_in_wait, 0)) over (partition by s.inst_id, s.sid, s.serial#) as max_blocked_wait_seconds,
       cast(null as varchar2(128)) as object_owner,
       cast(null as varchar2(128)) as object_name,
       cast(null as varchar2(23)) as object_type
from gv$session b
join gv$session s
  on s.inst_id = b.blocking_instance
 and s.sid = b.blocking_session
where b.blocking_session is not null
order by nvl(b.seconds_in_wait, 0) desc
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

SPID_TO_SESSION_SQL_FALLBACK = """
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
       to_char(s.logon_time, 'YYYY-MM-DD HH24:MI:SS') as logon_time
from gv$process p
left join gv$session s
  on s.inst_id = p.inst_id
 and s.paddr = p.addr
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
    left join v$statname sn
      on sn.statistic# = ss.statistic#
    where s.type = 'USER'
      and s.username is not null
      and (sn.name = 'CPU used by this session' or sn.name is null)
    order by nvl(ss.value, 0) desc, nvl(p.pga_used_mem, 0) desc
)
where rownum <= :lim
"""


def get_running_sessions_inventory() -> list[SessionRow]:
    return [SessionRow(**row) for row in fetch_all(ACTIVE_SESSIONS_SQL)]


def get_blocking_chains() -> list[BlockingChain]:
    rows = _fetch_blocking_rows()
    chains: list[BlockingChain] = []
    for row in rows:
        out = dict(row)
        out["blocker_has_transaction"] = _as_bool(out.get("blocker_has_transaction"))
        out["blocker_idle_in_transaction"] = _as_bool(out.get("blocker_idle_in_transaction"))
        out["blocker_classification"] = _classify_blocker_session(out)
        out["evidence_complete"] = _is_evidence_complete(out)
        chains.append(BlockingChain(**out))
    return chains


def map_spid_to_session(spid: str | int | None) -> list[SessionProcessCorrelationRow]:
    if spid is None or str(spid).strip() == "":
        return []
    try:
        rows = fetch_all(SPID_TO_SESSION_SQL, {"spid": str(spid).strip()})
    except Exception:
        try:
            rows = fetch_all(SPID_TO_SESSION_SQL_FALLBACK, {"spid": str(spid).strip()})
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
        try:
            return fetch_all(BLOCKING_SQL_FALLBACK)
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
        row.get("blocker_machine"),
        row.get("blocked_session_count"),
        row.get("max_blocked_wait_seconds"),
    )
    return all(value not in (None, "") for value in required)


def _classify_blocker_session(row: dict[str, Any]) -> str:
    user = str(row.get("blocker_user") or "").upper()
    program = str(row.get("blocker_program") or "").lower()
    module = str(row.get("blocker_module") or "").lower()
    sql_text = str(row.get("blocker_sql_text") or "").lower()
    combined = f"{program} {module} {sql_text}"
    has_tx = bool(row.get("blocker_has_transaction"))
    idle_in_tx = bool(row.get("blocker_idle_in_transaction"))

    if user in {"SYS", "SYSTEM"} or any(token in combined for token in ("pmon", "smon", "dbw", "lgwr", "ckpt", "mmon", "reco")):
        return "sys_or_background"
    if any(token in combined for token in ("dbms_scheduler", "jobq", "cjq")):
        return "dbms_scheduler"
    if any(token in combined for token in ("rman", "dbms_stats", "datapump", "expdp", "impdp", "auto stats")):
        return "maintenance_session"
    if idle_in_tx and has_tx:
        return "idle_in_transaction_blocker"
    if any(token in combined for token in ("batch", "etl", "loader", "job")):
        return "batch_job"
    if user and user not in {"-", "UNKNOWN"}:
        return "application_session"
    return "unknown"


def _as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y"}:
        return True
    if text in {"0", "false", "no", "n"}:
        return False
    return None
