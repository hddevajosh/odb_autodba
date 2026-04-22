from __future__ import annotations

import re
from typing import Any

from odb_autodba.db.connection import fetch_all, fetch_one
from odb_autodba.models.schemas import ActionableHealthItem, HealthCheckSection

SYSTEM_SCHEMAS = (
    "'SYS'",
    "'SYSTEM'",
    "'XDB'",
    "'DBSNMP'",
    "'OUTLN'",
    "'CTXSYS'",
    "'MDSYS'",
    "'ORDSYS'",
    "'OLAPSYS'",
    "'WMSYS'",
    "'SI_INFORMTN_SCHEMA'",
    "'LBACSYS'",
    "'APPQOSSYS'",
    "'GSMADMIN_INTERNAL'",
    "'OJVMSYS'",
    "'AUDSYS'",
    "'GGSYS'",
    "'GSMCATUSER'",
    "'ORDDATA'",
    "'DBSFWUSER'",
)


def collect_extended_health(window_hours: int = 24) -> tuple[list[HealthCheckSection], list[ActionableHealthItem], dict[str, Any]]:
    hours = max(int(window_hours or 24), 1)
    raw: dict[str, Any] = {}
    sections: list[HealthCheckSection] = []
    actions: list[ActionableHealthItem] = []

    db_status = _db_status()
    raw["db_status"] = db_status
    sections.append(_section("Database Status", _db_status_level(db_status), _db_status_summary(db_status), [db_status] if db_status else []))

    alert_check = _alert_log_check(hours)
    alert_rows = alert_check["rows"]
    raw["alert_log"] = alert_rows
    raw["alert_log_check"] = alert_check
    alert_section = _alert_section(alert_check, hours)
    sections.append(alert_section)
    actions.extend(_alert_actions(alert_rows, hours))

    storage_rows = _tablespace_rows()
    raw["tablespaces"] = storage_rows
    tablespace_section = _tablespace_section(storage_rows)
    anomaly_note = _tablespace_allocation_note(alert_rows=alert_rows, tablespace_rows=storage_rows)
    if anomaly_note:
        tablespace_section.notes.append(anomaly_note)
        alert_section.notes.append(anomaly_note)
        raw["tablespace_allocation_failure_with_low_pct"] = True
    sections.append(tablespace_section)
    actions.extend(_tablespace_actions(storage_rows))

    temp = _temp_summary()
    raw["temp"] = temp
    sections.append(_temp_section(temp))
    actions.extend(_temp_actions(temp))

    locks, lock_err = _lock_pairs()
    raw["lock_pairs"] = locks
    lock_section: HealthCheckSection
    if lock_err and not locks:
        sections.append(
            _section(
                "Locks And Blocking",
                "WARNING",
                "Blocking-session query could not be completed.",
                [],
                notes=[lock_err],
            )
        )
    else:
        lock_notes = [f"Query warning: {lock_err}"] if lock_err else []
        lock_section = _section(
            "Locks And Blocking",
            "CRITICAL" if locks else "OK",
            "No blocking sessions detected." if not locks else f"{len(locks)} blocked session(s) detected.",
            locks[:10],
            notes=lock_notes,
        )
        sections.append(lock_section)
    if locks:
        actions.append(ActionableHealthItem(category="blocking", title="Blocking locks detected", severity="CRITICAL", detail=f"{len(locks)} blocked session(s) found.", recommendation="Review blocker SQL and user before using the guarded remediation flow.", evidence=[_lock_evidence(row) for row in locks[:3]]))

    invalids = _invalid_objects()
    raw["invalid_objects"] = invalids
    sections.append(_section("Objects And Validity", "CRITICAL" if invalids else "OK", "No invalid non-system objects found." if not invalids else f"{len(invalids)} invalid non-system object sample row(s).", invalids[:20]))
    if invalids:
        actions.append(ActionableHealthItem(category="objects", title="Invalid objects present", severity="CRITICAL", detail=f"{len(invalids)} invalid non-system object sample row(s).", recommendation="Compile invalid objects and investigate dependency failures.", evidence=[f"{row.get('owner')}.{row.get('object_name')} {row.get('object_type')}" for row in invalids[:5]]))

    redo = _redo_archive(hours)
    raw["redo_archive"] = redo
    sections.append(_redo_section(redo, hours))
    actions.extend(_redo_actions(redo, hours))

    recovery = _recovery(hours)
    raw["recovery"] = recovery
    sections.append(_recovery_section(recovery, hours))
    actions.extend(_recovery_actions(recovery, hours))

    scheduler = _scheduler_failures(hours)
    raw["scheduler_failures"] = scheduler
    sections.append(_section("Scheduler Jobs", "CRITICAL" if scheduler else "OK", "No scheduler failures found in the health window." if not scheduler else f"{len(scheduler)} scheduler failure sample row(s).", scheduler[:10]))
    if scheduler:
        actions.append(ActionableHealthItem(category="scheduler", title="Scheduler job failures", severity="CRITICAL", detail=f"{len(scheduler)} failed job run sample row(s) in the last {hours}h.", recommendation="Review failed job logs and fix job-specific errors.", evidence=[str(row) for row in scheduler[:3]]))

    performance = _performance(hours)
    raw["performance"] = performance
    performance_sections = _performance_sections(performance)
    sections.extend(performance_sections)
    actions.extend(_performance_actions(performance, hours))
    lock_wait_note = _lock_wait_without_blocker_note(
        wait_rows=(performance.get("current_waits") or []) + (performance.get("awr_waits") or []),
        has_blockers=bool(locks),
    )
    if lock_wait_note:
        raw["blocking_interpretation_note"] = lock_wait_note
        for section in sections:
            if section.name in {"Locks And Blocking", "Current Wait Profile", "AWR Wait Events"}:
                section.notes.append(lock_wait_note)

    transactions = _transactions()
    raw["transactions"] = transactions
    sections.append(_transaction_section(transactions))
    actions.extend(_transaction_actions(transactions))

    memory = _memory_config()
    raw["memory_config"] = memory
    sections.append(_memory_section(memory))
    actions.extend(_memory_actions(memory))

    init_params = _init_params()
    raw["init_params"] = init_params
    sections.append(_section("Init Parameters", "INFO", f"{len(init_params.get('non_default', []))} non-default parameter row(s), {len(init_params.get('key', []))} key parameter row(s).", init_params.get("key", [])[:25], notes=[f"Non-default parameters captured: {len(init_params.get('non_default', []))}"]))

    return sections, actions, raw


def _fetch_all(sql: str, binds: dict[str, Any] | None = None, *, max_rows: int | None = None) -> tuple[list[dict[str, Any]], str | None]:
    try:
        return fetch_all(sql, binds, max_rows=max_rows), None
    except Exception as exc:
        return [], str(exc)


def _fetch_one(sql: str, binds: dict[str, Any] | None = None) -> tuple[dict[str, Any], str | None]:
    try:
        return fetch_one(sql, binds) or {}, None
    except Exception as exc:
        return {}, str(exc)


def _section(name: str, status: str, summary: str, rows: list[dict[str, Any]] | None = None, notes: list[str] | None = None) -> HealthCheckSection:
    return HealthCheckSection(name=name, status=status, summary=summary, rows=rows or [], notes=notes or [])


def _db_status() -> dict[str, Any]:
    row, err = _fetch_one(
        """
        select d.name as db_name, d.open_mode, d.database_role, d.log_mode,
               i.instance_name, i.status as instance_status
        from v$database d cross join v$instance i
        """
    )
    if err:
        return {"error": err}
    return row


def _db_status_level(row: dict[str, Any]) -> str:
    if row.get("error"):
        return "CRITICAL"
    open_mode = str(row.get("open_mode") or "").upper()
    return "OK" if open_mode.startswith("READ") or open_mode == "OPEN" else "CRITICAL"


def _db_status_summary(row: dict[str, Any]) -> str:
    if row.get("error"):
        return f"Database status query failed: {row.get('error')}"
    return f"{row.get('db_name') or 'database'} is {row.get('open_mode') or 'unknown'} as {row.get('database_role') or 'unknown'}; log mode is {row.get('log_mode') or 'unknown'}."


def _alert_log_check(hours: int) -> dict[str, Any]:
    sql = """
        select to_char(originating_timestamp, 'YYYY-MM-DD HH24:MI:SS') as ts,
               regexp_substr(message_text, 'ORA-[0-9]{5}') as code,
               substr(message_text, 1, 800) as message
        from v$diag_alert_ext
        where originating_timestamp > systimestamp - numtodsinterval(:hours, 'HOUR')
          and (message_text like '%ORA-%' or message_text like '%TNS-%')
        order by originating_timestamp desc
        fetch first 50 rows only
    """
    source = "v$diag_alert_ext"
    notes = [
        f"Checked {source} for messages containing ORA- or TNS- in the last {hours} hour(s).",
        "If the primary diagnostic view is unavailable, AutoDBA falls back to x$dbgalertext.",
    ]
    rows, err = _fetch_all(sql, {"hours": hours})
    if err:
        notes.append(f"Primary alert-log query failed: {err}")
        source = "x$dbgalertext"
        rows, err = _fetch_all(
            """
            select to_char(originating_timestamp, 'YYYY-MM-DD HH24:MI:SS') as ts,
                   regexp_substr(message_text, 'ORA-[0-9]{5}') as code,
                   substr(message_text, 1, 800) as message
            from x$dbgalertext
            where originating_timestamp > sysdate - (:hours/24)
              and (message_text like '%ORA-%' or message_text like '%TNS-%')
            order by originating_timestamp desc
            fetch first 50 rows only
            """,
            {"hours": hours},
        )
        if err:
            notes.append(f"Fallback alert-log query failed: {err}")
    for row in rows:
        code = str(row.get("code") or _extract_error_code(str(row.get("message") or "")) or "ORA/TNS")
        row["code"] = code
        row["severity"] = _ora_severity(code)
    return {"rows": rows, "source": source, "window_hours": hours, "error": err, "notes": notes}


def _alert_section(check: dict[str, Any], hours: int) -> HealthCheckSection:
    rows = check.get("rows") or []
    notes = list(check.get("notes") or [])
    source = check.get("source") or "diagnostic alert views"
    error = check.get("error")
    check_row = {
        "source": source,
        "window_hours": hours,
        "filter": "message contains ORA- or TNS-",
        "rows_found": len(rows),
        "status": "checked" if not error else "check_failed",
    }
    if error and not rows:
        return _section("Alert Log Errors", "WARNING", f"Alert-log check could not be completed from {source}.", [check_row], notes=notes)
    if not rows:
        return _section("Alert Log Errors", "OK", f"Checked {source}; no ORA/TNS alert log rows found in the last {hours}h.", [check_row], notes=notes)
    worst = _worst([str(row.get("severity") or "INFO") for row in rows])
    counts: dict[str, int] = {}
    for row in rows:
        code = str(row.get("code") or "ORA/TNS")
        counts[code] = counts.get(code, 0) + 1
    top = ", ".join(f"{code}({count})" for code, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:5])
    return _section("Alert Log Errors", worst, f"Checked {source}; {len(rows)} ORA/TNS row(s) found in the last {hours}h: {top}", rows[:20], notes=notes)


def _alert_actions(rows: list[dict[str, Any]], hours: int) -> list[ActionableHealthItem]:
    if not rows:
        return []
    worst = _worst([str(row.get("severity") or "INFO") for row in rows])
    if worst == "INFO":
        return []
    return [ActionableHealthItem(category="errors", title="Alert log ORA/TNS events", severity=worst, detail=f"{len(rows)} ORA/TNS alert log row(s) detected in the last {hours}h.", recommendation="Correlate alert log errors with workload, sessions, listener, and recent changes.", evidence=[f"{row.get('ts')} {row.get('code')} {row.get('message')}" for row in rows[:3]])]


def _tablespace_rows() -> list[dict[str, Any]]:
    rows, _ = _fetch_all(
        """
        select tablespace_name, round(used_percent, 2) as used_pct,
               tablespace_size*8 as total_mb,
               used_space*8 as used_mb,
               (tablespace_size-used_space)*8 as free_mb
        from dba_tablespace_usage_metrics
        order by used_percent desc
        """
    )
    return rows


def _tablespace_section(rows: list[dict[str, Any]]) -> HealthCheckSection:
    if not rows:
        return _section("Tablespace Usage", "INFO", "Tablespace usage metrics were not available.")
    worst = rows[0]
    pct = _float(worst.get("used_pct"))
    return _section("Tablespace Usage", _pct_status(pct, warn=80, crit=90), f"Highest usage is {pct:.2f}% on {worst.get('tablespace_name')}." if pct is not None else "Tablespace rows captured.", rows[:10])


def _tablespace_actions(rows: list[dict[str, Any]]) -> list[ActionableHealthItem]:
    actions = []
    for row in rows:
        pct = _float(row.get("used_pct")) or 0.0
        if pct < 80:
            continue
        severity = "CRITICAL" if pct >= 90 else "WARNING"
        tablespace = str(row.get("tablespace_name") or "unknown")
        actions.append(ActionableHealthItem(category="storage", title=f"Tablespace {tablespace} high usage", severity=severity, detail=f"{pct:.2f}% used.", recommendation="Review growth, largest segments, autoextend settings, and available storage before extending."))
    return actions


def _temp_summary() -> dict[str, Any]:
    pct_row, pct_err = _fetch_one(
        """
        select tablespace_name,
               round(100 * (1 - free_space / nullif(tablespace_size, 0)), 2) as used_pct
        from dba_temp_free_space
        order by used_pct desc
        fetch first 1 rows only
        """
    )
    consumers, _ = _fetch_all(
        """
        select s.sid, s.serial# as serial_num, nvl(s.username,'-') as username,
               nvl(s.program,'-') as program, nvl(s.module,'N/A') as module,
               nvl(s.sql_id,'N/A') as sql_id,
               round(sum(t.blocks * ts.block_size)/1024/1024/1024, 2) as gb_used
        from v$tempseg_usage t
        join v$session s on t.session_addr = s.saddr
        join dba_tablespaces ts on t.tablespace = ts.tablespace_name
        group by s.sid, s.serial#, s.username, s.program, s.module, s.sql_id
        order by sum(t.blocks * ts.block_size) desc
        fetch first 10 rows only
        """
    )
    return {"usage": pct_row, "usage_error": pct_err, "top_consumers": consumers}


def _temp_section(temp: dict[str, Any]) -> HealthCheckSection:
    usage = temp.get("usage") or {}
    pct = _float(usage.get("used_pct"))
    if pct is None:
        return _section("Temp Usage", "INFO", "TEMP usage percentage was not available.", temp.get("top_consumers", []), notes=[str(temp.get("usage_error"))] if temp.get("usage_error") else [])
    summary = f"TEMP usage is {pct:.2f}% for {usage.get('tablespace_name') or 'TEMP'}."
    consumers = temp.get("top_consumers") or []
    if consumers:
        first = consumers[0]
        summary += f" Top consumer is SID {first.get('sid')} SQL_ID {first.get('sql_id')} using {first.get('gb_used')} GB."
    return _section("Temp Usage", _pct_status(pct, warn=50, crit=80), summary, consumers[:10])


def _temp_actions(temp: dict[str, Any]) -> list[ActionableHealthItem]:
    pct = _float((temp.get("usage") or {}).get("used_pct"))
    if pct is None or pct < 50:
        return []
    severity = "CRITICAL" if pct >= 80 else "WARNING"
    return [ActionableHealthItem(category="temp", title="High TEMP usage", severity=severity, detail=f"TEMP usage is {pct:.2f}%.", recommendation="Identify TEMP consumers and tune/stop runaway sorts or extend TEMP after review.", evidence=[str(row) for row in (temp.get("top_consumers") or [])[:3]])]


def _lock_pairs() -> tuple[list[dict[str, Any]], str | None]:
    rows, err = _fetch_all(
        """
        select w.inst_id as waiter_inst_id, w.sid as waiter_sid, w.serial# as waiter_serial,
               nvl(w.username,'-') as waiter_user, nvl(w.sql_id,'-') as waiter_sql_id,
               nvl(w.event,'-') as waiter_event, w.seconds_in_wait,
               b.inst_id as blocker_inst_id, b.sid as blocker_sid, b.serial# as blocker_serial,
               nvl(b.username,'-') as blocker_user, nvl(b.sql_id,'-') as blocker_sql_id,
               nvl(b.module,'-') as blocker_module, nvl(b.program,'-') as blocker_program
        from gv$session w
        join gv$session b on b.inst_id = w.blocking_instance and b.sid = w.blocking_session
        where w.blocking_session is not null
        order by w.seconds_in_wait desc
        fetch first 20 rows only
        """
    )
    return rows, err


def _invalid_objects() -> list[dict[str, Any]]:
    rows, err = _fetch_all(
        """
        select o.owner, o.object_name, o.object_type
        from dba_objects o
        join dba_users u on u.username = o.owner
        where o.status = 'INVALID'
          and nvl(u.oracle_maintained, 'N') = 'N'
        order by o.owner, o.object_name
        fetch first 20 rows only
        """
    )
    if not err:
        return rows
    rows, _ = _fetch_all(
        f"""
        select owner, object_name, object_type
        from dba_objects
        where status = 'INVALID'
          and owner not in ({','.join(SYSTEM_SCHEMAS)})
        order by owner, object_name
        fetch first 20 rows only
        """
    )
    return rows


def _redo_archive(hours: int) -> dict[str, Any]:
    redo, _ = _fetch_one("select count(*) as redo_switches from v$log_history where first_time >= sysdate - (:hours/24)", {"hours": hours})
    archive_dest, err = _fetch_one(
        """
        select case
                 when destination = 'USE_DB_RECOVERY_FILE_DEST' then
                      (select value from v$parameter where name = 'db_recovery_file_dest')
                   || '/' || (select value from v$parameter where name = 'db_unique_name') || '/ARCHIVELOG'
                 else destination
               end as archive_dest
        from v$archive_dest
        where status = 'VALID'
          and target = 'PRIMARY'
          and rownum = 1
        """
    )
    log_mode, _ = _fetch_one("select log_mode from v$database")
    count = int(redo.get("redo_switches") or 0) if redo else None
    return {"redo_switches": count, "redo_per_hour": (count / hours if count is not None else None), "log_mode": log_mode.get("log_mode"), "archive_dest": archive_dest.get("archive_dest"), "archive_dest_error": err}


def _redo_section(redo: dict[str, Any], hours: int) -> HealthCheckSection:
    rate = _float(redo.get("redo_per_hour"))
    status = "INFO" if rate is None else ("CRITICAL" if rate > 5 else "WARNING" if rate > 1 else "OK")
    summary = f"{redo.get('redo_switches')} redo switch(es) in the last {hours}h ({rate:.2f}/hr)." if rate is not None else "Redo switch rate was not available."
    summary += f" Log mode: {redo.get('log_mode') or 'unknown'}; archive destination: {redo.get('archive_dest') or 'not found'}."
    return _section("Redo And Archiving", status, summary, [redo])


def _redo_actions(redo: dict[str, Any], hours: int) -> list[ActionableHealthItem]:
    actions = []
    rate = _float(redo.get("redo_per_hour"))
    if rate is not None and rate > 1:
        actions.append(ActionableHealthItem(category="redo", title="Elevated redo switch rate", severity="CRITICAL" if rate > 5 else "WARNING", detail=f"Redo switch rate is {rate:.2f}/hr over {hours}h.", recommendation="Review redo log sizing and workload spikes."))
    if not redo.get("archive_dest"):
        actions.append(ActionableHealthItem(category="archive", title="Archive destination not found", severity="CRITICAL", detail="No valid primary archive destination was discovered.", recommendation="Verify archive destination configuration and FRA settings."))
    return actions


def _recovery(hours: int) -> dict[str, Any]:
    fra, _ = _fetch_one("select round((space_used / nullif(space_limit, 0)) * 100, 2) as fra_used_pct from v$recovery_file_dest where space_limit > 0")
    rman, _ = _fetch_all(
        """
        select session_key, input_type, status, to_char(end_time,'YYYY-MM-DD HH24:MI:SS') as completed
        from v$rman_backup_job_details
        where end_time > sysdate - (:hours/24)
          and status not in ('COMPLETED','COMPLETED WITH WARNINGS')
        order by end_time desc
        fetch first 10 rows only
        """,
        {"hours": hours},
    )
    return {"fra_used_pct": fra.get("fra_used_pct"), "rman_failures": rman}


def _recovery_section(recovery: dict[str, Any], hours: int) -> HealthCheckSection:
    fra = _float(recovery.get("fra_used_pct"))
    rman = recovery.get("rman_failures") or []
    status = _worst([_pct_status(fra, warn=80, crit=90), "CRITICAL" if rman else "OK"])
    fra_text = "FRA not configured or unavailable." if fra is None else f"FRA is {fra:.2f}% used."
    rman_text = "No RMAN failures found." if not rman else f"{len(rman)} RMAN failure sample row(s) in the last {hours}h."
    return _section("Backup And Recovery", status, f"{fra_text} {rman_text}", rman[:10], notes=[fra_text])


def _recovery_actions(recovery: dict[str, Any], hours: int) -> list[ActionableHealthItem]:
    actions = []
    fra = _float(recovery.get("fra_used_pct"))
    if fra is not None and fra >= 80:
        actions.append(ActionableHealthItem(category="recovery", title="FRA usage high", severity="CRITICAL" if fra >= 90 else "WARNING", detail=f"FRA is {fra:.2f}% used.", recommendation="Review archive logs, backups, retention policy, and FRA size."))
    rman = recovery.get("rman_failures") or []
    if rman:
        actions.append(ActionableHealthItem(category="backup", title="RMAN backup failures", severity="CRITICAL", detail=f"{len(rman)} RMAN failure sample row(s) in the last {hours}h.", recommendation="Review RMAN job details and backup destination capacity.", evidence=[str(row) for row in rman[:3]]))
    return actions


def _scheduler_failures(hours: int) -> list[dict[str, Any]]:
    rows, _ = _fetch_all(
        """
        select owner, job_name, status, nvl(error#,0) as error,
               to_char(actual_start_date,'YYYY-MM-DD HH24:MI:SS') as started
        from dba_scheduler_job_run_details
        where status = 'FAILED'
          and actual_start_date > systimestamp - numtodsinterval(:hours, 'HOUR')
        order by actual_start_date desc
        fetch first 10 rows only
        """,
        {"hours": hours},
    )
    return rows


def _performance(hours: int) -> dict[str, Any]:
    plan_churn, _ = _fetch_all(
        """
        select sql_id, count(distinct plan_hash_value) as plans
        from v$sql
        where last_active_time > sysdate - (:hours/24)
        group by sql_id
        having count(distinct plan_hash_value) > 1
        order by plans desc
        fetch first 10 rows only
        """,
        {"hours": hours},
    )
    stale, stale_err = _fetch_all(
        """
        select s.owner, s.table_name, to_char(s.last_analyzed,'YYYY-MM-DD HH24:MI:SS') as last_analyzed
        from dba_tab_statistics s
        join dba_users u on u.username = s.owner
        where (s.last_analyzed is null or s.last_analyzed < sysdate - 7)
          and nvl(u.oracle_maintained, 'N') = 'N'
        order by s.last_analyzed nulls first
        fetch first 20 rows only
        """
    )
    if stale_err:
        stale, _ = _fetch_all(
            f"""
            select owner, table_name, to_char(last_analyzed,'YYYY-MM-DD HH24:MI:SS') as last_analyzed
            from dba_tab_statistics
            where (last_analyzed is null or last_analyzed < sysdate - 7)
              and owner not in ({','.join(SYSTEM_SCHEMAS)})
            order by last_analyzed nulls first
            fetch first 20 rows only
            """
        )
    cache = _cache_ratios()
    top_cpu, _ = _fetch_one(
        """
        with ash as (
          select sql_id, count(*) as oncpu_samples
          from v$active_session_history
          where sample_time > sysdate - (:hours/24)
            and session_state = 'ON CPU'
            and sql_id is not null
          group by sql_id
        )
        select sql_id, round(100.0 * oncpu_samples / nullif(sum(oncpu_samples) over (), 0), 2) as cpu_pct
        from ash
        where oncpu_samples > 0
        order by oncpu_samples desc
        fetch first 1 rows only
        """,
        {"hours": hours},
    )
    current_waits, wait_err = _fetch_all(
        """
        select *
        from (
          select event, wait_class,
                 round(time_waited/100, 3) as time_waited_s,
                 total_waits,
                 round(average_wait, 3) as avg_wait_ms
          from v$eventmetric
          where wait_class <> 'Idle'
          order by time_waited desc
        )
        where rownum <= 10
        """
    )
    if wait_err:
        current_waits, _ = _fetch_all(
            """
            select *
            from (
              select event, wait_class,
                     round(time_waited_micro/1e6, 3) as time_waited_s,
                     total_waits,
                     round(average_wait, 3) as avg_wait_ms
              from v$system_event
              where wait_class <> 'Idle'
              order by time_waited_micro desc
            )
            where rownum <= 10
            """
        )
    top_elapsed, _ = _fetch_all(
        """
        select *
        from (
          select sql_id, plan_hash_value, executions,
                 round(elapsed_time/1e6, 3) as elapsed_s,
                 round(cpu_time/1e6, 3) as cpu_s,
                 buffer_gets, disk_reads, rows_processed,
                 round((elapsed_time/1e6)/nullif(executions,0), 3) as ela_per_exec_s
          from v$sqlstats
          where sql_id is not null
          order by elapsed_time desc
        )
        where rownum <= 10
        """
    )
    awr_waits, _ = _fetch_all(
        """
        with inst as (select instance_number from v$instance)
        select e.event_name, round((sum(e.time_waited_micro)/1e6) / nullif(sum(e.total_waits),0) * 1000, 2) as ms_per_occ
        from dba_hist_system_event e
        join dba_hist_snapshot s on s.snap_id = e.snap_id and s.dbid = e.dbid and s.instance_number = e.instance_number
        join inst i on i.instance_number = s.instance_number
        where e.wait_class <> 'Idle'
          and s.begin_interval_time > sysdate - (:hours/24)
        group by e.event_name
        having (sum(e.time_waited_micro)/1e6) / nullif(sum(e.total_waits),0) > 0.5
        order by ms_per_occ desc
        fetch first 10 rows only
        """,
        {"hours": hours},
    )
    return {"plan_churn": plan_churn, "stale_stats": stale, "cache": cache, "top_cpu_sql": top_cpu, "current_waits": current_waits, "top_elapsed_sql": top_elapsed, "awr_waits": awr_waits}


def _performance_sections(perf: dict[str, Any]) -> list[HealthCheckSection]:
    sections = []
    plan_churn = perf.get("plan_churn") or []
    stale = perf.get("stale_stats") or []
    top_cpu = perf.get("top_cpu_sql") or {}
    top_cpu_pct = _float(top_cpu.get("cpu_pct"))
    perf_status = _worst(["WARNING" if plan_churn else "OK", "WARNING" if stale else "OK", "CRITICAL" if top_cpu_pct is not None and top_cpu_pct >= 50 else "WARNING" if top_cpu else "OK"])
    summary_parts = [
        f"{len(plan_churn)} SQL_ID(s) with plan churn.",
        f"{len(stale)} stale-stat table sample row(s).",
        f"Top ASH CPU SQL: {top_cpu.get('sql_id')} at {top_cpu_pct:.2f}%." if top_cpu_pct is not None else "Top ASH CPU SQL unavailable.",
    ]
    sections.append(_section("Performance Overview", perf_status, " ".join(summary_parts), (perf.get("top_elapsed_sql") or [])[:10]))
    sections.append(_section("Current Wait Profile", "INFO" if perf.get("current_waits") else "OK", f"{len(perf.get('current_waits') or [])} current non-idle wait row(s).", perf.get("current_waits") or []))
    sections.append(_section("AWR Wait Events", "INFO" if perf.get("awr_waits") else "OK", f"{len(perf.get('awr_waits') or [])} AWR wait event row(s) above threshold.", perf.get("awr_waits") or []))
    sections.append(_section("Cache Ratios", _cache_status(perf.get("cache") or {}), _cache_summary(perf.get("cache") or {}), [perf.get("cache") or {}]))
    return sections


def _performance_actions(perf: dict[str, Any], hours: int) -> list[ActionableHealthItem]:
    actions = []
    if perf.get("plan_churn"):
        actions.append(ActionableHealthItem(category="plans", title="SQL plan churn detected", severity="WARNING", detail=f"{len(perf.get('plan_churn') or [])} SQL_ID sample row(s) had multiple plans in {hours}h.", recommendation="Review plan baselines, bind sensitivity, stats changes, and execution plans.", evidence=[str(row) for row in (perf.get("plan_churn") or [])[:3]]))
    if perf.get("stale_stats"):
        actions.append(ActionableHealthItem(category="statistics", title="Stale or missing table statistics", severity="WARNING", detail=f"{len(perf.get('stale_stats') or [])} stale-stat table sample row(s).", recommendation="Review optimizer statistics freshness for application schemas.", evidence=[str(row) for row in (perf.get("stale_stats") or [])[:3]]))
    top_cpu = perf.get("top_cpu_sql") or {}
    pct = _float(top_cpu.get("cpu_pct"))
    if pct is not None:
        actions.append(ActionableHealthItem(category="sql", title="ASH top CPU SQL concentration", severity="CRITICAL" if pct >= 50 else "WARNING", detail=f"SQL_ID {top_cpu.get('sql_id')} accounts for {pct:.2f}% of ON CPU ASH samples in {hours}h.", recommendation="Run SQL_ID deep dive and inspect execution plan, waits, and row-source behavior."))
    cache = perf.get("cache") or {}
    cache_status = _cache_status(cache)
    if cache_status in {"WARNING", "CRITICAL"}:
        actions.append(ActionableHealthItem(category="cache", title="Low cache hit ratio", severity=cache_status, detail=_cache_summary(cache), recommendation="Review memory pressure, parsing behavior, SQL reuse, and physical I/O."))
    return actions


def _transactions() -> dict[str, Any]:
    long_tx, _ = _fetch_all(
        """
        select s.sid, s.serial# as serial_num, nvl(s.username,'-') as username,
               round((sysdate - t.start_date)*24*60, 2) as minutes,
               nvl(s.sql_id,'N/A') as sql_id
        from v$transaction t
        join v$session s on s.saddr = t.ses_addr
        where (sysdate - t.start_date) * 24 * 60 > 60
        order by minutes desc
        fetch first 10 rows only
        """
    )
    undo, _ = _fetch_all(
        """
        select tablespace_name, round(used_percent, 2) as used_pct
        from dba_tablespace_usage_metrics
        where upper(tablespace_name) like 'UNDO%'
        order by used_percent desc
        """
    )
    return {"long_transactions": long_tx, "undo": undo}


def _transaction_section(tx: dict[str, Any]) -> HealthCheckSection:
    long_tx = tx.get("long_transactions") or []
    undo = tx.get("undo") or []
    undo_pct = _float(undo[0].get("used_pct")) if undo else None
    status = _worst(["CRITICAL" if long_tx else "OK", _pct_status(undo_pct, warn=80, crit=90)])
    undo_text = "Undo usage unavailable." if undo_pct is None else f"Highest undo usage is {undo_pct:.2f}%."
    return _section("Transactions And Undo", status, f"{len(long_tx)} transaction(s) older than 60 minutes. {undo_text}", long_tx[:10] + undo[:5])


def _transaction_actions(tx: dict[str, Any]) -> list[ActionableHealthItem]:
    actions = []
    long_tx = tx.get("long_transactions") or []
    if long_tx:
        actions.append(ActionableHealthItem(category="transactions", title="Long transactions detected", severity="CRITICAL", detail=f"{len(long_tx)} transaction sample row(s) older than 60 minutes.", recommendation="Review transaction owners before any intervention.", evidence=[str(row) for row in long_tx[:3]]))
    undo = tx.get("undo") or []
    undo_pct = _float(undo[0].get("used_pct")) if undo else None
    if undo_pct is not None and undo_pct >= 80:
        actions.append(ActionableHealthItem(category="undo", title="Undo tablespace pressure", severity="CRITICAL" if undo_pct >= 90 else "WARNING", detail=f"Undo usage is {undo_pct:.2f}%.", recommendation="Review long transactions, undo retention, and undo tablespace capacity."))
    return actions


def _memory_config() -> dict[str, Any]:
    pga, _ = _fetch_one("select round(value/1024/1024, 2) as pga_mb from v$pgastat where name='total PGA inuse'")
    sga, _ = _fetch_one("select round(value/1024/1024, 2) as sga_max_mb from v$parameter where name='sga_max_size'")
    parallel, _ = _fetch_one("select value as parallel_max_servers from v$parameter where name='parallel_max_servers'")
    large_pages, _ = _fetch_one("select value as use_large_pages from v$parameter where name='use_large_pages'")
    top_cpu_sessions, _ = _fetch_all(
        """
        select * from (
          select s.sid, s.serial# as serial_num, nvl(s.username,'-') as username,
                 nvl(s.module,'-') as module, nvl(s.program,'-') as program,
                 nvl(s.sql_id,'-') as sql_id, round(ss.value/100, 2) as cpu_seconds
          from v$session s
          join v$sesstat ss on ss.sid = s.sid
          join v$statname sn on sn.statistic# = ss.statistic#
          where sn.name = 'CPU used by this session'
            and s.type = 'USER'
          order by ss.value desc
        )
        where rownum <= 10
        """
    )
    top_pga_sessions, _ = _fetch_all(
        """
        with temp_usage as (
          select session_addr,
                 round(sum(blocks * ts.block_size) / 1024 / 1024, 2) as temp_used_mb
          from v$tempseg_usage t
          join dba_tablespaces ts on ts.tablespace_name = t.tablespace
          group by session_addr
        )
        select * from (
          select s.sid, s.serial# as serial_num, nvl(s.username,'-') as username,
                 nvl(s.module,'-') as module, nvl(s.program,'-') as program,
                 nvl(s.machine,'-') as machine, nvl(s.osuser,'-') as osuser,
                 nvl(s.sql_id,'-') as sql_id, p.spid,
                 round(p.pga_used_mem/1024/1024, 2) as pga_used_mb,
                 round(p.pga_alloc_mem/1024/1024, 2) as pga_alloc_mb,
                 nvl(tu.temp_used_mb, 0) as temp_used_mb
          from v$session s
          join v$process p on p.addr = s.paddr
          left join temp_usage tu on tu.session_addr = s.saddr
          where s.type = 'USER'
          order by p.pga_used_mem desc
        )
        where rownum <= 10
        """
    )
    pga_mb = _float(pga.get("pga_mb"))
    sga_mb = _float(sga.get("sga_max_mb"))
    ratio = round(100.0 * pga_mb / sga_mb, 2) if pga_mb is not None and sga_mb and sga_mb > 0 else None
    return {"pga_mb": pga_mb, "sga_max_mb": sga_mb, "pga_to_sga_pct": ratio, "parallel_max_servers": parallel.get("parallel_max_servers"), "use_large_pages": large_pages.get("use_large_pages"), "top_cpu_sessions": top_cpu_sessions, "top_pga_sessions": top_pga_sessions}


def _memory_section(memory: dict[str, Any]) -> HealthCheckSection:
    ratio = _float(memory.get("pga_to_sga_pct"))
    status = "INFO" if ratio is None else ("CRITICAL" if ratio > 80 else "WARNING" if ratio >= 50 else "OK")
    summary = f"PGA in use is {memory.get('pga_mb')} MB; SGA max is {memory.get('sga_max_mb')} MB; PGA/SGA is {ratio:.2f}%." if ratio is not None else "PGA/SGA ratio unavailable."
    summary += f" parallel_max_servers={memory.get('parallel_max_servers') or 'unknown'}, use_large_pages={memory.get('use_large_pages') or 'unknown'}."
    top_pga_sessions = memory.get("top_pga_sessions") or []
    top_cpu_sessions = memory.get("top_cpu_sessions") or []
    notes = [f"Top DB CPU sessions captured: {len(top_cpu_sessions)}"]
    if top_pga_sessions:
        top = top_pga_sessions[0]
        summary += (
            f" Session SID {top.get('sid')} (SQL_ID {top.get('sql_id')}) is the largest Oracle PGA consumer in the current snapshot."
        )
        if any(str(cpu_row.get("sql_id") or "") == str(top.get("sql_id") or "") for cpu_row in top_cpu_sessions):
            notes.append(
                f"Largest PGA consumer SQL_ID {top.get('sql_id')} also appears in top DB CPU sessions."
            )
        if (_float(top.get("pga_used_mb")) or 0.0) >= 512:
            notes.append(
                f"High single-session PGA observed: SID {top.get('sid')} uses {top.get('pga_used_mb')} MB."
            )
    return _section("Memory And Configuration", status, summary, top_pga_sessions[:10], notes=notes)


def _memory_actions(memory: dict[str, Any]) -> list[ActionableHealthItem]:
    ratio = _float(memory.get("pga_to_sga_pct"))
    if ratio is None or ratio < 50:
        return []
    return [ActionableHealthItem(category="memory", title="High PGA relative to SGA", severity="CRITICAL" if ratio > 80 else "WARNING", detail=f"PGA/SGA ratio is {ratio:.2f}%.", recommendation="Review top PGA sessions, workarea pressure, parallelism, and memory targets.", evidence=[str(row) for row in (memory.get("top_pga_sessions") or [])[:3]])]


def _init_params() -> dict[str, Any]:
    non_default, _ = _fetch_all(
        """
        select name, value, isdefault
        from v$parameter
        where isdefault = 'FALSE'
        order by name
        """,
        max_rows=100,
    )
    key_names = [
        "processes",
        "sessions",
        "open_cursors",
        "sga_target",
        "sga_max_size",
        "pga_aggregate_target",
        "pga_aggregate_limit",
        "db_cache_size",
        "shared_pool_size",
        "workarea_size_policy",
        "parallel_degree_policy",
        "parallel_max_servers",
        "optimizer_features_enable",
        "optimizer_mode",
        "filesystemio_options",
        "disk_asynch_io",
    ]
    binds = {f"n{i}": name for i, name in enumerate(key_names)}
    inlist = ",".join(f":n{i}" for i in range(len(key_names)))
    key, _ = _fetch_all(f"select name, value from v$parameter where lower(name) in ({inlist}) order by name", binds)
    return {"non_default": non_default, "key": key}


def _cache_ratios() -> dict[str, Any]:
    buffer_hit, _ = _fetch_one(
        """
        select round((1 - (sum(case when name='physical reads' then value else 0 end)
                      / nullif(sum(case when name in ('db block gets','consistent gets') then value else 0 end), 0))) * 100, 2) as buffer_hit_pct
        from v$sysstat
        """
    )
    library_hit, _ = _fetch_one("select round(sum(pins) / nullif(sum(pins) + sum(reloads), 0) * 100, 2) as library_hit_pct from v$librarycache")
    dict_hit, _ = _fetch_one("select round(sum(gets) / nullif(sum(gets) + sum(getmisses), 0) * 100, 2) as dictionary_hit_pct from v$rowcache")
    return {"buffer_hit_pct": buffer_hit.get("buffer_hit_pct"), "library_hit_pct": library_hit.get("library_hit_pct"), "dictionary_hit_pct": dict_hit.get("dictionary_hit_pct")}


def _cache_status(cache: dict[str, Any]) -> str:
    statuses = []
    buffer_hit = _float(cache.get("buffer_hit_pct"))
    library_hit = _float(cache.get("library_hit_pct"))
    dictionary_hit = _float(cache.get("dictionary_hit_pct"))
    if buffer_hit is not None:
        statuses.append("CRITICAL" if buffer_hit < 90 else "WARNING" if buffer_hit < 95 else "OK")
    if library_hit is not None:
        statuses.append("CRITICAL" if library_hit < 85 else "WARNING" if library_hit < 90 else "OK")
    if dictionary_hit is not None:
        statuses.append("CRITICAL" if dictionary_hit < 85 else "WARNING" if dictionary_hit < 90 else "OK")
    return _worst(statuses or ["INFO"])


def _cache_summary(cache: dict[str, Any]) -> str:
    return f"Buffer={_fmt_pct(cache.get('buffer_hit_pct'))}, Library={_fmt_pct(cache.get('library_hit_pct'))}, Dictionary={_fmt_pct(cache.get('dictionary_hit_pct'))}."


def _tablespace_allocation_note(*, alert_rows: list[dict[str, Any]], tablespace_rows: list[dict[str, Any]]) -> str | None:
    has_ora_1653 = any(str(row.get("code") or "").upper() == "ORA-01653" for row in alert_rows)
    if not has_ora_1653:
        return None
    highest_pct = max((_float(row.get("used_pct")) or 0.0 for row in tablespace_rows), default=0.0)
    if highest_pct >= 80.0:
        return "ORA-01653 was observed; review datafile autoextend/maxsize and extent allocation for the affected tablespace."
    return (
        "Overall tablespace usage is low, but allocation failure was reported; review autoextend, maxsize, free extents, and quota."
    )


def _lock_wait_without_blocker_note(*, wait_rows: list[dict[str, Any]], has_blockers: bool) -> str | None:
    if has_blockers:
        return None
    lock_wait = any(
        "row lock contention" in str(row.get("event") or row.get("event_name") or "").lower()
        for row in wait_rows
    )
    if not lock_wait:
        return None
    return (
        "Lock-related waits were observed, but no active blocker was present at collection time; "
        "blocking may have cleared before live capture."
    )


def _ora_severity(code: str) -> str:
    upper = (code or "").upper()
    critical = {"ORA-00600", "ORA-00700", "ORA-07445", "ORA-04030", "ORA-04031", "ORA-03113", "ORA-03135", "ORA-01555"}
    warning = {"ORA-00060", "ORA-01652", "ORA-01653"}
    if upper in critical:
        return "CRITICAL"
    if upper in warning:
        return "WARNING"
    return "INFO"


def _extract_error_code(message: str) -> str | None:
    match = re.search(r"(ORA|TNS)-[0-9]{5}", message or "", flags=re.IGNORECASE)
    return match.group(0).upper() if match else None


def _pct_status(pct: float | None, *, warn: float, crit: float) -> str:
    if pct is None:
        return "INFO"
    if pct >= crit:
        return "CRITICAL"
    if pct >= warn:
        return "WARNING"
    return "OK"


def _worst(statuses: list[str]) -> str:
    rank = {"OK": 0, "INFO": 1, "WARNING": 2, "CRITICAL": 3}
    return max(statuses or ["INFO"], key=lambda status: rank.get(status, 1))


def _float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _fmt_pct(value: Any) -> str:
    pct = _float(value)
    return "unknown" if pct is None else f"{pct:.2f}%"


def _lock_evidence(row: dict[str, Any]) -> str:
    return f"Blocker SID {row.get('blocker_sid')},{row.get('blocker_serial')} user={row.get('blocker_user')} blocking waiter SID {row.get('waiter_sid')} wait={row.get('seconds_in_wait')}s"
