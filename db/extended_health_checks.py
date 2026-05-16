from __future__ import annotations

import json
import os
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
    role_mode = _database_role_mode(db_status)
    raw["database_role_mode"] = role_mode
    raw["standby_health_mode"] = bool(role_mode.get("standby_health_mode"))
    raw["primary_style_checks_skipped_for_mounted_standby"] = bool(role_mode.get("primary_style_checks_skipped"))
    sections.append(_database_role_mode_section(role_mode))
    if role_mode.get("standby_health_mode"):
        sections.append(_standby_role_open_mode_section(db_status=db_status, role_mode=role_mode))

    alert_check = _alert_log_check(hours)
    alert_rows = alert_check["rows"]
    raw["alert_log"] = alert_rows
    raw["alert_log_check"] = alert_check
    alert_section = _alert_section(alert_check, hours)
    sections.append(alert_section)
    actions.extend(_alert_actions(alert_rows, hours))

    storage_rows, storage_note = _tablespace_rows()
    raw["tablespaces"] = storage_rows
    raw["tablespace_headline_source"] = (
        "DBA_TABLESPACE_USAGE_METRICS" if not storage_note else "Fallback calculation used; DBA_TABLESPACE_USAGE_METRICS unavailable."
    )
    raw["tablespace_headline_note"] = storage_note
    tablespace_section = _tablespace_section(storage_rows)
    if storage_note:
        tablespace_section.notes.append(storage_note)
    anomaly_note = _tablespace_allocation_note(alert_rows=alert_rows, tablespace_rows=storage_rows)
    if anomaly_note:
        tablespace_section.notes.append(anomaly_note)
        alert_section.notes.append(anomaly_note)
        raw["tablespace_allocation_failure_with_low_pct"] = True
    sections.append(tablespace_section)
    actions.extend(_tablespace_actions(storage_rows))
    allocation_rows = _tablespace_allocation_details()
    raw["tablespace_allocation_details"] = allocation_rows
    sections.append(_tablespace_allocation_section(allocation_rows))

    temp = _temp_summary()
    raw["temp"] = temp
    raw["temp_pct"] = _float((temp.get("capacity") or {}).get("temp_used_pct"))
    sections.extend(_temp_sections(temp))
    actions.extend(_temp_actions(temp))

    locks: list[dict[str, Any]] = []
    lock_err: str | None = None
    if role_mode.get("primary_style_checks_skipped"):
        sections.append(
            _section(
                "Locks And Blocking",
                "INFO",
                "Skipped in mounted standby mode.",
                [],
                notes=["Primary-style blocking RCA is skipped in mounted standby mode unless recovery operations are impacted."],
            )
        )
    else:
        locks, lock_err = _lock_pairs()
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
            lock_status = _worst([str(row.get("blocking_severity") or "INFO") for row in locks]) if locks else "OK"
            lock_section = _section(
                "Locks And Blocking",
                lock_status,
                "No blocking sessions detected." if not locks else f"{len(locks)} blocked session(s) detected.",
                locks[:10],
                notes=lock_notes,
            )
            sections.append(lock_section)
    raw["lock_pairs"] = locks
    if locks and not role_mode.get("primary_style_checks_skipped"):
        action_severity = _worst([str(row.get("blocking_severity") or "INFO") for row in locks])
        if action_severity in {"CRITICAL", "WARNING"}:
            actions.append(ActionableHealthItem(category="blocking", title="Blocking locks detected", severity=action_severity, detail=f"{len(locks)} blocked session(s) found.", recommendation="Review blocker SQL and user before using the guarded remediation flow.", evidence=[_lock_evidence(row) for row in locks[:3]]))

    invalids = _invalid_objects()
    raw["invalid_objects"] = invalids
    sections.append(_section("Objects And Validity", "CRITICAL" if invalids else "OK", "No invalid non-system objects found." if not invalids else f"{len(invalids)} invalid non-system object sample row(s).", invalids[:20]))
    if invalids:
        actions.append(ActionableHealthItem(category="objects", title="Invalid objects present", severity="CRITICAL", detail=f"{len(invalids)} invalid non-system object sample row(s).", recommendation="Compile invalid objects and investigate dependency failures.", evidence=[f"{row.get('owner')}.{row.get('object_name')} {row.get('object_type')}" for row in invalids[:5]]))

    redo = _redo_archive(hours)
    raw["redo_archive"] = redo
    raw["redo"] = {"count": redo.get("switches_24h_total"), "rate_per_hr": redo.get("max_switches_per_hour")}
    sections.append(_redo_section(redo, hours))
    actions.extend(_redo_actions(redo, hours))

    services = _services_and_routing(role_mode=role_mode)
    raw["services"] = services
    if role_mode.get("standby_health_mode"):
        sections.append(_standby_services_section(services))
    else:
        sections.append(_services_section(services))
    actions.extend(_services_actions(services))

    if role_mode.get("standby_health_mode"):
        standby = _standby_health_checks(hours=hours, role_mode=role_mode)
        raw.update(standby.get("raw") or {})
        sections.extend(standby.get("sections") or [])
        actions.extend(standby.get("actions") or [])

    recovery = _recovery(hours)
    raw["recovery"] = recovery
    sections.append(_recovery_section(recovery, hours))
    actions.extend(_recovery_actions(recovery, hours))

    scheduler = _scheduler_failures(hours)
    raw["scheduler_failures"] = scheduler
    sections.append(_section("Scheduler Jobs", "CRITICAL" if scheduler else "OK", "No scheduler failures found in the health window." if not scheduler else f"{len(scheduler)} scheduler failure sample row(s).", scheduler[:10]))
    if scheduler:
        actions.append(ActionableHealthItem(category="scheduler", title="Scheduler job failures", severity="CRITICAL", detail=f"{len(scheduler)} failed job run sample row(s) in the last {hours}h.", recommendation="Review failed job logs and fix job-specific errors.", evidence=[str(row) for row in scheduler[:3]]))

    if role_mode.get("primary_style_checks_skipped"):
        sections.extend(
            [
                _section("Performance Overview", "INFO", "Skipped in mounted standby mode.", notes=["Primary-style SQL/top-plan RCA is skipped in mounted standby mode."]),
                _section("Current Wait Profile", "INFO", "Skipped in mounted standby mode."),
                _section("Session Wait Correlation", "INFO", "Skipped in mounted standby mode."),
                _section("AWR Wait Events", "INFO", "Skipped in mounted standby mode."),
                _section("Cache Ratios", "INFO", "Skipped in mounted standby mode."),
            ]
        )
        raw["performance"] = {"skipped": True, "reason": "mounted_physical_standby"}
    else:
        performance = _performance(hours)
        raw["performance"] = performance
        performance_sections = _performance_sections(performance)
        if role_mode.get("standby_health_mode"):
            for section in performance_sections:
                section.status = "INFO"
                section.notes.append("Read-only standby workload context: primary-style SQL regression/RCA is demoted.")
        sections.extend(performance_sections)
        if not role_mode.get("standby_health_mode"):
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
    tx_section = _transaction_section(transactions)
    if role_mode.get("primary_style_checks_skipped"):
        tx_section.status = "INFO"
        tx_section.summary = "Skipped in mounted standby mode."
        tx_section.notes.append("DML/transaction workload RCA is skipped in mounted standby mode.")
    elif role_mode.get("standby_health_mode"):
        tx_section.status = "INFO"
        tx_section.notes.append("Standby mode: transaction/undo findings are contextual only.")
    sections.append(tx_section)
    if not role_mode.get("standby_health_mode"):
        actions.extend(_transaction_actions(transactions))

    memory = _memory_config()
    raw["memory_config"] = memory
    sections.append(_memory_section(memory))
    actions.extend(_memory_actions(memory))

    init_params = _init_params()
    raw["init_params"] = init_params
    sections.append(_section("Init Parameters", "INFO", f"{len(init_params.get('non_default', []))} non-default parameter row(s), {len(init_params.get('key', []))} key parameter row(s).", init_params.get("key", [])[:25], notes=[f"Non-default parameters captured: {len(init_params.get('non_default', []))}"]))

    raw["dba_trust_checks"] = _build_dba_trust_checks(raw=raw, sections=sections)
    sections.append(_dba_trust_section(raw["dba_trust_checks"]))
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
    rows, err = _fetch_all(
        """
        select i.inst_id,
               d.name as db_name,
               d.open_mode,
               d.database_role,
               d.protection_mode,
               d.protection_level,
               d.switchover_status,
               d.log_mode,
               i.instance_name,
               i.host_name,
               i.status as instance_status,
               i.thread# as thread,
               i.parallel
        from v$database d
        cross join gv$instance i
        order by i.inst_id
        """
    )
    if err:
        return {"error": err}
    if not rows:
        return {}
    out = dict(rows[0])
    out["instances"] = rows
    return out


def _db_status_level(row: dict[str, Any]) -> str:
    if row.get("error"):
        return "CRITICAL"
    open_mode = str(row.get("open_mode") or "").upper()
    return "OK" if open_mode.startswith("READ") or open_mode in {"OPEN", "MOUNTED"} else "CRITICAL"


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


def _database_role_mode(db_status: dict[str, Any]) -> dict[str, Any]:
    role = str(db_status.get("database_role") or "").strip()
    open_mode = str(db_status.get("open_mode") or "").strip()
    role_u = role.upper()
    open_u = open_mode.upper()
    standby_roles = {"PHYSICAL STANDBY", "LOGICAL STANDBY", "SNAPSHOT STANDBY"}
    is_standby = role_u in standby_roles
    is_physical_standby = role_u == "PHYSICAL STANDBY"
    is_mounted_physical_standby = is_physical_standby and open_u == "MOUNTED"
    return {
        "role": role or "UNKNOWN",
        "open_mode": open_mode or "UNKNOWN",
        "role_upper": role_u,
        "open_mode_upper": open_u,
        "standby_health_mode": bool(is_standby),
        "is_primary": role_u == "PRIMARY",
        "is_standby": bool(is_standby),
        "is_physical_standby": bool(is_physical_standby),
        "is_mounted_physical_standby": bool(is_mounted_physical_standby),
        "is_read_only_standby": bool(is_standby and open_u.startswith("READ ONLY")),
        "primary_style_checks_skipped": bool(is_mounted_physical_standby),
        "detected": bool(role_u),
        "status": "OK" if role_u else "WARNING",
    }


def _database_role_mode_section(role_mode: dict[str, Any]) -> HealthCheckSection:
    status = str(role_mode.get("status") or "WARNING")
    summary = (
        "Standby health mode enabled."
        if role_mode.get("standby_health_mode")
        else "Primary health mode enabled."
    )
    if status == "WARNING":
        summary = "Database role detection unavailable; conservative logic applied."
    row = {
        "role": role_mode.get("role"),
        "open_mode": role_mode.get("open_mode"),
        "standby_health_mode": "enabled" if role_mode.get("standby_health_mode") else "disabled",
        "primary_style_checks_skipped": "yes" if role_mode.get("primary_style_checks_skipped") else "no",
    }
    return _section("Database Role Mode", status, summary, [row])


def _standby_role_open_mode_section(*, db_status: dict[str, Any], role_mode: dict[str, Any]) -> HealthCheckSection:
    rows = [
        {
            "db_name": db_status.get("db_name"),
            "database_role": db_status.get("database_role"),
            "open_mode": db_status.get("open_mode"),
            "protection_mode": db_status.get("protection_mode"),
            "protection_level": db_status.get("protection_level"),
            "switchover_status": db_status.get("switchover_status"),
            "log_mode": db_status.get("log_mode"),
        }
    ]
    expected_raw = os.getenv("ODB_AUTODBA_STANDBY_EXPECTED_OPEN_MODE", "").strip()
    expected_modes = {part.strip().upper() for part in expected_raw.split(",") if part.strip()}
    open_mode = str(db_status.get("open_mode") or "").upper()
    status = "OK" if role_mode.get("detected") else "WARNING"
    notes: list[str] = []
    if expected_modes:
        if open_mode not in expected_modes:
            status = "CRITICAL" if role_mode.get("is_physical_standby") else "WARNING"
            notes.append(f"Expected standby open mode(s): {sorted(expected_modes)}; current: {open_mode or 'UNKNOWN'}.")
        else:
            notes.append(f"Expected standby open mode check passed: {open_mode}.")
    summary = "Database role/open mode captured for standby interpretation."
    return _section("Standby Role / Open Mode", status, summary, rows, notes=notes)


def _standby_health_checks(*, hours: int, role_mode: dict[str, Any]) -> dict[str, Any]:
    sections: list[HealthCheckSection] = []
    actions: list[ActionableHealthItem] = []
    raw: dict[str, Any] = {}

    managed_section, managed_raw = _standby_managed_recovery_section(role_mode=role_mode)
    lag_section, lag_raw = _standby_lag_section()
    gap_section, gap_raw = _standby_archive_gap_section()
    dest_section, dest_raw = _standby_archive_dest_section()
    dg_status_section, dg_status_raw = _standby_dataguard_status_section(hours=hours)
    dg_alert_section, dg_alert_raw = _standby_alert_log_signals_section(hours=hours)
    listener_section, listener_raw = _listener_connectivity_log_signals_section(hours=hours)

    sections.extend(
        [
            managed_section,
            lag_section,
            gap_section,
            dest_section,
            dg_status_section,
            dg_alert_section,
            listener_section,
        ]
    )
    raw["standby_managed_recovery"] = managed_raw
    raw["standby_lag"] = lag_raw
    raw["archive_gap"] = gap_raw
    raw["archive_dest_status"] = dest_raw
    raw["dataguard_status"] = dg_status_raw
    raw["standby_alert_log_signals"] = dg_alert_raw
    raw["listener_connectivity_signals"] = listener_raw

    for section in sections:
        if section.status in {"CRITICAL", "WARNING"}:
            actions.append(
                ActionableHealthItem(
                    category="standby",
                    title=section.name,
                    severity=section.status,
                    detail=section.summary,
                    recommendation="Investigate Data Guard transport/apply chain before treating standby as healthy.",
                    evidence=[str(row) for row in section.rows[:3]],
                )
            )
    return {"sections": sections, "actions": actions[:6], "raw": raw}


def _standby_managed_recovery_section(*, role_mode: dict[str, Any]) -> tuple[HealthCheckSection, dict[str, Any]]:
    rows, err = _fetch_all(
        """
        select inst_id,
               process,
               status,
               client_process,
               thread#,
               sequence#,
               block#,
               blocks
        from gv$managed_standby
        order by inst_id, process, thread#, sequence#
        """
    )
    source = "gv$managed_standby"
    if err and not rows:
        rows, err = _fetch_all(
            """
            select cast(null as number) as inst_id,
                   process,
                   status,
                   client_process,
                   thread#,
                   sequence#,
                   block#,
                   blocks
            from v$managed_standby
            order by process, thread#, sequence#
            """
        )
        source = "v$managed_standby"

    notes = [f"Source view: {source}"]
    if err and not rows:
        notes.append(f"Collector warning: {err}")
        return _section("Managed Recovery Process", "INFO", "Managed recovery query unavailable due to privileges or view access.", [], notes=notes), {"checked": False, "source": source, "error": err}

    has_mrp = any(str(row.get("process") or "").upper().startswith("MRP") for row in rows)
    has_rfs = any(str(row.get("process") or "").upper().startswith("RFS") for row in rows)
    has_gap = any(str(row.get("status") or "").upper() == "WAIT_FOR_GAP" for row in rows)
    apply_expected = _env_flag("ODB_AUTODBA_STANDBY_APPLY_EXPECTED", default=bool(role_mode.get("is_physical_standby")))
    transport_expected = _env_flag("ODB_AUTODBA_STANDBY_TRANSPORT_EXPECTED", default=bool(role_mode.get("is_physical_standby")))

    status = "OK"
    if apply_expected and not has_mrp:
        status = "CRITICAL"
    elif has_gap:
        status = "CRITICAL"
    elif transport_expected and not has_rfs:
        status = "WARNING"

    summary = "Managed recovery processes captured."
    if apply_expected and not has_mrp:
        summary = "MRP process is missing while apply is expected."
    elif has_gap:
        summary = "Managed recovery is waiting for gap."
    elif transport_expected and not has_rfs:
        summary = "RFS process not observed while transport is expected."
    return _section("Managed Recovery Process", status, summary, rows[:50], notes=notes), {
        "checked": True,
        "source": source,
        "has_mrp": has_mrp,
        "has_rfs": has_rfs,
        "has_gap": has_gap,
        "apply_expected": apply_expected,
        "transport_expected": transport_expected,
    }


def _standby_lag_section() -> tuple[HealthCheckSection, dict[str, Any]]:
    warn_seconds = _as_int(os.getenv("ODB_AUTODBA_STANDBY_LAG_WARN_SECONDS")) or 300
    crit_seconds = _as_int(os.getenv("ODB_AUTODBA_STANDBY_LAG_CRIT_SECONDS")) or 1800
    rows, err = _fetch_all(
        """
        select name,
               value,
               unit,
               time_computed,
               datum_time
        from v$dataguard_stats
        where name in ('transport lag', 'apply lag', 'apply finish time', 'estimated startup time')
        order by name
        """
    )
    notes: list[str] = [f"Lag thresholds: warning>{warn_seconds}s, critical>{crit_seconds}s."]
    if err and not rows:
        notes.append(f"Collector warning: {err}")
        return _section("Data Guard Lag", "INFO", "Data Guard lag metrics unavailable due to privileges.", [], notes=notes), {"checked": False, "error": err}

    out: list[dict[str, Any]] = []
    statuses: list[str] = []
    for row in rows:
        name = str(row.get("name") or "")
        parsed = _parse_dataguard_interval_seconds(str(row.get("value") or ""))
        severity = "INFO"
        if name in {"apply lag", "transport lag"} and parsed is not None:
            if parsed > crit_seconds:
                severity = "CRITICAL"
            elif parsed > warn_seconds:
                severity = "WARNING"
            else:
                severity = "OK"
        elif name in {"apply lag", "transport lag"} and parsed is None:
            notes.append(f"Could not parse lag value for {name}; raw value retained.")
        statuses.append(severity)
        out.append({**row, "parsed_seconds": parsed, "severity": severity})
    status = _worst(statuses or ["INFO"])
    summary = "Data Guard lag metrics captured."
    return _section("Data Guard Lag", status, summary, out, notes=notes), {"checked": True, "rows": out}


def _standby_archive_gap_section() -> tuple[HealthCheckSection, dict[str, Any]]:
    rows, err = _fetch_all(
        """
        select thread#,
               low_sequence#,
               high_sequence#
        from v$archive_gap
        order by thread#
        """
    )
    if err and not rows:
        return _section("Archive Gap", "INFO", "Archive gap query unavailable due to privileges.", [], notes=[f"Collector warning: {err}"]), {"checked": False, "error": err}
    if rows:
        note = "Resolve archive gap before treating standby as healthy. Check primary archive availability, FAL_SERVER/FAL_CLIENT, network, and archive destination errors."
        return _section("Archive Gap", "CRITICAL", "Archive gap detected.", rows, notes=[note]), {"checked": True, "has_gap": True}
    return _section("Archive Gap", "OK", "No archive gap rows returned.", []), {"checked": True, "has_gap": False}


def _standby_archive_dest_section() -> tuple[HealthCheckSection, dict[str, Any]]:
    rows, err = _fetch_all(
        """
        select dest_id,
               status,
               type,
               database_mode,
               recovery_mode,
               protection_mode,
               destination,
               error,
               archived_thread#,
               archived_seq#,
               applied_thread#,
               applied_seq#
        from v$archive_dest_status
        where status <> 'INACTIVE'
        order by dest_id
        """
    )
    if err and not rows:
        return _section("Archive Destination Status", "INFO", "Archive destination status unavailable due to privileges.", [], notes=[f"Collector warning: {err}"]), {"checked": False, "error": err}
    status = "OK"
    for row in rows:
        row_status = str(row.get("status") or "").upper()
        row_error = str(row.get("error") or "").strip()
        if row_status == "ERROR" or (row_error and row_error not in {"0", "-", "(null)", "NULL"}):
            status = "CRITICAL"
            break
        if row_status not in {"VALID"} and status != "CRITICAL":
            status = "WARNING"
    summary = "Archive destinations validated."
    return _section("Archive Destination Status", status, summary, rows[:50]), {"checked": True, "rows": rows}


def _standby_dataguard_status_section(*, hours: int) -> tuple[HealthCheckSection, dict[str, Any]]:
    rows, err = _fetch_all(
        """
        select to_char(timestamp, 'YYYY-MM-DD HH24:MI:SS') as timestamp,
               severity,
               facility,
               error_code,
               message
        from v$dataguard_status
        where timestamp >= sysdate - (:window_hours / 24)
          and (
               severity in ('Error', 'Fatal', 'Warning')
               or error_code is not null
               or upper(message) like '%GAP%'
               or upper(message) like '%ERROR%'
               or upper(message) like '%FAILED%'
          )
        order by timestamp desc
        fetch first 50 rows only
        """,
        {"window_hours": hours},
    )
    if err and not rows:
        return _section("Data Guard Status Messages", "INFO", "Data Guard status messages unavailable due to privileges.", [], notes=[f"Collector warning: {err}"]), {"checked": False, "error": err}
    status = "OK"
    for row in rows:
        sev = str(row.get("severity") or "").upper()
        if sev in {"FATAL", "ERROR"}:
            status = "CRITICAL"
            break
        if sev == "WARNING" and status != "CRITICAL":
            status = "WARNING"
    summary = "No recent Data Guard error/fatal messages." if not rows else f"{len(rows)} Data Guard status message row(s) found in last {hours}h."
    return _section("Data Guard Status Messages", status, summary, rows), {"checked": True, "rows": rows}


def _standby_alert_log_signals_section(*, hours: int) -> tuple[HealthCheckSection, dict[str, Any]]:
    rows, err = _fetch_all(
        """
        select to_char(originating_timestamp, 'YYYY-MM-DD HH24:MI:SS') as originating_timestamp,
               component_id,
               message_type,
               message_level,
               substr(message_text, 1, 1000) as message_text
        from v$diag_alert_ext
        where originating_timestamp >= systimestamp - numtodsinterval(:window_hours, 'HOUR')
          and regexp_like(message_text, 'ORA-|TNS-|FAL|MRP|RFS|Data Guard|standby|archive gap|media recovery|managed recovery', 'i')
        order by originating_timestamp desc
        fetch first 100 rows only
        """,
        {"window_hours": hours},
    )
    if err and not rows:
        return _section("Standby Alert Log Signals", "INFO", "Standby alert signal query unavailable due to privileges.", [], notes=[f"Collector warning: {err}"]), {"checked": False, "error": err}

    severities: list[str] = []
    for row in rows:
        message = str(row.get("message_text") or "")
        code = _extract_error_code(message) or ""
        severity = _ora_severity(code) if code else "INFO"
        text = message.lower()
        if any(token in text for token in ("fatal", "failed", "archive gap", "media recovery", "error")) and severity != "CRITICAL":
            severity = "WARNING"
        if any(token in text for token in ("wait_for_gap", "mrp", "fal", "tns-")) and severity == "INFO":
            severity = "WARNING"
        row["severity"] = severity
        severities.append(severity)
    status = _worst(severities or ["OK"])
    summary = "No standby alert-log signals found." if not rows else f"{len(rows)} standby-oriented alert-log row(s) captured."
    return _section("Standby Alert Log Signals", status, summary, rows), {"checked": True, "rows": rows}


def _listener_connectivity_log_signals_section(*, hours: int) -> tuple[HealthCheckSection, dict[str, Any]]:
    listener_log_path = os.getenv("ODB_AUTODBA_LISTENER_LOG_PATH", "").strip()
    if not listener_log_path or not os.path.exists(listener_log_path):
        row = {
            "source": "os_adr",
            "severity": "INFO",
            "message": "Listener log check skipped; OS/ADR access not available.",
        }
        return _section("Listener / Connectivity Log Signals", "INFO", "Listener log check skipped; OS/ADR access not available.", [row]), {"checked": False, "skipped_no_os_access": True}

    try:
        with open(listener_log_path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()[-2000:]
    except Exception as exc:
        row = {"source": listener_log_path, "severity": "INFO", "message": f"Listener log check skipped; unable to read file: {exc}"}
        return _section("Listener / Connectivity Log Signals", "INFO", "Listener log read failed; check file permissions.", [row]), {"checked": False, "read_error": str(exc)}

    patterns = ("tns-", "refused", "no listener", "service not registered", "unknown service", "handler")
    matches: list[dict[str, Any]] = []
    for line in reversed(lines):
        lower = line.lower()
        if any(token in lower for token in patterns):
            sev = "WARNING"
            if "no listener" in lower or "service not registered" in lower or "unknown service" in lower:
                sev = "CRITICAL"
            matches.append({"source": listener_log_path, "severity": sev, "message": line.strip()[:1000]})
        if len(matches) >= 50:
            break
    if not matches:
        return _section("Listener / Connectivity Log Signals", "OK", f"Listener log checked ({hours}h horizon heuristic); no error signals found.", [{"source": listener_log_path, "severity": "OK", "message": "No TNS/listener registration errors found."}]), {"checked": True, "rows": []}
    status = _worst([str(row.get("severity") or "INFO") for row in matches])
    return _section("Listener / Connectivity Log Signals", status, f"{len(matches)} listener/connectivity signal row(s) found.", matches), {"checked": True, "rows": matches}


def _parse_dataguard_interval_seconds(value: str) -> float | None:
    text = (value or "").strip()
    if not text or text in {"UNKNOWN", "UNDEFINED", "-"}:
        return None
    match = re.match(r"^\+?(\d+)\s+(\d+):(\d+):(\d+)$", text)
    if match:
        days, hours, mins, secs = (int(match.group(index)) for index in range(1, 5))
        return float(days * 86400 + hours * 3600 + mins * 60 + secs)
    simple = re.match(r"^(\d+):(\d+):(\d+)$", text)
    if simple:
        hours, mins, secs = (int(simple.group(index)) for index in range(1, 4))
        return float(hours * 3600 + mins * 60 + secs)
    return None


def _env_flag(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _tablespace_rows() -> tuple[list[dict[str, Any]], str | None]:
    rows, err = _fetch_all(
        """
        select tablespace_name,
               round(used_space * 100 / nullif(tablespace_size, 0), 2) as pct_used,
               round((tablespace_size - used_space) * 100 / nullif(tablespace_size, 0), 2) as pct_free
        from dba_tablespace_usage_metrics
        order by pct_used desc
        """
    )
    if not err and rows:
        normalized: list[dict[str, Any]] = []
        for row in rows:
            pct_used = _bounded_pct(_float(row.get("pct_used")))
            pct_free = _bounded_pct(_float(row.get("pct_free")))
            if pct_used is None or pct_free is None:
                calc_used, calc_free = _tablespace_pct_from_metrics(
                    used_space=_float(row.get("used_space")),
                    tablespace_size=_float(row.get("tablespace_size")),
                )
                if pct_used is None:
                    pct_used = calc_used
                if pct_free is None:
                    pct_free = calc_free
            normalized.append(
                {
                    **row,
                    "pct_used": pct_used,
                    "pct_free": pct_free,
                    "used_pct": pct_used if pct_used is not None else 0.0,
                }
            )
        return normalized, None

    fallback_rows = _tablespace_rows_fallback()
    return fallback_rows, "Fallback calculation used; DBA_TABLESPACE_USAGE_METRICS unavailable."


def _tablespace_rows_fallback() -> list[dict[str, Any]]:
    rows, _ = _fetch_all(
        """
        with df as (
            select tablespace_name,
                   sum(bytes) as allocated_bytes,
                   sum(case when autoextensible = 'YES' and nvl(maxbytes, 0) > bytes then maxbytes else bytes end) as max_bytes
            from dba_data_files
            group by tablespace_name
        ),
        fs as (
            select tablespace_name, sum(bytes) as free_bytes
            from dba_free_space
            group by tablespace_name
        )
        select df.tablespace_name,
               round(case when df.allocated_bytes > 0 then ((df.allocated_bytes - nvl(fs.free_bytes, 0)) / df.allocated_bytes) * 100 end, 2) as pct_used,
               round(case when df.allocated_bytes > 0 then (nvl(fs.free_bytes, 0) / df.allocated_bytes) * 100 end, 2) as pct_free
        from df
        left join fs on fs.tablespace_name = df.tablespace_name
        order by pct_used desc
        """
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        pct_used = _bounded_pct(_float(row.get("pct_used")))
        pct_free = _bounded_pct(_float(row.get("pct_free")))
        out.append(
            {
                **row,
                "pct_used": pct_used,
                "pct_free": pct_free,
                "used_pct": pct_used if pct_used is not None else 0.0,
            }
        )
    return out


def _tablespace_pct_from_metrics(*, used_space: float | None, tablespace_size: float | None) -> tuple[float | None, float | None]:
    if used_space is None or tablespace_size is None or tablespace_size <= 0:
        return None, None
    pct_used = _bounded_pct(round((used_space * 100.0) / tablespace_size, 2))
    pct_free = _bounded_pct(round(((tablespace_size - used_space) * 100.0) / tablespace_size, 2))
    return pct_used, pct_free


def _tablespace_section(rows: list[dict[str, Any]]) -> HealthCheckSection:
    if not rows:
        return _section("Tablespace Usage", "INFO", "Tablespace usage metrics were not available.")
    worst = rows[0]
    pct = _float(worst.get("pct_used"))
    warn, crit = _tablespace_thresholds()
    return _section("Tablespace Usage", _pct_status(pct, warn=warn, crit=crit), f"Highest usage is {pct:.2f}% on {worst.get('tablespace_name')}." if pct is not None else "Tablespace rows captured.", rows[:10])


def _tablespace_actions(rows: list[dict[str, Any]]) -> list[ActionableHealthItem]:
    actions = []
    warn, crit = _tablespace_thresholds()
    for row in rows:
        pct = _float(row.get("pct_used")) or 0.0
        if pct < warn:
            continue
        severity = "CRITICAL" if pct >= crit else "WARNING"
        tablespace = str(row.get("tablespace_name") or "unknown")
        actions.append(ActionableHealthItem(category="storage", title=f"Tablespace {tablespace} high usage", severity=severity, detail=f"{pct:.2f}% used.", recommendation="Review growth, largest segments, autoextend settings, and available storage before extending."))
    return actions


def _tablespace_allocation_details() -> list[dict[str, Any]]:
    rows, _ = _fetch_all(
        """
        with df as (
            select tablespace_name,
                   sum(bytes) as allocated_bytes,
                   sum(
                       case
                           when autoextensible = 'YES'
                            and nvl(maxbytes, 0) > bytes
                           then maxbytes
                           else bytes
                       end
                   ) as max_bytes,
                   case
                       when max(case when autoextensible = 'YES' then 1 else 0 end) = 1
                       then 'YES'
                       else 'NO'
                   end as autoextensible
            from dba_data_files
            group by tablespace_name
        ),
        fs as (
            select tablespace_name,
                   sum(bytes) as free_bytes
            from dba_free_space
            group by tablespace_name
        )
        select df.tablespace_name,
               round(df.allocated_bytes / 1024 / 1024 / 1024, 2) as allocated_gb,
               round((df.allocated_bytes - nvl(fs.free_bytes, 0)) / 1024 / 1024 / 1024, 2) as used_allocated_gb,
               round(nvl(fs.free_bytes, 0) / 1024 / 1024 / 1024, 2) as free_allocated_gb,
               round(df.max_bytes / 1024 / 1024 / 1024, 2) as max_gb,
               round(
                   case
                       when df.allocated_bytes > 0
                       then ((df.allocated_bytes - nvl(fs.free_bytes, 0)) / df.allocated_bytes) * 100
                   end, 2
               ) as allocated_used_pct,
               round(
                   case
                       when df.max_bytes > 0
                       then ((df.allocated_bytes - nvl(fs.free_bytes, 0)) / df.max_bytes) * 100
                   end, 2
               ) as max_used_pct,
               df.autoextensible
        from df
        left join fs
               on fs.tablespace_name = df.tablespace_name
        order by allocated_used_pct desc
        """
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        max_used_pct = _float(row.get("max_used_pct"))
        anomaly = bool(max_used_pct is not None and max_used_pct > 100.0)
        out.append({**row, "allocation_anomaly": anomaly})
    return out


def _tablespace_allocation_section(rows: list[dict[str, Any]]) -> HealthCheckSection:
    if not rows:
        return _section("Tablespace Allocation Details", "INFO", "Tablespace allocation details were not available.")
    status = "OK"
    if any(bool(row.get("allocation_anomaly")) for row in rows):
        status = "WARNING"
    return _section(
        "Tablespace Allocation Details",
        status,
        "Allocation details are informational and are not used for headline tablespace severity.",
        rows[:20],
    )


def _temp_summary() -> dict[str, Any]:
    capacity_rows, pct_err = _fetch_all(
        """
        select tablespace_name,
               round(tablespace_size/1024/1024/1024,2) as temp_allocated_gb,
               round(allocated_space/1024/1024/1024,2) as temp_current_allocated_gb,
               round(free_space/1024/1024/1024,2) as temp_free_gb,
               round((tablespace_size - free_space)/1024/1024/1024,2) as temp_used_gb,
               round(
                   case
                       when tablespace_size > 0
                       then ((tablespace_size - free_space) / tablespace_size) * 100
                   end, 2
               ) as temp_used_pct
        from dba_temp_free_space
        order by temp_used_pct desc
        """
    )
    consumers, _ = _fetch_all(
        """
        select u.inst_id,
               s.sid,
               s.serial# as serial_num,
               s.username,
               s.sql_id,
               s.module,
               u.tablespace,
               round(sum(u.blocks * ts.block_size)/1024/1024,2) as temp_used_mb
        from gv$tempseg_usage u
        join gv$session s
          on s.inst_id = u.inst_id
         and s.saddr = u.session_addr
        join dba_tablespaces ts
          on ts.tablespace_name = u.tablespace
        group by u.inst_id, s.sid, s.serial#, s.username, s.sql_id, s.module, u.tablespace
        order by temp_used_mb desc
        fetch first 20 rows only
        """
    )
    top = capacity_rows[0] if capacity_rows else {}
    return {"capacity_rows": capacity_rows, "capacity": top, "usage_error": pct_err, "top_consumers": consumers}


def _temp_sections(temp: dict[str, Any]) -> list[HealthCheckSection]:
    usage = temp.get("capacity") or {}
    pct = _float(usage.get("temp_used_pct"))
    if pct is None:
        capacity = _section(
            "Temp Tablespace Capacity",
            "INFO",
            "TEMP usage percentage was not available.",
            temp.get("capacity_rows", []),
            notes=[str(temp.get("usage_error"))] if temp.get("usage_error") else [],
        )
    else:
        capacity = _section(
            "Temp Tablespace Capacity",
            _pct_status(pct, warn=50, crit=80),
            f"TEMP usage is {pct:.2f}% for {usage.get('tablespace_name') or 'TEMP'}.",
            temp.get("capacity_rows", [])[:20],
        )
    consumers = _section(
        "Temp Session Consumers",
        "INFO",
        f"{len(temp.get('top_consumers') or [])} active TEMP consumer row(s) captured.",
        (temp.get("top_consumers") or [])[:20],
    )
    return [capacity, consumers]


def _temp_actions(temp: dict[str, Any]) -> list[ActionableHealthItem]:
    pct = _float((temp.get("capacity") or {}).get("temp_used_pct"))
    if pct is None or pct < 50:
        return []
    severity = "CRITICAL" if pct >= 80 else "WARNING"
    return [ActionableHealthItem(category="temp", title="High TEMP usage", severity=severity, detail=f"TEMP usage is {pct:.2f}%.", recommendation="Identify TEMP consumers and tune/stop runaway sorts or extend TEMP after review.", evidence=[str(row) for row in (temp.get("top_consumers") or [])[:3]])]


def _lock_pairs() -> tuple[list[dict[str, Any]], str | None]:
    rows, err = _fetch_all(
        """
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
                   s.row_wait_obj#
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
            select inst_id, ses_addr, start_date, used_ublk, used_urec
            from gv$transaction
        )
        select b.blocked_inst_id as waiter_inst_id,
               b.blocked_sid as waiter_sid,
               b.blocked_serial as waiter_serial,
               b.blocked_user as waiter_user,
               b.blocked_sql_id as waiter_sql_id,
               b.blocked_event as waiter_event,
               b.blocked_wait_class as waiter_wait_class,
               b.blocked_seconds_in_wait as seconds_in_wait,
               nvl(b.blocker_inst_id, b.final_blocking_instance) as blocker_inst_id,
               nvl(b.blocker_sid, b.final_blocking_session) as blocker_sid,
               bl.serial# as blocker_serial,
               bl.username as blocker_user,
               bl.sql_id as blocker_sql_id,
               bl.module as blocker_module,
               bl.program as blocker_program,
               bl.machine as blocker_machine,
               bl.status as blocker_status,
               bl.wait_class as blocker_wait_class,
               bl.blocker_classification,
               o.owner as object_owner,
               o.object_name,
               o.object_type,
               round((sysdate - t.start_date) * 24 * 60, 2) as blocker_txn_age_min,
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
        order by b.blocked_seconds_in_wait desc
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
    groups, _ = _fetch_all(
        """
        select thread#,
               group#,
               sequence#,
               bytes/1024/1024 as size_mb,
               members,
               archived,
               status
        from v$log
        order by thread#, group#
        """
    )
    switches, _ = _fetch_all(
        """
        select thread#,
               count(*) as switches_24h,
               round(count(*)/24,2) as switches_per_hour
        from v$log_history
        where first_time >= sysdate - 1
        group by thread#
        order by thread#
        """
    )
    redo_waits, _ = _fetch_all(
        """
        select inst_id,
               event,
               wait_class,
               total_waits,
               round(time_waited_micro/1000000,2) as time_waited_s,
               round(case when total_waits > 0 then time_waited_micro/1000/total_waits else 0 end,2) as avg_wait_ms
        from gv$system_event
        where event in (
            'log file sync',
            'log file parallel write',
            'log file switch completion',
            'log file switch (checkpoint incomplete)',
            'log file switch (archiving needed)',
            'log file switch (private strand flush incomplete)'
        )
        order by time_waited_micro desc
        """
    )
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
    max_rate = max((_float(row.get("switches_per_hour")) or 0.0 for row in switches), default=0.0)
    total_switches_24h = sum((_as_int(row.get("switches_24h")) or 0 for row in switches))
    return {
        "log_groups": groups,
        "switches_by_thread": switches,
        "redo_waits": redo_waits,
        "switches_24h_total": total_switches_24h,
        "max_switches_per_hour": max_rate,
        "log_mode": log_mode.get("log_mode"),
        "archive_dest": archive_dest.get("archive_dest"),
        "archive_dest_error": err,
    }


def _redo_section(redo: dict[str, Any], hours: int) -> HealthCheckSection:
    rate = _float(redo.get("max_switches_per_hour"))
    waits = redo.get("redo_waits") or []
    checkpoint_wait = _event_wait_ms(waits, "log file switch (checkpoint incomplete)")
    sync_wait = _event_wait_ms(waits, "log file sync")
    parallel_wait = _event_wait_ms(waits, "log file parallel write")
    archive_wait = _event_wait_ms(waits, "log file switch (archiving needed)")

    status = "INFO"
    if checkpoint_wait is not None and checkpoint_wait > 1000:
        status = "CRITICAL"
    elif any(value is not None and value > 20 for value in (sync_wait, parallel_wait)) or (archive_wait is not None and archive_wait > 1000):
        status = "WARNING"
    elif rate is not None and rate > 12:
        status = "WARNING"
    elif rate is not None and rate > 6 and _small_redo_logs(redo):
        status = "WARNING"

    rate_label = f"{rate:.2f}" if rate is not None else "n/a"
    summary = (
        "Redo switch rate is informational; checkpoint/log file waits determine severity. "
        f"24h switches={redo.get('switches_24h_total')}, max switches/hr={rate_label}. "
        f"log file sync avg={sync_wait if sync_wait is not None else '-'} ms, "
        f"log file parallel write avg={parallel_wait if parallel_wait is not None else '-'} ms, "
        f"checkpoint incomplete avg={checkpoint_wait if checkpoint_wait is not None else '-'} ms."
    )
    summary += f" Log mode: {redo.get('log_mode') or 'unknown'}; archive destination: {redo.get('archive_dest') or 'not found'}."
    return _section("Redo And Archiving", status, summary, (redo.get("switches_by_thread") or []) + waits[:10])


def _redo_actions(redo: dict[str, Any], hours: int) -> list[ActionableHealthItem]:
    actions = []
    rate = _float(redo.get("max_switches_per_hour"))
    waits = redo.get("redo_waits") or []
    checkpoint_wait = _event_wait_ms(waits, "log file switch (checkpoint incomplete)")
    sync_wait = _event_wait_ms(waits, "log file sync")
    parallel_wait = _event_wait_ms(waits, "log file parallel write")
    if checkpoint_wait is not None and checkpoint_wait > 1000:
        actions.append(ActionableHealthItem(category="redo", title="Checkpoint-related log switch waits", severity="CRITICAL", detail=f"log file switch (checkpoint incomplete) avg wait is {checkpoint_wait:.2f} ms.", recommendation="Increase redo log size and review checkpoint throughput."))
    elif any(value is not None and value > 20 for value in (sync_wait, parallel_wait)):
        actions.append(ActionableHealthItem(category="redo", title="Commit/redo write latency elevated", severity="WARNING", detail=f"log file sync={sync_wait or 0:.2f} ms, log file parallel write={parallel_wait or 0:.2f} ms.", recommendation="Investigate redo I/O latency and commit frequency."))
    elif rate is not None and rate > 12:
        actions.append(ActionableHealthItem(category="redo", title="High redo switch rate", severity="WARNING", detail=f"Max redo switch rate is {rate:.2f}/hr.", recommendation="Review redo log sizing and workload spikes."))
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
        select sql_id,
               count(distinct plan_hash_value) as distinct_plans,
               sum(executions_delta) as executions,
               round(sum(elapsed_time_delta)/1000000,2) as elapsed_s,
               round(
                   case when sum(executions_delta) > 0
                   then sum(elapsed_time_delta)/1000000/sum(executions_delta)
                   end, 4
               ) as elapsed_per_exec_s
        from dba_hist_sqlstat
        where snap_id in (
            select snap_id
            from dba_hist_snapshot
            where begin_interval_time >= sysdate - 1
        )
          and plan_hash_value <> 0
        group by sql_id
        having count(distinct plan_hash_value) > 1
        order by elapsed_s desc
        fetch first 20 rows only
        """
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
          from gv$active_session_history
          where sample_time > sysdate - (:hours/24)
            and session_state = 'ON CPU'
            and sql_id is not null
          group by sql_id
        )
        select sql_id,
               oncpu_samples,
               sum(oncpu_samples) over () as total_oncpu_samples,
               round(100.0 * oncpu_samples / nullif(sum(oncpu_samples) over (), 0), 2) as cpu_pct
        from ash
        where oncpu_samples > 0
        order by oncpu_samples desc
        fetch first 1 rows only
        """,
        {"hours": hours},
    )
    current_waits, wait_err = _fetch_all(
        """
        select inst_id,
               event,
               wait_class,
               total_waits,
               time_waited,
               round(case when total_waits > 0 then (time_waited / total_waits) else 0 end, 2) as avg_wait_ms
        from gv$eventmetric
        where wait_class <> 'Idle'
        order by time_waited desc
        fetch first 20 rows only
        """
    )
    if wait_err:
        current_waits, _ = _fetch_all(
            """
            select inst_id,
                   event,
                   wait_class,
                   total_waits,
                   round(time_waited_micro/1000000,2) as time_waited_s,
                   round(case when total_waits > 0 then time_waited_micro/1000/total_waits else 0 end,2) as avg_wait_ms
            from gv$system_event
            where wait_class <> 'Idle'
            order by time_waited_micro desc
            fetch first 20 rows only
            """
        )
    session_waits, _ = _fetch_all(
        """
        select s.inst_id,
               s.event,
               s.wait_class,
               s.sql_id,
               s.module,
               s.username,
               count(*) as session_count,
               max(s.seconds_in_wait) as max_seconds_in_wait
        from gv$session s
        where s.type = 'USER'
          and s.username is not null
          and s.status = 'ACTIVE'
          and nvl(s.wait_class,'Idle') <> 'Idle'
        group by s.inst_id, s.event, s.wait_class, s.sql_id, s.module, s.username
        order by session_count desc, max_seconds_in_wait desc
        fetch first 20 rows only
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
          from gv$sqlstats
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
    return {
        "plan_churn": plan_churn,
        "stale_stats": stale,
        "cache": cache,
        "top_cpu_sql": top_cpu,
        "current_waits": current_waits,
        "session_waits": session_waits,
        "top_elapsed_sql": top_elapsed,
        "awr_waits": awr_waits,
        "current_waits_unavailable": bool(wait_err),
    }


def _performance_sections(perf: dict[str, Any]) -> list[HealthCheckSection]:
    sections = []
    plan_churn = perf.get("plan_churn") or []
    stale = perf.get("stale_stats") or []
    top_cpu = perf.get("top_cpu_sql") or {}
    top_cpu_pct = _float(top_cpu.get("cpu_pct"))
    total_oncpu = _float(top_cpu.get("total_oncpu_samples"))
    ash_sample_min = 20.0
    if top_cpu and top_cpu_pct is not None and (total_oncpu or 0.0) >= ash_sample_min:
        top_cpu_status = "CRITICAL" if top_cpu_pct >= 50 else "WARNING"
    elif top_cpu:
        top_cpu_status = "INFO"
    else:
        top_cpu_status = "OK"
    perf_status = _worst(["WARNING" if plan_churn else "OK", "WARNING" if stale else "OK", top_cpu_status])
    summary_parts = [
        f"{len(plan_churn)} SQL_ID(s) with plan churn.",
        f"{len(stale)} stale-stat table sample row(s).",
        (
            f"Top ASH CPU SQL: {top_cpu.get('sql_id')} at {top_cpu_pct:.2f}% "
            f"(ON CPU samples={int(total_oncpu or 0)})."
            if top_cpu_pct is not None
            else "Top ASH CPU SQL unavailable."
        ),
    ]
    if top_cpu and (total_oncpu or 0.0) < ash_sample_min:
        summary_parts.append("Top SQL concentration observed, but ASH sample count is too low for warning.")
    sections.append(_section("Performance Overview", perf_status, " ".join(summary_parts), (perf.get("top_elapsed_sql") or [])[:10]))
    wait_notes = ["Current wait metric unavailable from GV$EVENTMETRIC; fallback used GV$SYSTEM_EVENT (since instance startup)."] if perf.get("current_waits_unavailable") else []
    sections.append(_section("Current Wait Profile", "INFO" if perf.get("current_waits") else "OK", f"{len(perf.get('current_waits') or [])} current non-idle wait row(s).", perf.get("current_waits") or [], notes=wait_notes))
    sections.append(_section("Session Wait Correlation", "INFO" if perf.get("session_waits") else "OK", f"{len(perf.get('session_waits') or [])} active non-idle session wait row(s).", perf.get("session_waits") or []))
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
    total_oncpu = _float(top_cpu.get("total_oncpu_samples"))
    ash_sample_min = 20.0
    if pct is not None and (total_oncpu or 0.0) >= ash_sample_min:
        actions.append(ActionableHealthItem(category="sql", title="ASH top CPU SQL concentration", severity="CRITICAL" if pct >= 50 else "WARNING", detail=f"SQL_ID {top_cpu.get('sql_id')} accounts for {pct:.2f}% of ON CPU ASH samples in {hours}h.", recommendation="Run SQL_ID deep dive and inspect execution plan, waits, and row-source behavior."))
    return actions


def _transactions() -> dict[str, Any]:
    long_tx, _ = _fetch_all(
        """
        select s.sid, s.serial# as serial_num, nvl(s.username,'-') as username,
               round((sysdate - t.start_date)*24*60, 2) as minutes,
               nvl(s.sql_id,'N/A') as sql_id
        from gv$transaction t
        join gv$session s on s.inst_id = t.inst_id and s.saddr = t.ses_addr
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
          from gv$session s
          join gv$sesstat ss on ss.inst_id = s.inst_id and ss.sid = s.sid
          join gv$statname sn on sn.inst_id = ss.inst_id and sn.statistic# = ss.statistic#
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
          from gv$tempseg_usage t
          join dba_tablespaces ts on ts.tablespace_name = t.tablespace
          group by inst_id, session_addr
        )
        select * from (
          select s.sid, s.serial# as serial_num, nvl(s.username,'-') as username,
                 nvl(s.module,'-') as module, nvl(s.program,'-') as program,
                 nvl(s.machine,'-') as machine, nvl(s.osuser,'-') as osuser,
                 nvl(s.sql_id,'-') as sql_id, p.spid,
                 round(p.pga_used_mem/1024/1024, 2) as pga_used_mb,
                 round(p.pga_alloc_mem/1024/1024, 2) as pga_alloc_mb,
                 nvl(tu.temp_used_mb, 0) as temp_used_mb
          from gv$session s
          join gv$process p on p.inst_id = s.inst_id and p.addr = s.paddr
          left join temp_usage tu on tu.inst_id = s.inst_id and tu.session_addr = s.saddr
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
        top_sid = top.get("sid")
        top_sql_id = top.get("sql_id")
        top_user = top.get("username")
        top_module = top.get("module") or "-"
        top_program = top.get("program") or "-"
        summary += (
            f" Session SID {top_sid} (SQL_ID {top_sql_id}) user={top_user or '-'} "
            f"module={top_module} program={top_program} is the largest Oracle PGA consumer in the current snapshot."
        )
        if any(str(cpu_row.get("sql_id") or "") == str(top_sql_id or "") for cpu_row in top_cpu_sessions):
            notes.append(
                f"Largest PGA consumer SQL_ID {top_sql_id} also appears in top DB CPU sessions."
            )
        if (_float(top.get("pga_used_mb")) or 0.0) >= 512:
            notes.append(
                f"High single-session PGA observed: SID {top_sid} uses {top.get('pga_used_mb')} MB."
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
    # Cache ratios are context-only and must not be escalated standalone.
    return "INFO"


def _cache_summary(cache: dict[str, Any]) -> str:
    buffer_hit = _float(cache.get("buffer_hit_pct"))
    context_line = (
        "Cache ratios are healthy/context only."
        if buffer_hit is not None and buffer_hit >= 90.0
        else "Low buffer cache ratio observed, but insufficient correlated I/O evidence to call root cause."
    )
    return (
        f"Buffer={_fmt_pct(cache.get('buffer_hit_pct'))}, "
        f"Library={_fmt_pct(cache.get('library_hit_pct'))}, "
        f"Dictionary={_fmt_pct(cache.get('dictionary_hit_pct'))}. "
        f"{context_line}"
    )


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


def _services_and_routing(*, role_mode: dict[str, Any] | None = None) -> dict[str, Any]:
    active_rows, active_err = _fetch_all(
        """
        select s.inst_id,
               s.name,
               s.network_name,
               s.con_id,
               c.name as container_name,
               to_char(s.creation_date, 'YYYY-MM-DD HH24:MI:SS') as creation_date
        from gv$active_services s
        left join v$containers c
               on c.con_id = s.con_id
        order by s.inst_id, s.name
        """
    )
    source = "gv$active_services"
    if active_err and not active_rows:
        active_rows, active_err = _fetch_all(
            """
            select cast(null as number) as inst_id,
                   s.name,
                   s.network_name,
                   s.con_id,
                   c.name as container_name,
                   to_char(s.creation_date, 'YYYY-MM-DD HH24:MI:SS') as creation_date
            from v$active_services s
            left join v$containers c
                   on c.con_id = s.con_id
            order by s.name
            """
        )
        source = "v$active_services"

    configured_rows, configured_err = _fetch_all(
        """
        select inst_id,
               name,
               network_name,
               con_id,
               goal,
               clb_goal,
               aq_ha_notifications
        from gv$services
        order by inst_id, name
        """
    )
    if configured_err and "ORA-00904" in configured_err.upper() and "AQ_HA_NOTIFICATIONS" in configured_err.upper():
        fallback_rows, fallback_err = _fetch_all(
            """
            select inst_id,
                   name,
                   network_name,
                   con_id,
                   goal,
                   clb_goal
            from gv$services
            order by inst_id, name
            """
        )
        if fallback_rows and not fallback_err:
            configured_rows = fallback_rows
            configured_err = f"{configured_err}; fallback query used without AQ_HA_NOTIFICATIONS."

    context = role_mode or {}
    expected = _expected_services()
    evaluated = _evaluate_services(
        active_rows=active_rows,
        expected=expected,
        role_mode=context,
    )
    return {
        "active_services": active_rows,
        "configured_services": configured_rows,
        "expected_services": expected,
        "evaluation": evaluated,
        "source": source,
        "active_error": active_err,
        "configured_error": configured_err,
        "role_mode": context,
    }


def _services_section(services: dict[str, Any]) -> HealthCheckSection:
    evaluation = services.get("evaluation") or {}
    severity = str(evaluation.get("severity") or "INFO")
    rows = evaluation.get("rows") or []
    summary = str(evaluation.get("summary") or "Service routing evaluation completed.")
    notes: list[str] = []
    if services.get("active_error"):
        notes.append(f"Active service query warning: {services.get('active_error')}")
    if services.get("configured_error"):
        notes.append(f"Configured service query warning: {services.get('configured_error')}")
    notes.append(f"Active service source: {services.get('source')}")
    return _section("Services And Routing", severity, summary, rows, notes=notes)


def _standby_services_section(services: dict[str, Any]) -> HealthCheckSection:
    section = _services_section(services)
    section.name = "Standby Active Services"
    return section


def _services_actions(services: dict[str, Any]) -> list[ActionableHealthItem]:
    evaluation = services.get("evaluation") or {}
    severity = str(evaluation.get("severity") or "INFO")
    if severity not in {"CRITICAL", "WARNING"}:
        return []
    findings = evaluation.get("findings") or []
    return [
        ActionableHealthItem(
            category="services",
            title="Service routing mismatch",
            severity=severity,
            detail=str(evaluation.get("summary") or "Service routing issue detected."),
            recommendation="Validate service registration and instance placement against expected services.",
            evidence=[str(item) for item in findings[:5]],
        )
    ]


def _expected_services() -> list[dict[str, Any]]:
    raw = os.getenv("ODB_AUTODBA_EXPECTED_SERVICES", "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    out: list[dict[str, Any]] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        expected_instances = item.get("expected_instances")
        if not isinstance(expected_instances, list):
            expected_instances = []
        out.append(
            {
                "name": name,
                "required": bool(item.get("required", True)),
                "expected_instances": [int(x) for x in expected_instances if _as_int(x) is not None],
            }
        )
    return out


def _evaluate_services(
    *,
    active_rows: list[dict[str, Any]],
    expected: list[dict[str, Any]],
    role_mode: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = role_mode or {}
    standby_mode = bool(context.get("standby_health_mode"))
    mounted_physical_standby = bool(context.get("is_mounted_physical_standby"))
    read_only_standby = bool(context.get("is_read_only_standby"))
    filtered = [row for row in active_rows if not _is_internal_service(str(row.get("name") or ""))]
    findings: list[str] = []
    rows: list[dict[str, Any]] = []
    for row in filtered:
        rows.append(
            {
                "inst_id": row.get("inst_id"),
                "service_name": row.get("name"),
                "name": row.get("name"),
                "network_name": row.get("network_name"),
                "con_id": row.get("con_id"),
                "container_name": row.get("container_name"),
                "status": "ACTIVE",
                "finding": "discovered",
            }
        )
    if not filtered:
        findings.append("No non-internal active services were discovered.")

    severity = "INFO"
    if not active_rows:
        severity = "WARNING"
    if not filtered:
        if mounted_physical_standby and not expected:
            severity = "INFO"
        elif standby_mode and read_only_standby:
            severity = "WARNING"
        else:
            severity = "WARNING"

    if expected:
        expected_map = {str(item.get("name") or "").upper(): item for item in expected}
        active_by_name: dict[str, set[int]] = {}
        for row in filtered:
            name = str(row.get("name") or "").upper()
            if not name:
                continue
            active_by_name.setdefault(name, set()).add(_as_int(row.get("inst_id")) or 0)

        for name, item in expected_map.items():
            required = bool(item.get("required", True))
            expected_instances = {int(x) for x in (item.get("expected_instances") or [])}
            active_instances = active_by_name.get(name, set())
            if required and not active_instances:
                severity = "CRITICAL"
                findings.append(f"Required service {name} is missing.")
                rows.append({"inst_id": None, "service_name": name, "name": name, "network_name": None, "con_id": None, "container_name": None, "status": "MISSING", "finding": "required service missing"})
                continue
            if expected_instances and active_instances:
                if not expected_instances.issubset(active_instances):
                    severity = "CRITICAL" if required else "WARNING"
                    findings.append(f"Service {name} is active on fewer than expected instances.")
                unexpected = active_instances - expected_instances
                if unexpected:
                    severity = "WARNING" if severity != "CRITICAL" else severity
                    findings.append(f"Service {name} is active on unexpected instance(s): {sorted(unexpected)}.")
    else:
        findings.append("No expected_services config provided; reporting discovered services only.")

    if not active_rows:
        summary = "No active services returned from service views."
    else:
        summary = f"{len(filtered)} non-internal active service row(s) discovered."
    if mounted_physical_standby and not expected and not filtered:
        summary = "Mounted standby with no non-internal services is informational when no expected service config exists."
    return {"severity": severity, "summary": summary, "rows": rows[:50], "findings": findings}


def _is_internal_service(name: str) -> bool:
    upper = str(name or "").upper()
    return upper.startswith("SYS$") or upper in {"SYS$BACKGROUND", "SYS$USERS"}


def _build_dba_trust_checks(*, raw: dict[str, Any], sections: list[HealthCheckSection]) -> dict[str, Any]:
    tablespace_rows = raw.get("tablespaces") or []
    tablespace_unit_ok = all(_float(row.get("pct_used")) is None or 0.0 <= (_float(row.get("pct_used")) or 0.0) <= 100.0 for row in tablespace_rows)
    awr_valid = True
    awr_mode = str(raw.get("awr_mode") or "")
    if awr_mode == "SAME_SNAPSHOT_WINDOW":
        awr_valid = False
    services = raw.get("services") or {}
    expected_services = services.get("expected_services") if isinstance(services, dict) else []
    role_mode = raw.get("database_role_mode") if isinstance(raw.get("database_role_mode"), dict) else {}
    has_inst_id = any(
        (_as_int(row.get("inst_id")) is not None)
        for row in (services.get("active_services") or []) + (raw.get("temp", {}).get("top_consumers") or []) + (raw.get("lock_pairs") or [])
        if isinstance(row, dict)
    )
    listener_raw = raw.get("listener_connectivity_signals") if isinstance(raw.get("listener_connectivity_signals"), dict) else {}
    if listener_raw.get("skipped_no_os_access"):
        listener_checked = "skipped_no_os_access"
    else:
        listener_checked = "yes" if listener_raw else "no"
    standby_mode = bool(role_mode.get("standby_health_mode"))
    standby_recovery = raw.get("standby_managed_recovery") if isinstance(raw.get("standby_managed_recovery"), dict) else {}
    standby_lag = raw.get("standby_lag") if isinstance(raw.get("standby_lag"), dict) else {}
    archive_gap = raw.get("archive_gap") if isinstance(raw.get("archive_gap"), dict) else {}
    dg_status = raw.get("dataguard_status") if isinstance(raw.get("dataguard_status"), dict) else {}
    return {
        "rac_mode_detected": "yes" if (bool((raw.get("db_status") or {}).get("instances")) and len((raw.get("db_status") or {}).get("instances") or []) > 1) else "no",
        "runtime_views_used": "GV$",
        "inst_id_included": "yes" if has_inst_id else "no",
        "service_check_performed": "yes" if bool(raw.get("services")) else "no",
        "expected_service_validation": "yes" if bool(expected_services) else "no",
        "active_sessions_split_true_active_idle_active": "yes",
        "blocking_severity_used_seconds_in_wait": "yes",
        "blocking_severity_used_blocker_classification": "yes",
        "awr_comparison_valid": "yes" if awr_valid else "no",
        "tablespace_headline_source": raw.get("tablespace_headline_source") or "DBA_TABLESPACE_USAGE_METRICS",
        "tablespace_headline_percent_validation_passed": "yes" if tablespace_unit_ok else "no",
        "tablespace_optional_allocation_unit_validation_passed": "yes" if not any(bool(row.get("allocation_anomaly")) for row in (raw.get("tablespace_allocation_details") or [])) else "no",
        "temp_capacity_separated_from_temp_consumers": "yes",
        "sql_id_wrapper_detection_enabled": "yes",
        "cache_ratio_standalone_critical_disabled": "yes",
        "redo_switch_standalone_warning_disabled": "yes",
        "standby_mode_detected": "yes" if standby_mode else "no",
        "standby_apply_checked": "yes" if standby_recovery.get("checked") else "no",
        "standby_lag_checked": "yes" if standby_lag.get("checked") else "no",
        "archive_gap_checked": "yes" if archive_gap.get("checked") else "no",
        "dataguard_status_checked": "yes" if dg_status.get("checked") else "no",
        "standby_services_checked": "yes" if standby_mode and bool(raw.get("services")) else ("no" if standby_mode else "n/a"),
        "listener_log_checked": listener_checked,
        "primary_style_checks_skipped_for_mounted_standby": "yes" if raw.get("primary_style_checks_skipped_for_mounted_standby") else "no",
    }


def _dba_trust_section(checks: dict[str, Any]) -> HealthCheckSection:
    rows = [{"check": key, "value": value} for key, value in checks.items()]
    return _section("DBA Trust Checks", "INFO", "Collector trust and interpretation guardrails status.", rows)


def _ora_severity(code: str) -> str:
    upper = (code or "").upper()
    critical = {"ORA-00600", "ORA-00700", "ORA-07445", "ORA-04030", "ORA-04031", "ORA-03113", "ORA-03135", "ORA-01555"}
    warning = {"ORA-00060", "ORA-01652", "ORA-01653"}
    if upper in critical:
        return "CRITICAL"
    if upper in warning:
        return "WARNING"
    return "INFO"


def _tablespace_thresholds() -> tuple[float, float]:
    warn = _float(os.getenv("ODB_AUTODBA_TABLESPACE_WARN_PCT")) or 85.0
    crit = _float(os.getenv("ODB_AUTODBA_TABLESPACE_CRIT_PCT")) or 97.0
    if crit <= warn:
        crit = warn + 1.0
    return warn, crit


def _bounded_pct(value: float | None) -> float | None:
    if value is None:
        return None
    return round(max(0.0, min(100.0, value)), 2)


def _event_wait_ms(rows: list[dict[str, Any]], event_name: str) -> float | None:
    for row in rows:
        if str(row.get("event") or "").lower() == event_name.lower():
            return _float(row.get("avg_wait_ms"))
    return None


def _small_redo_logs(redo: dict[str, Any]) -> bool:
    groups = redo.get("log_groups") or []
    sizes = [_float(row.get("size_mb")) for row in groups]
    sizes = [size for size in sizes if size is not None]
    if not sizes:
        return False
    return max(sizes) < 1024.0


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


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(float(value))
    except Exception:
        return None


def _fmt_pct(value: Any) -> str:
    pct = _float(value)
    return "unknown" if pct is None else f"{pct:.2f}%"


def _lock_evidence(row: dict[str, Any]) -> str:
    return f"Blocker SID {row.get('blocker_sid')},{row.get('blocker_serial')} user={row.get('blocker_user')} blocking waiter SID {row.get('waiter_sid')} wait={row.get('seconds_in_wait')}s"
