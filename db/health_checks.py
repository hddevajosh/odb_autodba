from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from typing import Any

from odb_autodba.db.connection import fetch_all, fetch_one
from odb_autodba.db.extended_health_checks import collect_extended_health
from odb_autodba.db.log_checks import collect_alert_error_summary, collect_listener_error_summary
from odb_autodba.db.module_health import summarize_modules
from odb_autodba.db.plan_checks import collect_plan_evidence_for_top_sql
from odb_autodba.db.running_sessions import (
    get_blocking_chains,
    get_running_sessions_inventory,
    get_top_session_resource_candidates,
    map_top_processes_to_sessions,
)
from odb_autodba.db.sql_text import get_sql_text
from odb_autodba.host.health_checks import collect_host_snapshot
from odb_autodba.models.schemas import (
    ActionableHealthItem,
    BlockingInterpretationNote,
    HealthCheckSection,
    HealthIssue,
    HealthSnapshot,
    HotspotCorrelationSummary,
    HotspotProcessRow,
    HostProcessRow,
    HostSnapshot,
    InstanceInfo,
    OracleHotspotCandidate,
    SessionSummary,
    TablespaceUsageRow,
    TablespaceAllocationAnomaly,
    TempUsageRow,
    TopSqlRow,
    WaitClassSummary,
    WaitEventRow,
)
from odb_autodba.utils.oracle_env import env_flag


INSTANCE_SQL = """
select i.instance_name, i.host_name, i.version,
       to_char(i.startup_time, 'YYYY-MM-DD HH24:MI:SS') as startup_time,
       d.name as db_name, d.db_unique_name, d.open_mode, d.database_role, d.platform_name,
       case when exists (select 1 from gv$instance having count(*) > 1) then 1 else 0 end as rac_enabled,
       d.cdb
from v$instance i cross join v$database d
"""

SESSION_SUMMARY_SQL = """
select count(*) as total_sessions,
       sum(case when status = 'ACTIVE' then 1 else 0 end) as active_sessions,
       sum(case when status = 'INACTIVE' then 1 else 0 end) as inactive_sessions,
       sum(case when username is not null then 1 else 0 end) as user_sessions,
       sum(case when blocking_session is not null then 1 else 0 end) as blocked_sessions,
       count(distinct case when blocking_session is not null then blocking_session end) as blocking_sessions,
       sum(case when status='ACTIVE' and last_call_et > 3600 then 1 else 0 end) as long_running_sessions
from gv$session
where type='USER'
"""

WAIT_CLASS_SQL = """
select wait_class, count(*) as session_count
from gv$session
where type='USER' and status='ACTIVE' and wait_class is not null
group by wait_class
order by session_count desc
fetch first 10 rows only
"""

TOP_WAITS_SQL = """
select event, total_waits, round(time_waited_micro/1e6,3) as time_waited_s, wait_class
from v$system_event
where wait_class <> 'Idle'
order by time_waited_micro desc
fetch first 10 rows only
"""

ENRICHED_TOP_SQL_ELAPSED_SQL = """
select *
from (
    select s.sql_id,
           s.plan_hash_value,
           coalesce(v.parsing_schema_name, sess.username) as parsing_schema_name,
           sess.username,
           coalesce(v.module, sess.module) as module,
           sess.program,
           sess.machine,
           round(s.elapsed_time/1e6,3) as elapsed_s,
           round(s.cpu_time/1e6,3) as cpu_s,
           round((s.elapsed_time/1e6)/nullif(s.executions,0),6) as ela_per_exec_s,
           round((s.cpu_time/1e6)/nullif(s.executions,0),6) as cpu_per_exec_s,
           s.buffer_gets,
           round(s.buffer_gets/nullif(s.executions,0),3) as buffer_gets_per_exec,
           s.disk_reads,
           round(s.disk_reads/nullif(s.executions,0),3) as disk_reads_per_exec,
           s.executions,
           s.rows_processed,
           round(s.rows_processed/nullif(s.executions,0),3) as rows_processed_per_exec,
           to_char(v.last_active_time, 'YYYY-MM-DD HH24:MI:SS') as last_active_time
    from v$sqlstats s
    left join (
        select sql_id,
               max(parsing_schema_name) as parsing_schema_name,
               max(module) as module,
               max(last_active_time) as last_active_time
        from v$sql
        group by sql_id
    ) v on v.sql_id = s.sql_id
    left join (
        select sql_id,
               max(username) as username,
               max(module) as module,
               max(program) as program,
               max(machine) as machine
        from gv$session
        where sql_id is not null and username is not null
        group by sql_id
    ) sess on sess.sql_id = s.sql_id
    where s.sql_id is not null
    order by s.elapsed_time desc
)
where rownum <= :lim
"""

ENRICHED_TOP_SQL_CPU_SQL = """
select *
from (
    select s.sql_id,
           s.plan_hash_value,
           coalesce(v.parsing_schema_name, sess.username) as parsing_schema_name,
           sess.username,
           coalesce(v.module, sess.module) as module,
           sess.program,
           sess.machine,
           round(s.elapsed_time/1e6,3) as elapsed_s,
           round(s.cpu_time/1e6,3) as cpu_s,
           round((s.elapsed_time/1e6)/nullif(s.executions,0),6) as ela_per_exec_s,
           round((s.cpu_time/1e6)/nullif(s.executions,0),6) as cpu_per_exec_s,
           s.buffer_gets,
           round(s.buffer_gets/nullif(s.executions,0),3) as buffer_gets_per_exec,
           s.disk_reads,
           round(s.disk_reads/nullif(s.executions,0),3) as disk_reads_per_exec,
           s.executions,
           s.rows_processed,
           round(s.rows_processed/nullif(s.executions,0),3) as rows_processed_per_exec,
           to_char(v.last_active_time, 'YYYY-MM-DD HH24:MI:SS') as last_active_time
    from v$sqlstats s
    left join (
        select sql_id,
               max(parsing_schema_name) as parsing_schema_name,
               max(module) as module,
               max(last_active_time) as last_active_time
        from v$sql
        group by sql_id
    ) v on v.sql_id = s.sql_id
    left join (
        select sql_id,
               max(username) as username,
               max(module) as module,
               max(program) as program,
               max(machine) as machine
        from gv$session
        where sql_id is not null and username is not null
        group by sql_id
    ) sess on sess.sql_id = s.sql_id
    where s.sql_id is not null
    order by s.cpu_time desc
)
where rownum <= :lim
"""

LEGACY_TOP_SQL_ELAPSED_SQL = """
select * from (
  select s.sql_id, s.plan_hash_value,
         (select max(q.parsing_schema_name)
          from v$sql q
          where q.sql_id = s.sql_id) as parsing_schema_name,
         (select max(q.module)
          from v$sql q
          where q.sql_id = s.sql_id) as module,
         round(s.elapsed_time/1e6,3) as elapsed_s,
         round(s.cpu_time/1e6,3) as cpu_s,
         s.buffer_gets, s.disk_reads, s.executions, s.rows_processed
  from v$sqlstats s
  where s.sql_id is not null
  order by s.elapsed_time desc
) where rownum <= :lim
"""

LEGACY_TOP_SQL_CPU_SQL = """
select * from (
  select s.sql_id, s.plan_hash_value,
         (select max(q.parsing_schema_name)
          from v$sql q
          where q.sql_id = s.sql_id) as parsing_schema_name,
         (select max(q.module)
          from v$sql q
          where q.sql_id = s.sql_id) as module,
         round(s.elapsed_time/1e6,3) as elapsed_s,
         round(s.cpu_time/1e6,3) as cpu_s,
         s.buffer_gets, s.disk_reads, s.executions, s.rows_processed
  from v$sqlstats s
  where s.sql_id is not null
  order by s.cpu_time desc
) where rownum <= :lim
"""

TABLESPACE_SQL = """
select tablespace_name, used_percent as used_pct,
       tablespace_size*8 as total_mb,
       used_space*8 as used_mb,
       (tablespace_size-used_space)*8 as free_mb,
       contents, bigfile
from dba_tablespace_usage_metrics m
join dba_tablespaces t using (tablespace_name)
order by used_percent desc
"""

TEMP_SQL = """
select s.username, u.sql_id, u.segtype, round(u.blocks * ts.block_size / 1024 / 1024, 2) as mb_used,
       u.tablespace as tablespace
from v$tempseg_usage u
join v$session s on s.saddr = u.session_addr
join dba_tablespaces ts on ts.tablespace_name = u.tablespace
order by mb_used desc
fetch first 10 rows only
"""

INIT_PARAM_SQL = """
select name, value, isdefault
from v$parameter
where isdefault = 'FALSE'
order by name
fetch first 50 rows only
"""

SCHEDULER_SQL = """
select owner, job_name, enabled, state
from dba_scheduler_jobs
order by owner, job_name
fetch first 20 rows only
"""


def collect_health_snapshot() -> HealthSnapshot:
    notes: list[str] = []
    generated_at = datetime.now(UTC).isoformat()
    window_hours = _health_window_hours()

    instance_row = fetch_one(INSTANCE_SQL) or {}
    summary_row = fetch_one(SESSION_SUMMARY_SQL) or {}
    wait_classes = [WaitClassSummary(**row) for row in fetch_all(WAIT_CLASS_SQL)]
    top_waits = [WaitEventRow(**row) for row in fetch_all(TOP_WAITS_SQL)]

    top_elapsed = _collect_top_sql_rows(limit=10, order="elapsed", notes=notes)
    top_cpu = _collect_top_sql_rows(limit=10, order="cpu", notes=notes)

    tablespaces = [TablespaceUsageRow(**row) for row in fetch_all(TABLESPACE_SQL)]
    temp_usage = [TempUsageRow(**row) for row in fetch_all(TEMP_SQL)]
    active_sessions = get_running_sessions_inventory()
    blocking = get_blocking_chains()
    ora_errors = collect_alert_error_summary()
    listener_errors = collect_listener_error_summary()
    host_snapshot = collect_host_snapshot() if env_flag("ENABLE_HOST_CHECKS", True) else None
    top_session_candidates = get_top_session_resource_candidates(limit=10)

    plan_evidence = collect_plan_evidence_for_top_sql([row.sql_id for row in top_elapsed[:5]])
    extended_sections, actionable_items, raw_evidence = collect_extended_health(window_hours=window_hours)
    raw_evidence["top_session_resource_candidates"] = top_session_candidates

    if host_snapshot is not None:
        host_snapshot = _correlate_host_hotspots_with_db(
            host_snapshot,
            notes=notes,
            top_sql_by_cpu=top_cpu,
            top_session_candidates=top_session_candidates,
            top_pga_candidates=(raw_evidence.get("memory_config") or {}).get("top_pga_sessions") or [],
        )

    if host_snapshot:
        extended_sections.append(_host_health_section(host_snapshot))
        extended_sections.extend(_build_hotspot_sections(host_snapshot))
        actionable_items.extend(_host_actionable_items(host_snapshot))
        raw_evidence["host"] = host_snapshot.model_dump(mode="json")
    raw_evidence["blocking_chains"] = [chain.model_dump(mode="json") for chain in blocking]

    snapshot = HealthSnapshot(
        generated_at=generated_at,
        instance_info=InstanceInfo(**instance_row),
        session_summary=SessionSummary(**summary_row),
        active_sessions=active_sessions,
        blocking_chains=blocking,
        top_waits=top_waits,
        wait_classes=wait_classes,
        top_sql_by_elapsed=top_elapsed,
        top_sql_by_cpu=top_cpu,
        tablespaces=tablespaces,
        temp_usage=temp_usage,
        ora_errors=ora_errors,
        listener_errors=listener_errors,
        init_parameters=fetch_all(INIT_PARAM_SQL),
        scheduler_jobs=fetch_all(SCHEDULER_SQL),
        host_snapshot=host_snapshot,
        plan_evidence=plan_evidence,
        health_sections=extended_sections,
        actionable_items=actionable_items,
        raw_evidence=raw_evidence,
        notes=notes,
    )
    _reconcile_lock_section(snapshot)
    _apply_tablespace_allocation_anomaly(snapshot)
    _apply_lock_wait_interpretation(snapshot)
    snapshot.issues = _derive_issues(snapshot)
    snapshot.module_summaries = summarize_modules(snapshot)
    return snapshot


def _collect_top_sql_rows(*, limit: int, order: str, notes: list[str]) -> list[TopSqlRow]:
    primary_sql = ENRICHED_TOP_SQL_ELAPSED_SQL if order == "elapsed" else ENRICHED_TOP_SQL_CPU_SQL
    fallback_sql = LEGACY_TOP_SQL_ELAPSED_SQL if order == "elapsed" else LEGACY_TOP_SQL_CPU_SQL

    rows: list[dict[str, Any]] = []
    try:
        rows = fetch_all(primary_sql, {"lim": int(limit)})
    except Exception as exc:
        notes.append(f"enriched top SQL ({order}) unavailable: {exc}")

    if not rows:
        try:
            rows = fetch_all(fallback_sql, {"lim": int(limit)})
            if rows:
                notes.append(f"top SQL ({order}) used legacy fallback without session context.")
        except Exception as exc:
            notes.append(f"top SQL ({order}) fallback unavailable: {exc}")
            return []

    out: list[TopSqlRow] = []
    for row in rows:
        with_text = _attach_sql_text(row)
        enriched = _enrich_top_sql_row(with_text)
        out.append(TopSqlRow(**enriched))
    return out


def _enrich_top_sql_row(row: dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    executions = _as_int(data.get("executions"))

    data["ela_per_exec_s"] = _first_float(data.get("ela_per_exec_s"), _per_exec(data.get("elapsed_s"), executions))
    data["cpu_per_exec_s"] = _first_float(data.get("cpu_per_exec_s"), _per_exec(data.get("cpu_s"), executions))
    data["buffer_gets_per_exec"] = _first_float(data.get("buffer_gets_per_exec"), _per_exec(data.get("buffer_gets"), executions))
    data["disk_reads_per_exec"] = _first_float(data.get("disk_reads_per_exec"), _per_exec(data.get("disk_reads"), executions))
    data["rows_processed_per_exec"] = _first_float(data.get("rows_processed_per_exec"), _per_exec(data.get("rows_processed"), executions))

    if not data.get("parsing_schema_name") and data.get("username"):
        data["parsing_schema_name"] = data.get("username")

    sql_classification = _classify_top_sql(data)
    data["sql_classification"] = sql_classification
    data["workload_interpretation"] = _top_sql_workload_interpretation(data, sql_classification=sql_classification)
    return data


def _classify_top_sql(row: dict[str, Any]) -> str:
    schema = str(row.get("parsing_schema_name") or row.get("username") or "").upper()
    module = str(row.get("module") or "").lower()
    sql_text = str(row.get("sql_text") or "").lower()

    if schema in {"SYS", "SYSTEM"} and ("scheduler" in module or "dbms_scheduler" in sql_text or "sys.job" in sql_text):
        return "internal scheduler workload"
    if schema in {"SYS", "SYSTEM"}:
        return "oracle_internal_sql"
    if any(token in sql_text for token in (" dba_", " v$", " gv$", " x$", " sys.")):
        return "dictionary_sql"
    if any(token in module for token in ("rman", "datapump", "dbms_stats", "scheduler")):
        return "maintenance_sql"
    return "application_sql"


def _top_sql_workload_interpretation(row: dict[str, Any], *, sql_classification: str) -> str:
    execs = _as_int(row.get("executions")) or 0
    elapsed_s = _as_float(row.get("elapsed_s")) or 0.0
    cpu_s = _as_float(row.get("cpu_s")) or 0.0
    ela_per_exec = _as_float(row.get("ela_per_exec_s")) or 0.0
    cpu_per_exec = _as_float(row.get("cpu_per_exec_s")) or 0.0
    lio_per_exec = _as_float(row.get("buffer_gets_per_exec")) or 0.0
    pio_per_exec = _as_float(row.get("disk_reads_per_exec")) or 0.0

    if sql_classification == "internal scheduler workload":
        return "internal scheduler workload"
    if execs >= 1000 and ela_per_exec <= 0.02 and cpu_per_exec <= 0.01:
        return "high-frequency lightweight"
    if execs <= 20 and ela_per_exec >= 1.0:
        return "low-frequency but expensive"
    if lio_per_exec >= 100000:
        return "high logical I/O per exec"
    if pio_per_exec >= 500:
        return "likely I/O-heavy"
    if elapsed_s > 0 and cpu_s / elapsed_s >= 0.7 and cpu_per_exec >= 0.2:
        return "likely CPU-heavy"
    if sql_classification in {"oracle_internal_sql", "maintenance_sql", "dictionary_sql"}:
        return sql_classification
    return "likely application SQL"


def _derive_issues(snapshot: HealthSnapshot) -> list[HealthIssue]:
    issues: list[HealthIssue] = []
    for item in snapshot.actionable_items:
        issues.append(
            HealthIssue(
                category=item.category,
                title=item.title,
                severity=item.severity,
                description=item.detail,
                evidence=item.evidence,
                recommendation=item.recommendation,
            )
        )

    if snapshot.blocking_chains:
        issues.append(
            HealthIssue(
                category="blocking",
                title="Blocking sessions detected",
                severity="CRITICAL",
                description=f"Detected {len(snapshot.blocking_chains)} blocking chain(s).",
                evidence=[f"Blocker SID {c.blocker_sid} blocking SID {c.blocked_sid}" for c in snapshot.blocking_chains[:3]],
                recommendation="Review the blocker SQL_ID and kill only after operator confirmation.",
            )
        )

    if snapshot.tablespaces and snapshot.tablespaces[0].used_pct >= 90:
        ts = snapshot.tablespaces[0]
        issues.append(
            HealthIssue(
                category="tablespace",
                title=f"Tablespace {ts.tablespace_name} is nearly full",
                severity="CRITICAL" if ts.used_pct >= 95 else "WARNING",
                description=f"Tablespace usage is {ts.used_pct:.1f}%.",
                evidence=[f"Used {ts.used_mb} MB of {ts.total_mb} MB"],
                recommendation="Review growth pattern and extend storage if appropriate.",
            )
        )

    window_alerts = snapshot.raw_evidence.get("alert_log") or []
    if window_alerts:
        issues.append(
            HealthIssue(
                category="errors",
                title="Recent ORA/TNS errors found",
                severity="WARNING",
                description=f"Found {len(window_alerts)} ORA/TNS alert-log row(s) in the health window.",
                evidence=[str(row.get("message") or row) for row in window_alerts[:3]],
                recommendation="Correlate the errors with session, listener, and workload spikes.",
            )
        )

    if snapshot.top_sql_by_cpu:
        top = snapshot.top_sql_by_cpu[0]
        issues.append(
            HealthIssue(
                category="sql",
                title=f"SQL_ID {top.sql_id} is a top CPU consumer",
                severity="WARNING",
                description="A single SQL appears prominently in current SQL statistics.",
                evidence=[
                    f"schema={top.parsing_schema_name or top.username}",
                    f"cpu_s={top.cpu_s}, elapsed_s={top.elapsed_s}, executions={top.executions}",
                    f"cpu_per_exec_s={top.cpu_per_exec_s}, workload={top.workload_interpretation}",
                ],
                recommendation="Run SQL_ID deep dive to inspect plan hash, waits, and AWR history.",
            )
        )

    return issues


def _reconcile_lock_section(snapshot: HealthSnapshot) -> None:
    blocking = snapshot.blocking_chains or []
    if not blocking:
        return
    lock_section: HealthCheckSection | None = None
    for section in snapshot.health_sections:
        if section.name == "Locks And Blocking":
            lock_section = section
            break
    if lock_section is None:
        snapshot.health_sections.append(
            HealthCheckSection(
                name="Locks And Blocking",
                status="CRITICAL",
                summary=f"{len(blocking)} blocked session(s) detected.",
                rows=[_blocking_chain_row(chain) for chain in blocking[:10]],
            )
        )
        return
    if lock_section.status != "CRITICAL":
        lock_section.status = "CRITICAL"
    lock_section.summary = f"{len(blocking)} blocked session(s) detected."
    if not lock_section.rows:
        lock_section.rows = [_blocking_chain_row(chain) for chain in blocking[:10]]
    note = "Status reconciled with blocking_chains snapshot."
    if note not in lock_section.notes:
        lock_section.notes.append(note)


def _blocking_chain_row(chain) -> dict[str, Any]:
    return {
        "waiter_sid": chain.blocked_sid,
        "waiter_serial": chain.blocked_serial,
        "waiter_user": chain.blocked_user,
        "waiter_sql_id": chain.blocked_sql_id,
        "waiter_event": chain.event,
        "seconds_in_wait": chain.seconds_in_wait,
        "blocker_sid": chain.blocker_sid,
        "blocker_serial": chain.blocker_serial,
        "blocker_user": chain.blocker_user,
        "blocker_sql_id": chain.blocker_sql_id,
        "blocker_program": chain.blocker_program,
        "blocker_module": chain.blocker_module,
        "blocker_machine": chain.blocker_machine,
        "blocker_classification": chain.blocker_classification,
        "blocked_session_count": chain.blocked_session_count,
        "max_blocked_wait_seconds": chain.max_blocked_wait_seconds,
        "object_owner": chain.object_owner,
        "object_name": chain.object_name,
        "object_type": chain.object_type,
    }


def _health_window_hours() -> int:
    try:
        return max(int(os.getenv("ODB_AUTODBA_HEALTH_WINDOW_HOURS", "24")), 1)
    except Exception:
        return 24


def _correlate_host_hotspots_with_db(
    host: HostSnapshot,
    *,
    notes: list[str],
    top_sql_by_cpu: list[TopSqlRow],
    top_session_candidates: list[dict[str, Any]],
    top_pga_candidates: list[dict[str, Any]],
) -> HostSnapshot:
    _apply_hotspot_correlation(
        host.cpu_hotspot,
        notes=notes,
        metric="cpu",
        top_sql_by_cpu=top_sql_by_cpu,
        top_session_candidates=top_session_candidates,
        top_pga_candidates=top_pga_candidates,
    )
    _apply_hotspot_correlation(
        host.memory_hotspot,
        notes=notes,
        metric="memory",
        top_sql_by_cpu=top_sql_by_cpu,
        top_session_candidates=top_session_candidates,
        top_pga_candidates=top_pga_candidates,
    )
    return host


def _apply_hotspot_correlation(
    hotspot,
    *,
    notes: list[str],
    metric: str,
    top_sql_by_cpu: list[TopSqlRow],
    top_session_candidates: list[dict[str, Any]],
    top_pga_candidates: list[dict[str, Any]],
) -> None:
    if not hotspot.triggered or not hotspot.top_processes:
        return
    mapped_rows, mapped_count, mapping_notes = map_top_processes_to_sessions(hotspot.top_processes)
    hotspot.top_processes = mapped_rows
    hotspot.correlation_success_count = mapped_count
    attempted_count = len(mapped_rows)
    correlated_rows = _oracle_correlated_hotspot_rows(mapped_rows)
    sql_candidates = _oracle_hotspot_candidates(
        metric=metric,
        top_sql_by_cpu=top_sql_by_cpu,
        top_session_candidates=top_session_candidates,
        top_pga_candidates=top_pga_candidates,
    )
    confidence = _hotspot_correlation_confidence(
        attempted_count=attempted_count,
        mapped_count=mapped_count,
        has_candidates=bool(sql_candidates),
    )
    ratio = (float(mapped_count) / float(attempted_count)) if attempted_count > 0 else 0.0
    summary = HotspotCorrelationSummary(
        attempted_count=attempted_count,
        correlation_success_count=mapped_count,
        correlation_ratio=round(ratio, 2),
        correlation_confidence=confidence,
        top_oracle_candidate_sql_ids=[candidate.sql_id for candidate in sql_candidates if candidate.sql_id][:5],
        notes=list(mapping_notes),
    )
    hotspot.oracle_correlated_rows = correlated_rows
    hotspot.oracle_candidate_sql = sql_candidates
    hotspot.correlation_confidence = confidence
    hotspot.correlation_summary = summary

    hotspot.notes.extend(mapping_notes)
    if confidence == "high":
        hotspot.notes.append(f"Correlation confidence is high ({mapped_count}/{attempted_count} sampled processes mapped).")
    elif confidence == "medium":
        hotspot.notes.append(f"Correlation confidence is medium ({mapped_count}/{attempted_count} sampled processes mapped).")
    elif confidence == "low":
        hotspot.notes.append(
            "Correlation confidence is low: direct OS-to-session mapping was incomplete, but Oracle-side SQL/session candidates are available."
        )
    else:
        hotspot.notes.append("Correlation confidence is none: no direct Oracle mapping or Oracle-side candidates were available.")

    candidate_notes = _oracle_candidate_notes(sql_candidates)
    hotspot.notes.extend(candidate_notes[:4])
    notes.extend(mapping_notes + candidate_notes[:2])

    if mapped_count > 0:
        hotspot.interpretation = (
            f"{hotspot.interpretation} Correlated {mapped_count}/{attempted_count} sampled process(es) to Oracle session and SQL context."
        ).strip()
    elif sql_candidates:
        hotspot.interpretation = (
            f"{hotspot.interpretation} Direct OS-to-session mapping was incomplete, but Oracle SQL/session candidates indicate {metric.upper()} pressure."
        ).strip()
    else:
        hotspot.interpretation = (
            f"{hotspot.interpretation} No Oracle session correlation was found for sampled SPIDs and no fallback Oracle candidates were identified."
        ).strip()

    container_cpu = _as_float(getattr(hotspot, "container_cpu_pct", None))
    host_cpu = _as_float(getattr(hotspot, "host_cpu_pct", None))
    if metric == "cpu" and container_cpu is not None and container_cpu >= 85.0 and (host_cpu is None or host_cpu < 70.0):
        hotspot.notes.append(
            "Container CPU is critically high despite moderate host CPU, suggesting localized DB/container pressure rather than host-wide saturation."
        )


def _build_hotspot_sections(host: HostSnapshot) -> list[HealthCheckSection]:
    sections: list[HealthCheckSection] = []
    if host.cpu_hotspot.triggered:
        sections.append(_cpu_hotspot_section(host))
    if host.memory_hotspot.triggered:
        sections.append(_memory_hotspot_section(host))
    return sections


def _oracle_correlated_hotspot_rows(processes: list[HostProcessRow]) -> list[HotspotProcessRow]:
    rows: list[HotspotProcessRow] = []
    for process in processes:
        if not process.session_correlations:
            continue
        for session in process.session_correlations[:3]:
            rows.append(
                HotspotProcessRow(
                    os_pid=process.pid,
                    spid=process.spid,
                    sid=session.sid,
                    serial_num=session.serial_num,
                    inst_id=session.inst_id,
                    username=session.username,
                    status=session.status,
                    sql_id=session.sql_id,
                    event=session.event,
                    wait_class=session.wait_class,
                    module=session.module,
                    program=session.program,
                    machine=session.machine,
                    osuser=session.osuser,
                    cpu_pct=process.cpu_pct,
                    memory_pct=process.memory_pct,
                    rss_mb=process.rss_mb,
                    pga_used_mb=session.pga_used_mb,
                    pga_alloc_mb=session.pga_alloc_mb,
                    temp_used_mb=session.temp_used_mb,
                    process_group=process.process_group,
                )
            )
    return rows[:12]


def _oracle_hotspot_candidates(
    *,
    metric: str,
    top_sql_by_cpu: list[TopSqlRow],
    top_session_candidates: list[dict[str, Any]],
    top_pga_candidates: list[dict[str, Any]],
) -> list[OracleHotspotCandidate]:
    candidates: list[OracleHotspotCandidate] = []
    for row in top_sql_by_cpu[:5]:
        candidates.append(
            OracleHotspotCandidate(
                sql_id=row.sql_id,
                username=row.parsing_schema_name or row.username,
                module=row.module,
                program=row.program,
                sql_classification=row.sql_classification,
                workload_interpretation=row.workload_interpretation,
                cpu_s=row.cpu_s,
                cpu_per_exec_s=row.cpu_per_exec_s,
                elapsed_s=row.elapsed_s,
                ela_per_exec_s=row.ela_per_exec_s,
                source="top_sql_by_cpu",
            )
        )

    if metric == "memory":
        for row in (top_pga_candidates or [])[:5]:
            candidates.append(
                OracleHotspotCandidate(
                    sql_id=_nullable_text(row.get("sql_id")),
                    username=_nullable_text(row.get("username")),
                    module=_nullable_text(row.get("module")),
                    program=_nullable_text(row.get("program")),
                    workload_interpretation="top_pga_session",
                    source="top_pga_sessions",
                )
            )
    for row in (top_session_candidates or [])[:5]:
        candidates.append(
            OracleHotspotCandidate(
                sql_id=_nullable_text(row.get("sql_id")),
                username=_nullable_text(row.get("username")),
                module=_nullable_text(row.get("module")),
                program=_nullable_text(row.get("program")),
                workload_interpretation="top_session_resource_candidate",
                source="top_session_resources",
            )
        )
    deduped: list[OracleHotspotCandidate] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        key = (
            str(candidate.sql_id or ""),
            str(candidate.username or ""),
            str(candidate.source or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped[:8]


def _hotspot_correlation_confidence(*, attempted_count: int, mapped_count: int, has_candidates: bool) -> str:
    if attempted_count <= 0:
        return "none"
    if mapped_count <= 0:
        return "low" if has_candidates else "none"
    ratio = float(mapped_count) / float(attempted_count)
    if ratio >= 0.8:
        return "high"
    return "medium"


def _oracle_candidate_notes(candidates: list[OracleHotspotCandidate]) -> list[str]:
    notes: list[str] = []
    for candidate in candidates[:3]:
        if not candidate.sql_id:
            continue
        notes.append(
            "Oracle candidate SQL "
            f"{candidate.sql_id} user={candidate.username or '-'} module={candidate.module or '-'} "
            f"program={candidate.program or '-'} cpu_per_exec={candidate.cpu_per_exec_s if candidate.cpu_per_exec_s is not None else '-'} "
            f"class={candidate.sql_classification or '-'} source={candidate.source}."
        )
    return notes


def _cpu_hotspot_section(host: HostSnapshot) -> HealthCheckSection:
    hotspot = host.cpu_hotspot
    status = "CRITICAL" if (hotspot.host_cpu_pct or 0) >= 85 or (hotspot.container_cpu_pct or 0) >= 85 else "WARNING"
    rows = _flatten_hotspot_process_rows(hotspot.top_processes)
    rows.extend(_hotspot_candidate_rows(hotspot.oracle_candidate_sql, metric="cpu"))
    summary = (
        f"CPU hotspot triggered (host={_fmt_pct(hotspot.host_cpu_pct)}, container={_fmt_pct(hotspot.container_cpu_pct)}). "
        f"Correlated {hotspot.correlation_success_count}/{len(hotspot.top_processes)} sampled process(es) to Oracle sessions "
        f"(confidence={hotspot.correlation_confidence})."
    )
    notes = [
        hotspot.interpretation,
        (
            f"Correlation summary: success={hotspot.correlation_summary.correlation_success_count}/"
            f"{hotspot.correlation_summary.attempted_count}, "
            f"confidence={hotspot.correlation_summary.correlation_confidence}, "
            f"candidate_sql_ids={','.join(hotspot.correlation_summary.top_oracle_candidate_sql_ids) or 'none'}."
        ),
        f"Top Oracle foreground: {hotspot.top_oracle_foreground or 'n/a'}",
        f"Top Oracle background: {hotspot.top_oracle_background or 'n/a'}",
        f"Top non-Oracle: {hotspot.top_non_oracle or 'n/a'}",
    ] + list(hotspot.notes)
    return HealthCheckSection(name="CPU Hotspots", status=status, summary=summary, rows=rows[:20], notes=[note for note in notes if note])


def _memory_hotspot_section(host: HostSnapshot) -> HealthCheckSection:
    hotspot = host.memory_hotspot
    status = "CRITICAL" if (hotspot.host_memory_pct or 0) >= 90 or (hotspot.container_memory_pct or 0) >= 90 else "WARNING"
    rows = _flatten_hotspot_process_rows(hotspot.top_processes)
    rows.extend(_hotspot_candidate_rows(hotspot.oracle_candidate_sql, metric="memory"))
    summary = (
        f"Memory hotspot triggered (host={_fmt_pct(hotspot.host_memory_pct)}, container={_fmt_pct(hotspot.container_memory_pct)}). "
        f"Correlated {hotspot.correlation_success_count}/{len(hotspot.top_processes)} sampled process(es) to Oracle sessions "
        f"(confidence={hotspot.correlation_confidence})."
    )
    notes = [
        hotspot.interpretation,
        (
            f"Correlation summary: success={hotspot.correlation_summary.correlation_success_count}/"
            f"{hotspot.correlation_summary.attempted_count}, "
            f"confidence={hotspot.correlation_summary.correlation_confidence}, "
            f"candidate_sql_ids={','.join(hotspot.correlation_summary.top_oracle_candidate_sql_ids) or 'none'}."
        ),
        f"Top Oracle foreground: {hotspot.top_oracle_foreground or 'n/a'}",
        f"Top Oracle background: {hotspot.top_oracle_background or 'n/a'}",
        f"Top non-Oracle: {hotspot.top_non_oracle or 'n/a'}",
    ] + list(hotspot.notes)
    return HealthCheckSection(name="Memory Hotspots", status=status, summary=summary, rows=rows[:20], notes=[note for note in notes if note])


def _flatten_hotspot_process_rows(processes: list[HostProcessRow]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for process in processes:
        base = {
            "row_type": "os_sample",
            "os_pid": process.pid,
            "spid": process.spid,
            "process_group": process.process_group,
            "process_name": process.process_name,
            "oracle_process_type": process.oracle_process_type_guess,
            "cpu_pct": process.cpu_pct,
            "memory_pct": process.memory_pct,
            "rss_mb": process.rss_mb,
            "vsz_mb": process.vsz_mb,
            "swap_mb": process.swap_mb,
            "command": process.command,
        }
        if process.session_correlations:
            for session in process.session_correlations[:2]:
                rows.append(
                    {
                        **base,
                        "inst_id": session.inst_id,
                        "sid": session.sid,
                        "serial_num": session.serial_num,
                        "username": session.username,
                        "status": session.status,
                        "sql_id": session.sql_id,
                        "event": session.event,
                        "wait_class": session.wait_class,
                        "module": session.module,
                        "program": session.program,
                        "machine": session.machine,
                        "osuser": session.osuser,
                        "pga_used_mb": session.pga_used_mb,
                        "pga_alloc_mb": session.pga_alloc_mb,
                        "temp_used_mb": session.temp_used_mb,
                        "logon_time": session.logon_time,
                    }
                )
        else:
            rows.append(base)
    return rows


def _hotspot_candidate_rows(candidates: list[OracleHotspotCandidate], *, metric: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for candidate in candidates[:4]:
        rows.append(
            {
                "row_type": f"oracle_{metric}_candidate",
                "sql_id": candidate.sql_id,
                "username": candidate.username,
                "module": candidate.module,
                "program": candidate.program,
                "cpu_s": candidate.cpu_s,
                "cpu_per_exec_s": candidate.cpu_per_exec_s,
                "elapsed_s": candidate.elapsed_s,
                "ela_per_exec_s": candidate.ela_per_exec_s,
                "sql_classification": candidate.sql_classification,
                "workload_interpretation": candidate.workload_interpretation,
                "source": candidate.source,
            }
        )
    return rows


def _host_health_section(host: HostSnapshot) -> HealthCheckSection:
    statuses = [
        _pct_status(host.cpu_pct, warn=60, crit=85),
        _pct_status(host.memory_pct, warn=70, crit=90),
        _pct_status(host.swap_pct, warn=50, crit=80),
    ]
    docker_cpu = _as_float((host.docker_stats or {}).get("cpu_pct"))
    docker_mem = _as_float((host.docker_stats or {}).get("memory_pct"))
    if docker_cpu is not None:
        statuses.append(_pct_status(docker_cpu, warn=60, crit=85))
    if docker_mem is not None:
        statuses.append(_pct_status(docker_mem, warn=70, crit=90))
    status = _worst_status(statuses)

    rows: list[dict[str, Any]] = [
        {
            "scope": "host",
            "cpu_pct": host.cpu_pct,
            "memory_pct": host.memory_pct,
            "swap_pct": host.swap_pct,
            "load_average": host.load_average,
        }
    ]
    if host.docker_stats:
        rows.append({"scope": "oracle_container", "container": host.docker_container, **host.docker_stats})
    rows.append(
        {
            "scope": "hotspot_analysis",
            "cpu_hotspot_triggered": host.cpu_hotspot.triggered,
            "memory_hotspot_triggered": host.memory_hotspot.triggered,
            "cpu_correlation_success": host.cpu_hotspot.correlation_success_count,
            "memory_correlation_success": host.memory_hotspot.correlation_success_count,
            "cpu_correlation_confidence": host.cpu_hotspot.correlation_confidence,
            "memory_correlation_confidence": host.memory_hotspot.correlation_confidence,
            "top_oracle_fg_cpu": host.cpu_hotspot.top_oracle_foreground,
            "top_oracle_bg_cpu": host.cpu_hotspot.top_oracle_background,
            "top_non_oracle_cpu": host.cpu_hotspot.top_non_oracle,
            "top_oracle_fg_mem": host.memory_hotspot.top_oracle_foreground,
            "top_oracle_bg_mem": host.memory_hotspot.top_oracle_background,
            "top_non_oracle_mem": host.memory_hotspot.top_non_oracle,
        }
    )
    rows.extend({"scope": "filesystem", **row} for row in host.filesystems[:10])

    summary = f"Host CPU={_fmt_pct(host.cpu_pct)}, memory={_fmt_pct(host.memory_pct)}, swap={_fmt_pct(host.swap_pct)}."
    if host.docker_container:
        summary += f" Oracle container {host.docker_container} CPU={_fmt_pct(docker_cpu)}, memory={_fmt_pct(docker_mem)}."
    else:
        summary += " Oracle Docker container was not detected."
    summary += (
        f" Hotspot analysis: CPU={'triggered' if host.cpu_hotspot.triggered else 'normal'}, "
        f"memory={'triggered' if host.memory_hotspot.triggered else 'normal'}."
    )
    if docker_cpu is not None and docker_cpu >= 85.0 and (host.cpu_pct is None or host.cpu_pct < 70.0):
        summary += (
            " Container CPU is critically high despite moderate host CPU, suggesting localized DB/container pressure rather than host-wide saturation."
        )

    notes = list(host.notes)
    notes.append(host.cpu_hotspot.interpretation)
    notes.append(host.memory_hotspot.interpretation)
    notes.append(
        f"CPU hotspot correlation confidence={host.cpu_hotspot.correlation_confidence}, "
        f"memory hotspot correlation confidence={host.memory_hotspot.correlation_confidence}."
    )
    if host.mount_points:
        notes.append("Host mount and inode details captured in raw evidence.")
    return HealthCheckSection(name="Host And OS", status=status, summary=summary, rows=rows, notes=[note for note in notes if note])


def _host_actionable_items(host: HostSnapshot) -> list[ActionableHealthItem]:
    items: list[ActionableHealthItem] = []
    for label, value, warn, crit in (
        ("Host CPU utilization", host.cpu_pct, 60, 85),
        ("Host memory utilization", host.memory_pct, 70, 90),
        ("Host swap utilization", host.swap_pct, 50, 80),
    ):
        status = _pct_status(value, warn=warn, crit=crit)
        if status in {"WARNING", "CRITICAL"}:
            items.append(
                ActionableHealthItem(
                    category="host",
                    title=label,
                    severity=status,
                    detail=f"{label} is {_fmt_pct(value)}.",
                    recommendation="Correlate OS pressure with top Oracle sessions, SQL, and container/process data.",
                    evidence=[str(row.model_dump(mode="json")) for row in host.top_processes[:3]],
                )
            )

    docker_cpu = _as_float((host.docker_stats or {}).get("cpu_pct"))
    docker_mem = _as_float((host.docker_stats or {}).get("memory_pct"))
    for label, value, warn, crit in (
        ("Oracle container CPU utilization", docker_cpu, 60, 85),
        ("Oracle container memory utilization", docker_mem, 70, 90),
    ):
        status = _pct_status(value, warn=warn, crit=crit)
        if status in {"WARNING", "CRITICAL"}:
            items.append(
                ActionableHealthItem(
                    category="host",
                    title=label,
                    severity=status,
                    detail=f"{label} is {_fmt_pct(value)}.",
                    recommendation="Review container limits, Oracle processes, and DB session resource consumers.",
                )
            )

    if host.cpu_hotspot.triggered:
        items.append(
                ActionableHealthItem(
                    category="host",
                    title="CPU hotspots detected",
                    severity=("CRITICAL" if (host.cpu_hotspot.host_cpu_pct or 0) >= 85 else "WARNING"),
                    detail=host.cpu_hotspot.interpretation,
                    recommendation="Review top OS CPU consumers and correlated Oracle SQL/session context.",
                    evidence=[str(row) for row in _flatten_hotspot_process_rows(host.cpu_hotspot.top_processes)[:5]],
                )
            )

    if host.memory_hotspot.triggered:
        items.append(
                ActionableHealthItem(
                    category="host",
                    title="Memory hotspots detected",
                    severity=("CRITICAL" if (host.memory_hotspot.host_memory_pct or 0) >= 90 else "WARNING"),
                    detail=host.memory_hotspot.interpretation,
                    recommendation="Review top OS memory consumers and correlated Oracle SQL/session context.",
                    evidence=[str(row) for row in _flatten_hotspot_process_rows(host.memory_hotspot.top_processes)[:5]],
                )
            )

    return items


def _apply_tablespace_allocation_anomaly(snapshot: HealthSnapshot) -> None:
    alert_rows = list(snapshot.raw_evidence.get("alert_log") or [])
    tablespaces = snapshot.tablespaces or []
    anomaly = _tablespace_allocation_anomaly(alert_rows=alert_rows, tablespaces=tablespaces)
    snapshot.raw_evidence["tablespace_allocation_anomaly"] = anomaly.model_dump(mode="json")
    if not anomaly.tablespace_allocation_failure_with_low_pct:
        return
    note = anomaly.interpretation
    for section in snapshot.health_sections:
        if section.name in {"Tablespace Usage", "Alert Log Errors"} and note not in section.notes:
            section.notes.append(note)
    snapshot.notes.append(note)


def _tablespace_allocation_anomaly(
    *,
    alert_rows: list[dict[str, Any]],
    tablespaces: list[TablespaceUsageRow],
) -> TablespaceAllocationAnomaly:
    ora_1653_rows = [row for row in alert_rows if str(row.get("code") or "").upper() == "ORA-01653"]
    highest_used_pct = max((float(row.used_pct) for row in tablespaces), default=0.0) if tablespaces else None
    if not ora_1653_rows:
        return TablespaceAllocationAnomaly(
            tablespace_allocation_failure_with_low_pct=False,
            highest_used_pct=highest_used_pct,
        )

    sample_message = str((ora_1653_rows[0] or {}).get("message") or "")
    tablespace_name = _extract_tablespace_name_from_ora_1653(sample_message)
    low_pct = highest_used_pct is None or highest_used_pct < 80.0
    interpretation = (
        "Overall tablespace usage is low, but allocation failure was reported; review autoextend, maxsize, free extents, and quota."
        if low_pct
        else "Allocation failure was reported; review datafile autoextend/maxsize and segment extent allocation."
    )
    return TablespaceAllocationAnomaly(
        tablespace_allocation_failure_with_low_pct=low_pct,
        error_code="ORA-01653",
        tablespace_name=tablespace_name,
        highest_used_pct=highest_used_pct,
        interpretation=interpretation,
        evidence=[sample_message] + [str(row.get("message") or "") for row in ora_1653_rows[1:3]],
    )


def _extract_tablespace_name_from_ora_1653(message: str) -> str | None:
    text = str(message or "")
    match = re.search(r"in tablespace\s+([A-Za-z0-9_#$]+)", text, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1).upper()


def _apply_lock_wait_interpretation(snapshot: HealthSnapshot) -> None:
    has_blockers = bool(snapshot.blocking_chains)
    lock_wait_rows = _lock_wait_rows(snapshot)
    note_obj = _blocking_interpretation_note(lock_wait_rows=lock_wait_rows, has_blockers=has_blockers)
    snapshot.raw_evidence["blocking_interpretation"] = note_obj.model_dump(mode="json")
    if not note_obj.note:
        return
    for section in snapshot.health_sections:
        if section.name in {"Locks And Blocking", "Current Wait Profile", "AWR Wait Events"} and note_obj.note not in section.notes:
            section.notes.append(note_obj.note)
    snapshot.notes.append(note_obj.note)


def _lock_wait_rows(snapshot: HealthSnapshot) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for section in snapshot.health_sections:
        if section.name in {"Current Wait Profile", "AWR Wait Events"}:
            rows.extend(section.rows or [])
    return rows


def _blocking_interpretation_note(*, lock_wait_rows: list[dict[str, Any]], has_blockers: bool) -> BlockingInterpretationNote:
    lock_rows = [
        row
        for row in lock_wait_rows
        if "row lock contention" in str(row.get("event") or row.get("event_name") or "").lower()
    ]
    if not lock_rows:
        return BlockingInterpretationNote(lock_wait_observed=False, active_blocker_present=has_blockers)
    if has_blockers:
        return BlockingInterpretationNote(
            lock_wait_observed=True,
            active_blocker_present=True,
            note="Lock-related waits were observed and active blockers were captured in the live snapshot.",
            evidence=[str(row) for row in lock_rows[:3]],
        )
    return BlockingInterpretationNote(
        lock_wait_observed=True,
        active_blocker_present=False,
        note=(
            "Lock-related waits were observed, but no active blocker was present at collection time; "
            "blocking may have cleared before live capture."
        ),
        evidence=[str(row) for row in lock_rows[:3]],
    )


def _attach_sql_text(row: dict[str, Any]) -> dict[str, Any]:
    sql_id = row.get("sql_id")
    out = dict(row)
    out["sql_text"] = get_sql_text(sql_id) if sql_id else None
    return out


def enrich_host_snapshot_with_db_activity(host_snapshot: HostSnapshot | None, snapshot: HealthSnapshot) -> HostSnapshot | None:
    if host_snapshot is None:
        return None
    return _correlate_host_hotspots_with_db(
        host_snapshot,
        notes=snapshot.notes if snapshot else [],
        top_sql_by_cpu=(snapshot.top_sql_by_cpu if snapshot else []),
        top_session_candidates=(snapshot.raw_evidence.get("top_session_resource_candidates") if snapshot else []) or [],
        top_pga_candidates=((snapshot.raw_evidence.get("memory_config") or {}).get("top_pga_sessions") if snapshot else []) or [],
    )


def _pct_status(value: float | None, *, warn: float, crit: float) -> str:
    if value is None:
        return "INFO"
    if value >= crit:
        return "CRITICAL"
    if value >= warn:
        return "WARNING"
    return "OK"


def _worst_status(statuses: list[str]) -> str:
    rank = {"OK": 0, "INFO": 1, "WARNING": 2, "CRITICAL": 3}
    return max(statuses or ["INFO"], key=lambda status: rank.get(status, 1))


def _fmt_pct(value: Any) -> str:
    number = _as_float(value)
    return "unknown" if number is None else f"{number:.2f}%"


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None


def _per_exec(total: Any, executions: int | None) -> float | None:
    total_value = _as_float(total)
    if total_value is None or executions is None or executions <= 0:
        return None
    return round(total_value / float(executions), 6)


def _first_float(primary: Any, fallback: float | None) -> float | None:
    candidate = _as_float(primary)
    if candidate is not None:
        return candidate
    return fallback


def _nullable_text(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or text in {"-", "N/A"}:
        return None
    return text
