from __future__ import annotations

import os
import re
from typing import Any

from odb_autodba.db.connection import fetch_all, fetch_one
from odb_autodba.db.plan_checks import collect_formatted_execution_plan
from odb_autodba.db.sql_text import get_sql_text
from odb_autodba.models.schemas import (
    SqlClassification,
    SqlDbaRecommendation,
    SqlIdDeepDive,
    SqlImpactSummary,
    SqlWaitEventRow,
    SqlWaitProfile,
)
from odb_autodba.rag.trace_store import read_health_run_traces
from odb_autodba.utils.sql_analysis import extract_sql_id


WAIT_CLASS_BUCKETS = (
    ("user_io_pct", "User I/O"),
    ("system_io_pct", "System I/O"),
    ("concurrency_pct", "Concurrency"),
    ("cluster_pct", "Cluster"),
    ("commit_pct", "Commit"),
    ("configuration_pct", "Configuration"),
    ("application_pct", "Application"),
    ("network_pct", "Network"),
)

MAINTENANCE_TOKENS = (
    "dbms_stats",
    "gather_",
    "analyze ",
    "dbms_scheduler",
    "rman",
    "dbms_auto_task",
    "wri$_",
    "optstat",
)

DICTIONARY_TOKENS = (
    " dba_",
    " all_",
    " user_",
    " v$",
    " gv$",
    " x$",
    " sys.",
)

INTERNAL_MARKERS = (
    "/* sql analyze",
    "/*+ rule */",
    "ora$",
    "sys_op_",
    "sys_context",
)


def extract_queryid_from_text(text: str) -> str | None:
    return extract_sql_id(text)


def build_sql_id_deep_dive_report(sql_id: str, lookback_days: int = 30) -> SqlIdDeepDive:
    normalized_sql_id = (sql_id or "").strip().lower()
    notes: list[str] = []

    sql_text = get_sql_text(normalized_sql_id)
    current = _current_stats(normalized_sql_id, notes)
    children = _child_cursors(normalized_sql_id, notes)
    plan_lines = _plan_lines(normalized_sql_id, notes)
    ash = _ash_summary(normalized_sql_id, lookback_days, notes)
    awr = _awr_summary(normalized_sql_id, lookback_days, notes)

    active_queries = _active_queries(normalized_sql_id, notes)
    lock_analysis = _lock_analysis(normalized_sql_id, notes)
    wait_profile = collect_sql_wait_profile(
        sql_id=normalized_sql_id,
        active_queries=active_queries,
        lookback_days=lookback_days,
        notes=notes,
    )
    classification = classify_sql(
        sql_id=normalized_sql_id,
        sql_text=sql_text,
        current_stats=current,
        active_queries=active_queries,
    )
    history_analysis = _history_analysis(normalized_sql_id, notes)
    impact_summary = _impact_summary(
        current_stats=current,
        awr=awr,
        active_queries=active_queries,
        history_analysis=history_analysis,
    )
    execution_plan = collect_formatted_execution_plan(
        sql_id=normalized_sql_id,
        current_stats=current,
        child_cursors=children,
        awr=awr,
        raw_plan_lines=plan_lines,
    )
    plan_analysis = _plan_analysis(
        current=current,
        children=children,
        awr=awr,
        lookback_days=lookback_days,
        execution_plan=execution_plan.model_dump(mode="json"),
    )
    risk_summary = _risk_summary(
        active_queries=active_queries,
        lock_analysis=lock_analysis,
        plan_analysis=plan_analysis,
        history_analysis=history_analysis,
        wait_profile=wait_profile,
        impact_summary=impact_summary,
    )
    dba_recommendation = _dba_recommendation(
        classification=classification,
        wait_profile=wait_profile,
        impact_summary=impact_summary,
        lock_analysis=lock_analysis,
        plan_analysis=plan_analysis,
        risk_summary=risk_summary,
        awr=awr,
    )

    return SqlIdDeepDive(
        sql_id=normalized_sql_id,
        sql_text=sql_text,
        current_stats=current,
        child_cursors=children,
        plan_lines=plan_lines,
        ash=ash,
        awr=awr,
        active_queries=active_queries,
        wait_profile=wait_profile,
        classification=classification,
        impact_summary=impact_summary,
        execution_plan=execution_plan,
        lock_analysis=lock_analysis,
        plan_analysis=plan_analysis,
        history_analysis=history_analysis,
        risk_summary=risk_summary,
        dba_recommendation=dba_recommendation,
        notes=notes,
    )


def collect_sql_wait_profile(
    *,
    sql_id: str,
    active_queries: list[dict[str, Any]],
    lookback_days: int,
    notes: list[str],
) -> SqlWaitProfile:
    active_rows = [row for row in active_queries if str(row.get("status") or "").upper() == "ACTIVE"]
    if active_rows:
        return _live_wait_profile(active_rows)

    ash_profile = _ash_wait_profile(sql_id=sql_id, lookback_days=lookback_days, notes=notes)
    if ash_profile.available and ash_profile.sample_count > 0:
        return ash_profile

    awr_profile = _awr_wait_profile(sql_id=sql_id, lookback_days=lookback_days, notes=notes)
    if awr_profile.available and awr_profile.sample_count > 0:
        if ash_profile.available and ash_profile.sample_count == 0:
            awr_profile.notes.append("ASH had zero samples; using AWR ASH history for wait evidence.")
        return awr_profile

    if ash_profile.available:
        if ash_profile.sample_count == 0 and not ash_profile.interpretation:
            ash_profile.interpretation = (
                "No ASH wait-profile rows were captured. This can happen for short-lived SQL, "
                "low sampling hit rate, or low recent activity."
            )
        if awr_profile.available and awr_profile.sample_count == 0:
            ash_profile.notes.append("AWR ASH history also showed zero samples in the selected window.")
        return ash_profile

    if awr_profile.available:
        if awr_profile.sample_count == 0 and not awr_profile.interpretation:
            awr_profile.interpretation = (
                "Historical ASH wait-profile rows were not captured in AWR for this SQL_ID in the selected window."
            )
        return awr_profile

    return SqlWaitProfile(
        available=False,
        source_used=None,
        interpretation="No wait evidence could be collected (live sessions, ASH, and AWR ASH were unavailable).",
        notes=["Verify privileges for gv$session, v$active_session_history, and dba_hist_active_sess_history."],
    )


def classify_sql(
    *,
    sql_id: str,
    sql_text: str | None,
    current_stats: dict[str, Any],
    active_queries: list[dict[str, Any]],
) -> SqlClassification:
    schema = str(current_stats.get("parsing_schema_name") or "").upper()
    module = str(current_stats.get("module") or "")
    text = (sql_text or "").strip()
    lowered = text.lower()
    evidence: list[str] = []

    if schema:
        evidence.append(f"parsing_schema={schema}")
    if module:
        evidence.append(f"module={module}")

    if not text and not schema:
        return SqlClassification(
            classification="unknown",
            confidence="LOW",
            explanation="SQL text and parsing schema were not available.",
            evidence=evidence,
        )

    has_dictionary_pattern = any(token in lowered for token in DICTIONARY_TOKENS)
    has_maintenance_pattern = any(token in lowered for token in MAINTENANCE_TOKENS)
    has_internal_marker = any(marker in lowered for marker in INTERNAL_MARKERS)
    active_is_sys = any(str(row.get("username") or "").upper() in {"SYS", "SYSTEM"} for row in active_queries)

    if schema in {"SYS", "SYSTEM"} and has_dictionary_pattern:
        return SqlClassification(
            classification="dictionary_sql",
            confidence="HIGH",
            explanation="Parsed under SYS/SYSTEM and references dictionary/runtime objects.",
            evidence=evidence + ["dictionary object pattern in SQL text"],
        )
    if has_maintenance_pattern:
        confidence = "HIGH" if schema in {"SYS", "SYSTEM"} else "MEDIUM"
        return SqlClassification(
            classification="maintenance_sql",
            confidence=confidence,
            explanation="SQL text contains optimizer/statistics/maintenance markers.",
            evidence=evidence + ["maintenance keyword pattern matched"],
        )
    if schema in {"SYS", "SYSTEM"} and has_internal_marker:
        return SqlClassification(
            classification="recursive_sql",
            confidence="MEDIUM",
            explanation="SQL text includes internal recursive markers under SYS/SYSTEM.",
            evidence=evidence + ["internal marker detected"],
        )
    if schema in {"SYS", "SYSTEM"} or active_is_sys:
        return SqlClassification(
            classification="oracle_internal_sql",
            confidence="MEDIUM",
            explanation="SQL is associated with Oracle internal schema/session context.",
            evidence=evidence + (["active SYS/SYSTEM session context"] if active_is_sys else []),
        )
    if has_dictionary_pattern:
        return SqlClassification(
            classification="dictionary_sql",
            confidence="MEDIUM",
            explanation="SQL references dictionary/runtime objects from a non-SYS parsing schema.",
            evidence=evidence + ["dictionary object pattern in SQL text"],
        )
    if schema:
        return SqlClassification(
            classification="application_sql",
            confidence="HIGH",
            explanation="SQL appears to be application workload from non-SYS parsing schema.",
            evidence=evidence,
        )
    return SqlClassification(
        classification="unknown",
        confidence="LOW",
        explanation=f"Unable to classify SQL_ID {sql_id} confidently from available evidence.",
        evidence=evidence,
    )


def _current_stats(sql_id: str, notes: list[str]) -> dict[str, Any]:
    try:
        row = fetch_one(
            """
            select s.sql_id, s.plan_hash_value, s.executions,
                   round(s.elapsed_time/1e6,3) as elapsed_s,
                   round(s.cpu_time/1e6,3) as cpu_s,
                   round((s.elapsed_time/1e6)/nullif(s.executions,0), 6) as ela_per_exec_s,
                   s.buffer_gets, s.disk_reads, s.rows_processed,
                   to_char(s.last_active_time, 'YYYY-MM-DD HH24:MI:SS') as last_active_time,
                   (select max(q.parsing_schema_name) from v$sql q where q.sql_id = s.sql_id) as parsing_schema_name,
                   (select max(q.module) from v$sql q where q.sql_id = s.sql_id) as module
            from v$sqlstats s
            where s.sql_id = :sql_id
            fetch first 1 rows only
            """,
            {"sql_id": sql_id},
        )
        return row or {}
    except Exception as exc:
        notes.append(f"current_stats unavailable: {exc}")
        return {}


def _child_cursors(sql_id: str, notes: list[str]) -> list[dict[str, Any]]:
    try:
        return fetch_all(
            """
            select child_number, plan_hash_value, executions,
                   round(elapsed_time/1e6,3) as elapsed_s,
                   round(cpu_time/1e6,3) as cpu_s,
                   round((elapsed_time/1e6)/nullif(executions,0), 6) as ela_per_exec_s,
                   buffer_gets, disk_reads,
                   to_char(last_active_time, 'YYYY-MM-DD HH24:MI:SS') as last_active
            from v$sql
            where sql_id = :sql_id
            order by elapsed_time desc
            fetch first 20 rows only
            """,
            {"sql_id": sql_id},
        )
    except Exception as exc:
        notes.append(f"child_cursors unavailable: {exc}")
        return []


def _plan_lines(sql_id: str, notes: list[str]) -> list[dict[str, Any]]:
    try:
        return fetch_all(
            """
            select id, parent_id, lpad(' ', depth*2) || operation as operation,
                   options, object_owner, object_name, object_type,
                   cardinality, cost, bytes
            from v$sql_plan
            where sql_id = :sql_id
            order by id
            """,
            {"sql_id": sql_id},
            max_rows=250,
        )
    except Exception as exc:
        notes.append(f"plan_lines unavailable: {exc}")
        return []


def _ash_summary(sql_id: str, lookback_days: int, notes: list[str]) -> dict[str, Any]:
    try:
        summary = fetch_one(
            """
            select count(*) as samples,
                   round(100 * sum(case when session_state = 'ON CPU' then 1 else 0 end) / nullif(count(*),0), 1) as oncpu_pct
            from v$active_session_history
            where sample_time > sysdate - (:days)
              and sql_id = :sql_id
            """,
            {"days": lookback_days, "sql_id": sql_id},
        ) or {}
        waits = fetch_all(
            """
            select nvl(event, 'ON CPU') as event, count(*) as samples
            from v$active_session_history
            where sample_time > sysdate - (:days)
              and sql_id = :sql_id
            group by nvl(event, 'ON CPU')
            order by samples desc
            fetch first 8 rows only
            """,
            {"days": lookback_days, "sql_id": sql_id},
        )
        samples = int(summary.get("samples") or 0)
        interpretation = ""
        if samples == 0:
            interpretation = (
                "No ASH wait-profile rows were captured. This can happen for short-lived SQL, "
                "low sampling hit rate, or low recent activity."
            )
        return {
            "available": True,
            "samples": samples,
            "oncpu_pct": _as_float(summary.get("oncpu_pct")),
            "top_waits": waits,
            "lookback_days": lookback_days,
            "interpretation": interpretation,
        }
    except Exception as exc:
        notes.append(f"ash unavailable: {exc}")
        return {"available": False, "error": str(exc), "top_waits": []}


def _awr_summary(sql_id: str, lookback_days: int, notes: list[str]) -> dict[str, Any]:
    try:
        plan_changes = fetch_all(
            """
            select t.plan_hash_value,
                   sum(t.executions_delta) as execs,
                   round(sum(t.elapsed_time_delta)/1e6, 3) as elapsed_s,
                   round(sum(t.cpu_time_delta)/1e6, 3) as cpu_s,
                   sum(t.buffer_gets_delta) as buffer_gets,
                   sum(t.disk_reads_delta) as disk_reads,
                   sum(t.rows_processed_delta) as rows_processed,
                   round((sum(t.elapsed_time_delta)/nullif(sum(t.executions_delta),0))/1e6, 6) as ela_per_exec_s,
                   min(to_char(s.begin_interval_time, 'YYYY-MM-DD HH24:MI:SS')) as first_seen,
                   max(to_char(s.end_interval_time, 'YYYY-MM-DD HH24:MI:SS')) as last_seen
            from dba_hist_sqlstat t
            join dba_hist_snapshot s
              on s.snap_id = t.snap_id and s.dbid = t.dbid and s.instance_number = t.instance_number
            where t.sql_id = :sql_id
              and s.begin_interval_time > sysdate - (:days)
            group by t.plan_hash_value
            order by elapsed_s desc
            fetch first 10 rows only
            """,
            {"sql_id": sql_id, "days": lookback_days},
        )
        totals = fetch_one(
            """
            select sum(t.executions_delta) as executions,
                   round(sum(t.elapsed_time_delta)/1e6, 3) as elapsed_s,
                   round(sum(t.cpu_time_delta)/1e6, 3) as cpu_s,
                   sum(t.buffer_gets_delta) as buffer_gets,
                   sum(t.disk_reads_delta) as disk_reads,
                   sum(t.rows_processed_delta) as rows_processed
            from dba_hist_sqlstat t
            join dba_hist_snapshot s
              on s.snap_id = t.snap_id and s.dbid = t.dbid and s.instance_number = t.instance_number
            where t.sql_id = :sql_id
              and s.begin_interval_time > sysdate - (:days)
            """,
            {"sql_id": sql_id, "days": lookback_days},
        ) or {}
        executions = _as_int(totals.get("executions"))
        interpretation = ""
        if executions is not None and executions <= 5:
            interpretation = (
                f"AWR captured only {executions} execution(s) in the last {lookback_days} day(s), "
                "indicating low frequency."
            )
        return {
            "available": True,
            "plan_changes": plan_changes,
            "totals": totals,
            "lookback_days": lookback_days,
            "interpretation": interpretation,
        }
    except Exception as exc:
        notes.append(f"awr unavailable: {exc}")
        return {"available": False, "error": str(exc), "plan_changes": [], "totals": {}}


def _active_queries(sql_id: str, notes: list[str]) -> list[dict[str, Any]]:
    warn_seconds, critical_seconds = _long_running_thresholds()
    try:
        rows = fetch_all(
            """
            select inst_id, sid, serial# as serial_num, nvl(username,'-') as username,
                   status, sql_id, state, event, wait_class,
                   seconds_in_wait, last_call_et, blocking_instance, blocking_session,
                   nvl(module,'-') as module, nvl(program,'-') as program, nvl(machine,'-') as machine
            from gv$session
            where type = 'USER'
              and username is not null
              and sql_id = :sql_id
            order by case when status = 'ACTIVE' then 0 else 1 end, last_call_et desc
            fetch first 25 rows only
            """,
            {"sql_id": sql_id},
        )
    except Exception as exc:
        notes.append(f"active_queries unavailable: {exc}")
        return []

    enriched: list[dict[str, Any]] = []
    for row in rows:
        runtime_s = _as_int(row.get("last_call_et")) or 0
        runtime_severity = "CRITICAL" if runtime_s >= critical_seconds else "WARNING" if runtime_s >= warn_seconds else "OK"
        enriched.append(
            {
                **row,
                "runtime_seconds": runtime_s,
                "runtime_minutes": round(runtime_s / 60.0, 2),
                "long_running": runtime_s >= warn_seconds,
                "runtime_severity": runtime_severity,
            }
        )
    return enriched


def _live_wait_profile(active_rows: list[dict[str, Any]]) -> SqlWaitProfile:
    sample_count = len(active_rows)
    if sample_count <= 0:
        return SqlWaitProfile(available=False, source_used="gv$session", interpretation="No active session rows matched this SQL_ID.")
    bucket_counts = _wait_bucket_counts(active_rows)
    breakdown = _wait_breakdown(active_rows, source="gv$session")
    top = breakdown[0] if breakdown else None
    profile = SqlWaitProfile(
        available=True,
        source_used="gv$session",
        sample_count=sample_count,
        top_event=top.event if top else None,
        top_wait_class=top.wait_class if top else None,
        event_breakdown=breakdown,
        interpretation=(
            "Wait profile is from currently active sessions only (point-in-time evidence). "
            "Historical ASH/AWR sampling may show different distribution."
        ),
    )
    _apply_wait_bucket_percentages(profile, bucket_counts, sample_count)
    return profile


def _ash_wait_profile(sql_id: str, lookback_days: int, notes: list[str]) -> SqlWaitProfile:
    try:
        summary = fetch_one(
            """
            select count(*) as sample_count,
                   sum(case when session_state = 'ON CPU' then 1 else 0 end) as on_cpu_samples,
                   sum(case when wait_class = 'User I/O' then 1 else 0 end) as user_io_samples,
                   sum(case when wait_class = 'System I/O' then 1 else 0 end) as system_io_samples,
                   sum(case when wait_class = 'Concurrency' then 1 else 0 end) as concurrency_samples,
                   sum(case when wait_class = 'Cluster' then 1 else 0 end) as cluster_samples,
                   sum(case when wait_class = 'Commit' then 1 else 0 end) as commit_samples,
                   sum(case when wait_class = 'Configuration' then 1 else 0 end) as configuration_samples,
                   sum(case when wait_class = 'Application' then 1 else 0 end) as application_samples,
                   sum(case when wait_class = 'Network' then 1 else 0 end) as network_samples
            from v$active_session_history
            where sample_time > sysdate - (:days)
              and sql_id = :sql_id
            """,
            {"days": lookback_days, "sql_id": sql_id},
        ) or {}
        rows = fetch_all(
            """
            select nvl(event, 'ON CPU') as event,
                   case when session_state = 'ON CPU' then 'ON CPU' else nvl(wait_class, 'Other') end as wait_class,
                   count(*) as samples
            from v$active_session_history
            where sample_time > sysdate - (:days)
              and sql_id = :sql_id
            group by nvl(event, 'ON CPU'),
                     case when session_state = 'ON CPU' then 'ON CPU' else nvl(wait_class, 'Other') end
            order by samples desc
            fetch first 15 rows only
            """,
            {"days": lookback_days, "sql_id": sql_id},
        )
    except Exception as exc:
        notes.append(f"ASH wait profile unavailable: {exc}")
        return SqlWaitProfile(available=False, source_used="v$active_session_history", notes=[str(exc)])

    return _build_wait_profile_from_summary(
        source="v$active_session_history",
        summary=summary,
        breakdown_rows=rows,
        lookback_days=lookback_days,
    )


def _awr_wait_profile(sql_id: str, lookback_days: int, notes: list[str]) -> SqlWaitProfile:
    try:
        summary = fetch_one(
            """
            select count(*) as sample_count,
                   sum(case when session_state = 'ON CPU' then 1 else 0 end) as on_cpu_samples,
                   sum(case when wait_class = 'User I/O' then 1 else 0 end) as user_io_samples,
                   sum(case when wait_class = 'System I/O' then 1 else 0 end) as system_io_samples,
                   sum(case when wait_class = 'Concurrency' then 1 else 0 end) as concurrency_samples,
                   sum(case when wait_class = 'Cluster' then 1 else 0 end) as cluster_samples,
                   sum(case when wait_class = 'Commit' then 1 else 0 end) as commit_samples,
                   sum(case when wait_class = 'Configuration' then 1 else 0 end) as configuration_samples,
                   sum(case when wait_class = 'Application' then 1 else 0 end) as application_samples,
                   sum(case when wait_class = 'Network' then 1 else 0 end) as network_samples
            from dba_hist_active_sess_history
            where sample_time > sysdate - (:days)
              and sql_id = :sql_id
            """,
            {"days": lookback_days, "sql_id": sql_id},
        ) or {}
        rows = fetch_all(
            """
            select nvl(event, 'ON CPU') as event,
                   case when session_state = 'ON CPU' then 'ON CPU' else nvl(wait_class, 'Other') end as wait_class,
                   count(*) as samples
            from dba_hist_active_sess_history
            where sample_time > sysdate - (:days)
              and sql_id = :sql_id
            group by nvl(event, 'ON CPU'),
                     case when session_state = 'ON CPU' then 'ON CPU' else nvl(wait_class, 'Other') end
            order by samples desc
            fetch first 15 rows only
            """,
            {"days": lookback_days, "sql_id": sql_id},
        )
    except Exception as exc:
        notes.append(f"AWR ASH wait profile unavailable: {exc}")
        return SqlWaitProfile(available=False, source_used="dba_hist_active_sess_history", notes=[str(exc)])

    return _build_wait_profile_from_summary(
        source="dba_hist_active_sess_history",
        summary=summary,
        breakdown_rows=rows,
        lookback_days=lookback_days,
    )


def _build_wait_profile_from_summary(
    *,
    source: str,
    summary: dict[str, Any],
    breakdown_rows: list[dict[str, Any]],
    lookback_days: int,
) -> SqlWaitProfile:
    sample_count = _as_int(summary.get("sample_count")) or 0
    breakdown = [
        SqlWaitEventRow(
            event=str(row.get("event") or "ON CPU"),
            wait_class=str(row.get("wait_class") or "Other"),
            samples=_as_int(row.get("samples")) or 0,
            pct=_pct(_as_int(row.get("samples")) or 0, sample_count),
            source=source,
        )
        for row in breakdown_rows
    ]
    top = breakdown[0] if breakdown else None
    profile = SqlWaitProfile(
        available=True,
        source_used=source,
        sample_count=sample_count,
        top_event=top.event if top else None,
        top_wait_class=top.wait_class if top else None,
        event_breakdown=breakdown,
        interpretation="",
    )
    bucket_counts = {
        "on_cpu_pct": _as_int(summary.get("on_cpu_samples")) or 0,
        "user_io_pct": _as_int(summary.get("user_io_samples")) or 0,
        "system_io_pct": _as_int(summary.get("system_io_samples")) or 0,
        "concurrency_pct": _as_int(summary.get("concurrency_samples")) or 0,
        "cluster_pct": _as_int(summary.get("cluster_samples")) or 0,
        "commit_pct": _as_int(summary.get("commit_samples")) or 0,
        "configuration_pct": _as_int(summary.get("configuration_samples")) or 0,
        "application_pct": _as_int(summary.get("application_samples")) or 0,
        "network_pct": _as_int(summary.get("network_samples")) or 0,
    }
    _apply_wait_bucket_percentages(profile, bucket_counts, sample_count)
    known = sum(value for key, value in bucket_counts.items() if key != "on_cpu_pct")
    profile.other_pct = _pct(max(sample_count - (_as_int(summary.get("on_cpu_samples")) or 0) - known, 0), sample_count)
    if sample_count == 0:
        profile.interpretation = (
            "No ASH wait-profile rows were captured. This can happen for short-lived SQL, "
            "low sampling hit rate, or low recent activity."
        )
    else:
        profile.interpretation = (
            f"Wait profile is based on {sample_count} sampled active-session row(s) from {source} "
            f"in the last {lookback_days} day(s)."
        )
    return profile


def _wait_bucket_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {field: 0 for field, _ in WAIT_CLASS_BUCKETS}
    counts["on_cpu_pct"] = 0
    other = 0
    for row in rows:
        state = str(row.get("state") or "").upper()
        wait_class = str(row.get("wait_class") or "").strip()
        if state and state != "WAITING":
            counts["on_cpu_pct"] += 1
            continue
        matched = False
        for field, label in WAIT_CLASS_BUCKETS:
            if wait_class == label:
                counts[field] += 1
                matched = True
                break
        if not matched:
            other += 1
    counts["other_pct"] = other
    return counts


def _wait_breakdown(rows: list[dict[str, Any]], source: str) -> list[SqlWaitEventRow]:
    grouped: dict[tuple[str, str], int] = {}
    for row in rows:
        state = str(row.get("state") or "").upper()
        if state and state != "WAITING":
            event = "ON CPU"
            wait_class = "ON CPU"
        else:
            event = str(row.get("event") or "Unknown")
            wait_class = str(row.get("wait_class") or "Other")
        key = (event, wait_class)
        grouped[key] = grouped.get(key, 0) + 1
    total = sum(grouped.values())
    sorted_items = sorted(grouped.items(), key=lambda item: item[1], reverse=True)
    return [
        SqlWaitEventRow(
            event=event,
            wait_class=wait_class,
            samples=count,
            pct=_pct(count, total),
            source=source,
        )
        for (event, wait_class), count in sorted_items
    ]


def _apply_wait_bucket_percentages(profile: SqlWaitProfile, bucket_counts: dict[str, int], sample_count: int) -> None:
    profile.on_cpu_pct = _pct(bucket_counts.get("on_cpu_pct", 0), sample_count)
    for field, _ in WAIT_CLASS_BUCKETS:
        setattr(profile, field, _pct(bucket_counts.get(field, 0), sample_count))
    other = bucket_counts.get("other_pct")
    if other is not None:
        profile.other_pct = _pct(other, sample_count)


def _impact_summary(
    *,
    current_stats: dict[str, Any],
    awr: dict[str, Any],
    active_queries: list[dict[str, Any]],
    history_analysis: dict[str, Any],
) -> SqlImpactSummary:
    awr_totals = awr.get("totals") if isinstance(awr, dict) else {}
    awr_execs = _as_int((awr_totals or {}).get("executions"))
    current_execs = _as_int(current_stats.get("executions"))

    use_awr = bool(awr.get("available")) and awr_execs is not None and awr_execs > 0
    executions = awr_execs if use_awr else current_execs
    executions_source = "AWR lookback" if use_awr else ("v$sqlstats current cursor" if current_execs is not None else None)

    elapsed_total = _as_float((awr_totals or {}).get("elapsed_s")) if use_awr else _as_float(current_stats.get("elapsed_s"))
    cpu_total = _as_float((awr_totals or {}).get("cpu_s")) if use_awr else _as_float(current_stats.get("cpu_s"))
    buffer_total = _as_int((awr_totals or {}).get("buffer_gets")) if use_awr else _as_int(current_stats.get("buffer_gets"))
    disk_total = _as_int((awr_totals or {}).get("disk_reads")) if use_awr else _as_int(current_stats.get("disk_reads"))
    rows_total = _as_int((awr_totals or {}).get("rows_processed")) if use_awr else _as_int(current_stats.get("rows_processed"))

    ela_per_exec = _per_exec(elapsed_total, executions)
    buffer_per_exec = _per_exec(buffer_total, executions)
    disk_per_exec = _per_exec(disk_total, executions)
    rows_per_exec = _per_exec(rows_total, executions)
    active_now = any(str(row.get("status") or "").upper() == "ACTIVE" for row in active_queries)
    appears_in_top_sql = (_as_int(history_analysis.get("top_cpu_run_count")) or 0) > 0 or (_as_int(history_analysis.get("top_elapsed_run_count")) or 0) > 0

    notes: list[str] = []
    if use_awr and awr_execs is not None and awr_execs <= 5:
        notes.append("AWR captured only a few executions in the selected lookback window.")

    impact_summary = "Impact could not be assessed from available execution counters."
    if executions is not None:
        if executions >= 1000 and (ela_per_exec or 0) < 0.02 and (elapsed_total or 0) < 60:
            impact_summary = "High-frequency, cheap SQL pattern. Usually monitor unless cumulative DB time rises."
        elif executions <= 20 and (ela_per_exec or 0) >= 1:
            impact_summary = "Low-frequency, expensive SQL pattern. Individual executions may be tuning candidates."
        elif (elapsed_total or 0) >= 300 or (cpu_total or 0) >= 180 or appears_in_top_sql:
            impact_summary = "Top workload contributor pattern. SQL is likely material to system performance."
        else:
            impact_summary = "Visible SQL with currently low-to-moderate impact."

    return SqlImpactSummary(
        executions=executions,
        executions_source=executions_source,
        elapsed_s_total=elapsed_total,
        cpu_s_total=cpu_total,
        ela_per_exec_s=ela_per_exec,
        buffer_gets_total=buffer_total,
        buffer_gets_per_exec=buffer_per_exec,
        disk_reads_total=disk_total,
        disk_reads_per_exec=disk_per_exec,
        rows_processed_total=rows_total,
        rows_processed_per_exec=rows_per_exec,
        active_now=active_now,
        appears_in_top_sql=appears_in_top_sql,
        impact_summary=impact_summary,
        notes=notes,
    )


def _lock_analysis(sql_id: str, notes: list[str]) -> dict[str, Any]:
    try:
        rows = fetch_all(
            """
            select w.inst_id as waiter_inst_id, w.sid as waiter_sid, w.serial# as waiter_serial,
                   nvl(w.username,'-') as waiter_user, nvl(w.sql_id,'-') as waiter_sql_id,
                   nvl(w.event,'-') as waiter_event, nvl(w.wait_class,'-') as waiter_wait_class,
                   w.seconds_in_wait,
                   b.inst_id as blocker_inst_id, b.sid as blocker_sid, b.serial# as blocker_serial,
                   nvl(b.username,'-') as blocker_user, nvl(b.sql_id,'-') as blocker_sql_id,
                   nvl(b.module,'-') as blocker_module, nvl(b.program,'-') as blocker_program
            from gv$session w
            join gv$session b
              on b.inst_id = w.blocking_instance and b.sid = w.blocking_session
            where w.blocking_session is not null
              and (w.sql_id = :sql_id or b.sql_id = :sql_id)
            order by w.seconds_in_wait desc
            fetch first 20 rows only
            """,
            {"sql_id": sql_id},
        )
    except Exception as exc:
        notes.append(f"lock_analysis unavailable: {exc}")
        rows = []

    as_waiter = sum(1 for row in rows if str(row.get("waiter_sql_id") or "").lower() == sql_id)
    as_blocker = sum(1 for row in rows if str(row.get("blocker_sql_id") or "").lower() == sql_id)
    max_wait = max((_as_int(row.get("seconds_in_wait")) or 0 for row in rows), default=0)
    status = "CRITICAL" if as_blocker > 0 else "WARNING" if as_waiter > 0 else "OK"
    return {
        "status": status,
        "as_waiter_count": as_waiter,
        "as_blocker_count": as_blocker,
        "blocking_rows": rows,
        "max_wait_seconds": max_wait,
    }


def _plan_analysis(
    *,
    current: dict[str, Any],
    children: list[dict[str, Any]],
    awr: dict[str, Any],
    lookback_days: int,
    execution_plan: dict[str, Any],
) -> dict[str, Any]:
    plan_hashes: set[int] = set()
    current_plan_hash = _as_int(current.get("plan_hash_value"))
    if current_plan_hash is not None:
        plan_hashes.add(current_plan_hash)

    for row in children:
        value = _as_int(row.get("plan_hash_value"))
        if value is not None:
            plan_hashes.add(value)

    awr_rows = awr.get("plan_changes") if isinstance(awr, dict) else []
    if isinstance(awr_rows, list):
        for row in awr_rows:
            if not isinstance(row, dict):
                continue
            value = _as_int(row.get("plan_hash_value"))
            if value is not None:
                plan_hashes.add(value)

    distinct_plans = sorted(plan_hashes)
    dominant_plan_hash = None
    dominant_elapsed_s = None
    if isinstance(awr_rows, list) and awr_rows:
        top = awr_rows[0]
        if isinstance(top, dict):
            dominant_plan_hash = _as_int(top.get("plan_hash_value"))
            dominant_elapsed_s = _as_float(top.get("elapsed_s"))

    churn = len(distinct_plans) > 1
    if len(distinct_plans) >= 4:
        stability = "high_churn"
        severity = "CRITICAL"
    elif len(distinct_plans) >= 2:
        stability = "churn"
        severity = "WARNING"
    else:
        stability = "stable"
        severity = "OK"

    summary = (
        f"Observed {len(distinct_plans)} distinct plan hash value(s) in {lookback_days} day(s)."
        if distinct_plans
        else f"No plan hash evidence was captured for this SQL_ID in {lookback_days} day(s)."
    )
    if execution_plan.get("source_used"):
        summary += f" Plan rendered via {execution_plan.get('source_used')}."
    return {
        "status": severity,
        "stability": stability,
        "summary": summary,
        "current_plan_hash": current_plan_hash,
        "distinct_plan_hashes": distinct_plans,
        "distinct_plan_count": len(distinct_plans),
        "churn_detected": churn,
        "dominant_plan_hash": dominant_plan_hash,
        "dominant_plan_elapsed_s": dominant_elapsed_s,
        "active_child_cursor_count": len(children),
        "awr_plan_count": len(awr_rows) if isinstance(awr_rows, list) else 0,
        "plan_source_used": execution_plan.get("source_used"),
        "lookback_days": lookback_days,
    }


def _history_analysis(sql_id: str, notes: list[str]) -> dict[str, Any]:
    try:
        traces = read_health_run_traces(limit=120)
    except Exception as exc:
        notes.append(f"history_analysis unavailable: {exc}")
        return {
            "available": False,
            "error": str(exc),
            "runs_scanned": 0,
            "top_cpu_run_count": 0,
            "top_elapsed_run_count": 0,
            "sql_issue_mentions": 0,
        }

    top_cpu_count = 0
    top_elapsed_count = 0
    issue_mentions = 0
    first_seen = None
    last_seen = None
    cpu_seconds_samples: list[float] = []
    elapsed_seconds_samples: list[float] = []
    matched_runs: list[dict[str, Any]] = []

    for trace in traces:
        metrics = trace.metrics or {}
        is_match = False
        top_cpu_sql_id = str(metrics.get("top_cpu_sql_id") or "").strip().lower()
        top_elapsed_sql_id = str(metrics.get("top_elapsed_sql_id") or "").strip().lower()
        if top_cpu_sql_id == sql_id:
            top_cpu_count += 1
            is_match = True
            value = _as_float(metrics.get("top_cpu_sql_cpu_s"))
            if value is not None:
                cpu_seconds_samples.append(value)
        if top_elapsed_sql_id == sql_id:
            top_elapsed_count += 1
            is_match = True
            value = _as_float(metrics.get("top_elapsed_sql_elapsed_s"))
            if value is not None:
                elapsed_seconds_samples.append(value)

        joined_issue_text = " ".join(
            [
                (issue.title or "") + " " + (issue.description or "")
                for issue in (trace.issues or [])
            ]
        ).lower()
        if sql_id in joined_issue_text:
            issue_mentions += 1
            is_match = True

        if is_match:
            completed_at = trace.completed_at
            if first_seen is None or str(completed_at) < str(first_seen):
                first_seen = completed_at
            if last_seen is None or str(completed_at) > str(last_seen):
                last_seen = completed_at
            matched_runs.append(
                {
                    "completed_at": completed_at,
                    "run_id": trace.run_id,
                    "overall_status": trace.overall_status,
                    "top_cpu_sql_cpu_s": metrics.get("top_cpu_sql_cpu_s"),
                    "top_elapsed_sql_elapsed_s": metrics.get("top_elapsed_sql_elapsed_s"),
                }
            )

    runs_scanned = len(traces)
    recurrence_ratio = round((max(top_cpu_count, top_elapsed_count) / runs_scanned), 3) if runs_scanned else 0.0
    return {
        "available": True,
        "runs_scanned": runs_scanned,
        "top_cpu_run_count": top_cpu_count,
        "top_elapsed_run_count": top_elapsed_count,
        "sql_issue_mentions": issue_mentions,
        "recurrence_ratio": recurrence_ratio,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "cpu_seconds_samples": cpu_seconds_samples[:20],
        "elapsed_seconds_samples": elapsed_seconds_samples[:20],
        "matched_runs": matched_runs[:10],
    }


def _risk_summary(
    *,
    active_queries: list[dict[str, Any]],
    lock_analysis: dict[str, Any],
    plan_analysis: dict[str, Any],
    history_analysis: dict[str, Any],
    wait_profile: SqlWaitProfile,
    impact_summary: SqlImpactSummary,
) -> dict[str, Any]:
    warn_seconds, critical_seconds = _long_running_thresholds()
    reasons: list[str] = []
    score = 0

    long_warn = 0
    long_critical = 0
    for row in active_queries:
        runtime_s = _as_int(row.get("runtime_seconds")) or 0
        if runtime_s >= critical_seconds:
            long_critical += 1
        elif runtime_s >= warn_seconds:
            long_warn += 1
    if long_critical:
        score += 4
        reasons.append(f"{long_critical} active execution(s) exceed {critical_seconds}s.")
    elif long_warn:
        score += 2
        reasons.append(f"{long_warn} active execution(s) exceed {warn_seconds}s.")

    blocker_count = _as_int(lock_analysis.get("as_blocker_count")) or 0
    waiter_count = _as_int(lock_analysis.get("as_waiter_count")) or 0
    if blocker_count > 0:
        score += 4
        reasons.append(f"SQL_ID appears as blocker in {blocker_count} lock chain(s).")
    elif waiter_count > 0:
        score += 2
        reasons.append(f"SQL_ID appears as waiter in {waiter_count} lock chain(s).")

    distinct_plan_count = _as_int(plan_analysis.get("distinct_plan_count")) or 0
    if distinct_plan_count >= 4:
        score += 3
        reasons.append(f"High plan churn detected ({distinct_plan_count} distinct plan hash values).")
    elif distinct_plan_count >= 2:
        score += 1
        reasons.append(f"Plan churn detected ({distinct_plan_count} distinct plan hash values).")

    if wait_profile.available and wait_profile.sample_count > 0:
        io_pct = (wait_profile.user_io_pct or 0) + (wait_profile.system_io_pct or 0)
        if io_pct >= 50:
            score += 2
            reasons.append(f"I/O wait dominance observed ({io_pct:.1f}% of samples).")
        if (wait_profile.concurrency_pct or 0) >= 30 or (wait_profile.application_pct or 0) >= 30:
            score += 2
            reasons.append("Concurrency/Application wait pressure observed.")
    elif wait_profile.available and wait_profile.sample_count == 0:
        reasons.append("No ASH/AWR wait samples captured in current lookback window.")

    if impact_summary.impact_summary.lower().startswith("top workload contributor"):
        score += 2
        reasons.append("Impact summary indicates top workload contribution.")
    elif impact_summary.impact_summary.lower().startswith("low-frequency, expensive"):
        score += 1
        reasons.append("Impact summary indicates expensive per-exec behavior.")

    runs_scanned = _as_int(history_analysis.get("runs_scanned")) or 0
    recurrence_ratio = _as_float(history_analysis.get("recurrence_ratio")) or 0.0
    issue_mentions = _as_int(history_analysis.get("sql_issue_mentions")) or 0
    if runs_scanned >= 3 and recurrence_ratio >= 0.5:
        score += 2
        reasons.append(f"Recurring SQL pressure across history ({recurrence_ratio:.0%} of runs).")
    elif runs_scanned >= 3 and recurrence_ratio >= 0.2:
        score += 1
        reasons.append(f"SQL appears repeatedly in recent history ({recurrence_ratio:.0%} of runs).")
    if issue_mentions >= 2:
        score += 1
        reasons.append(f"SQL_ID referenced in {issue_mentions} historical issue entries.")

    if score >= 8:
        status = "CRITICAL"
    elif score >= 4:
        status = "WARNING"
    else:
        status = "OK"

    return {
        "status": status,
        "score": score,
        "long_running_warning_threshold_seconds": warn_seconds,
        "long_running_critical_threshold_seconds": critical_seconds,
        "long_running_warning_count": long_warn,
        "long_running_critical_count": long_critical,
        "reason_lines": reasons or ["No strong long-running, wait, lock, plan-change, or recurrence risk signals were detected."],
    }


def _dba_recommendation(
    *,
    classification: SqlClassification,
    wait_profile: SqlWaitProfile,
    impact_summary: SqlImpactSummary,
    lock_analysis: dict[str, Any],
    plan_analysis: dict[str, Any],
    risk_summary: dict[str, Any],
    awr: dict[str, Any],
) -> SqlDbaRecommendation:
    rationale: list[str] = []
    next_actions: list[str] = []
    severity: str = "INFO"
    recommendation = "Monitor only"

    blocker_count = _as_int(lock_analysis.get("as_blocker_count")) or 0
    if blocker_count > 0:
        severity = "CRITICAL"
        recommendation = "Investigate blocking immediately"
        rationale.append(f"SQL_ID is a blocker in {blocker_count} active chain(s).")
        next_actions.extend(
            [
                "Correlate blocker SID/SQL with application transaction context.",
                "Release blocking safely only after operator confirmation and business validation.",
            ]
        )
        return SqlDbaRecommendation(severity=severity, recommendation=recommendation, rationale=rationale, next_actions=next_actions)

    io_pct = (wait_profile.user_io_pct or 0) + (wait_profile.system_io_pct or 0)
    if wait_profile.available and wait_profile.sample_count > 0 and io_pct >= 50:
        severity = "WARNING"
        recommendation = "Investigate I/O path and object access pattern"
        rationale.append(f"User/System I/O waits dominate sampled activity ({io_pct:.1f}%).")
        next_actions.extend(
            [
                "Review plan access paths for full scans and large object reads.",
                "Validate object statistics and storage latency for referenced objects.",
            ]
        )
    elif wait_profile.available and wait_profile.sample_count > 0 and ((wait_profile.concurrency_pct or 0) >= 30 or (wait_profile.application_pct or 0) >= 30):
        severity = "WARNING"
        recommendation = "Investigate concurrency and blocking context"
        rationale.append("Concurrency/Application waits are a significant share of sampled activity.")
        next_actions.extend(
            [
                "Check lock chains and hot-row/object contention.",
                "Review transaction scope and commit frequency in calling workload.",
            ]
        )

    if bool(plan_analysis.get("churn_detected")) and impact_summary.executions and impact_summary.executions > 0:
        if severity != "CRITICAL":
            severity = "WARNING"
        recommendation = "Review optimizer statistics and potential plan regression"
        rationale.append("Multiple plan hash values detected for this SQL_ID.")
        next_actions.extend(
            [
                "Compare current plan hash with historical dominant plan.",
                "Validate bind peeking/sensitivity and recent stats changes.",
            ]
        )

    impact_text = (impact_summary.impact_summary or "").lower()
    if impact_text.startswith("high-frequency, cheap"):
        if severity == "INFO":
            recommendation = "No tuning required"
        rationale.append("Observed high-frequency cheap pattern with low per-exec latency.")
        next_actions.append("Monitor only if frequency or cumulative DB time contribution rises.")
    elif impact_text.startswith("low-frequency, expensive"):
        if severity == "INFO":
            severity = "WARNING"
            recommendation = "Investigate expensive executions"
        rationale.append("Executions are infrequent but expensive per execution.")
        next_actions.append("Capture bind values and row-source stats for representative expensive runs.")
    elif impact_text.startswith("top workload contributor"):
        if severity != "CRITICAL":
            severity = "WARNING"
        recommendation = "Prioritize SQL tuning review"
        rationale.append("Impact summary indicates material workload contribution.")
        next_actions.append("Start with wait-profile dominant class and plan row-source hotspots.")

    if classification.classification in {"oracle_internal_sql", "dictionary_sql", "maintenance_sql", "recursive_sql"} and severity == "INFO":
        rationale.append(f"SQL classified as {classification.classification}; avoid aggressive tuning unless impact increases.")

    awr_execs = _as_int(((awr or {}).get("totals") or {}).get("executions"))
    if awr_execs is not None and awr_execs <= 5:
        rationale.append("AWR shows low execution frequency in lookback window.")
        if severity == "INFO":
            recommendation = "No tuning required"
            next_actions.append("Keep baseline only; revisit if frequency or DB time rises.")

    if wait_profile.available and wait_profile.sample_count == 0:
        next_actions.append("If needed, rerun during peak load to capture ASH wait evidence.")

    risk_status = str(risk_summary.get("status") or "OK").upper()
    if risk_status == "CRITICAL" and severity != "CRITICAL":
        severity = "CRITICAL"
    elif risk_status == "WARNING" and severity == "INFO":
        severity = "WARNING"

    if not rationale:
        rationale.append("Current evidence does not indicate a strong tuning signal.")
        next_actions.append("Monitor only if frequency or DB time contribution rises.")
        recommendation = "No tuning required"

    return SqlDbaRecommendation(
        severity=severity,
        recommendation=recommendation,
        rationale=_dedupe_preserve_order(rationale),
        next_actions=_dedupe_preserve_order(next_actions),
    )


def _long_running_thresholds() -> tuple[int, int]:
    warn = _env_int("ODB_AUTODBA_LONG_SQL_WARN_SECONDS", 600)
    critical = _env_int("ODB_AUTODBA_LONG_SQL_CRITICAL_SECONDS", 1800)
    if critical <= warn:
        critical = warn + 1
    return warn, critical


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return max(int(value), 1)
    except Exception:
        return default


def _per_exec(total: float | int | None, executions: int | None) -> float | None:
    if total is None or executions is None or executions <= 0:
        return None
    try:
        return round(float(total) / float(executions), 6)
    except Exception:
        return None


def _pct(part: int | float, total: int | float) -> float | None:
    try:
        if total <= 0:
            return None
        return round((float(part) / float(total)) * 100.0, 2)
    except Exception:
        return None


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _snake_label(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip())
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return normalized.lower()
