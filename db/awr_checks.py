from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from odb_autodba.db.ash_checks import get_ash_window_state
from odb_autodba.db.connection import fetch_all, fetch_one
from odb_autodba.models.schemas import (
    AwrAshState,
    AwrCapabilities,
    AwrHostCpuState,
    AwrIoProfileState,
    AwrMetricDelta,
    AwrMemoryState,
    AwrMetricDiff,
    AwrRunPairWindowMapping,
    AwrSnapshotQuality,
    AwrSnapshotWindowMapping,
    AwrSqlChangeSummary,
    AwrSqlChangeIntelligence,
    AwrStateDiff,
    AwrTimeModelState,
    AwrWaitShiftSummary,
    AwrWaitClassShift,
    AwrWorkloadInterpretation,
)


_REQUIRED_AWR_COMPONENTS: dict[str, str] = {
    "DBA_HIST_SNAPSHOT": "select 1 as x from dba_hist_snapshot where rownum = 1",
    "DBA_HIST_SQLSTAT": "select 1 as x from dba_hist_sqlstat where rownum = 1",
    "DBA_HIST_SYS_TIME_MODEL": "select 1 as x from dba_hist_sys_time_model where rownum = 1",
    "DBA_HIST_SYSTEM_EVENT": "select 1 as x from dba_hist_system_event where rownum = 1",
}

_OPTIONAL_COMPONENTS: dict[str, str] = {
    "DBA_HIST_ACTIVE_SESS_HISTORY": "select 1 as x from dba_hist_active_sess_history where rownum = 1",
    "V$ACTIVE_SESSION_HISTORY": "select 1 as x from v$active_session_history where rownum = 1",
    "V$DATABASE": "select dbid from v$database",
}


_LOAD_PROFILE_METRIC_ORDER = [
    "DB Time",
    "DB CPU",
    "Background CPU",
    "Logical Reads",
    "Physical Reads",
    "Physical Writes",
    "Read IO Requests",
    "Write IO Requests",
    "Redo Size",
    "Parses",
    "Hard Parses",
    "Executes",
    "Transactions",
]


def is_awr_available() -> bool:
    return get_awr_capabilities().available


def get_awr_capabilities() -> AwrCapabilities:
    missing: list[str] = []
    notes: list[str] = []

    for component, sql in _REQUIRED_AWR_COMPONENTS.items():
        if not _probe_component(sql):
            missing.append(component)
    for component, sql in _OPTIONAL_COMPONENTS.items():
        if not _probe_component(sql):
            missing.append(component)

    dbid = _safe_int((fetch_one("select dbid from v$database") or {}).get("dbid"))
    instance_count = _safe_int((fetch_one("select count(*) as instance_count from gv$instance") or {}).get("instance_count")) or 1

    interval_minutes: float | None = None
    retention_minutes: float | None = None
    try:
        wr = fetch_one("select snap_interval, retention from dba_hist_wr_control") or {}
        interval_minutes = _interval_to_minutes(wr.get("snap_interval"))
        retention_minutes = _interval_to_minutes(wr.get("retention"))
    except Exception as exc:
        notes.append(f"AWR retention metadata unavailable: {exc}")

    available = not any(component in missing for component in _REQUIRED_AWR_COMPONENTS)
    ash_available = "V$ACTIVE_SESSION_HISTORY" not in missing or "DBA_HIST_ACTIVE_SESS_HISTORY" not in missing

    if not available:
        notes.append("One or more required AWR components are missing.")
    if interval_minutes is None:
        notes.append("Snapshot interval could not be determined from dba_hist_wr_control.")
    if retention_minutes is None:
        notes.append("Retention window could not be determined from dba_hist_wr_control.")

    return AwrCapabilities(
        available=available,
        ash_available=ash_available,
        dbid=dbid,
        instance_count=max(instance_count, 1),
        rac_enabled=bool(instance_count and instance_count > 1),
        snapshot_interval_minutes=interval_minutes,
        retention_minutes=retention_minutes,
        missing_components=missing,
        notes=notes,
    )


def map_run_to_snapshot_window(
    run_completed_at: str | datetime | None,
    dbid: int | None = None,
    *,
    window_start: str | datetime | None = None,
    window_end: str | datetime | None = None,
) -> AwrSnapshotWindowMapping:
    target_dt = _coerce_dt(run_completed_at)
    if target_dt is None:
        return AwrSnapshotWindowMapping(
            dbid=dbid,
            mapping_quality="NONE",
            notes=["Run timestamp was missing or malformed; cannot map to AWR snapshot window."],
        )
    start_dt = _coerce_dt(window_start) or target_dt
    end_dt = _coerce_dt(window_end) or target_dt
    if end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt

    logical_snapshots = _load_logical_snapshots(
        dbid=dbid,
        scan_start=min(start_dt, target_dt) - timedelta(hours=6),
        scan_end=max(end_dt, target_dt) + timedelta(hours=6),
    )
    if not logical_snapshots:
        return AwrSnapshotWindowMapping(
            dbid=dbid,
            mapping_quality="NONE",
            notes=["No AWR snapshot rows were available around the run timestamp."],
        )

    overlapping = [
        row
        for row in logical_snapshots
        if _snapshot_end(row) > start_dt and _snapshot_begin(row) < end_dt
    ]

    if overlapping:
        matched = _match_snapshot_for_target(overlapping, target_dt) or overlapping[-1]
        begin_row = overlapping[0]
        end_row = overlapping[-1]
        if len(overlapping) == 1:
            matched_index = logical_snapshots.index(matched)
            previous_row = logical_snapshots[matched_index - 1] if matched_index > 0 else None
            next_row = logical_snapshots[matched_index + 1] if matched_index < (len(logical_snapshots) - 1) else None
            if previous_row is not None:
                begin_row = previous_row
                end_row = matched
            elif next_row is not None:
                begin_row = matched
                end_row = next_row
        contains_target = _snapshot_contains(matched, target_dt)
        quality = "HIGH" if contains_target else "MEDIUM"
        notes = [
            (
                f"Window-based mapping used {len(overlapping)} logical snapshot interval(s); "
                f"matched SNAP {int(matched.get('snap_id') or 0)} "
                f"(instance_rows={int(matched.get('instance_rows_found') or 0)}, "
                f"instances={int(matched.get('instance_count') or 0)})."
            )
        ]
        if len(overlapping) == 1 and begin_row.get("snap_id") != end_row.get("snap_id"):
            notes.append(
                f"Expanded window to SNAP {int(begin_row.get('snap_id') or 0)}..{int(end_row.get('snap_id') or 0)} for delta extraction."
            )
        return AwrSnapshotWindowMapping(
            dbid=dbid,
            begin_snap_id=_safe_int(begin_row.get("snap_id")),
            end_snap_id=_safe_int(end_row.get("snap_id")),
            matched_snap_id=_safe_int(matched.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(begin_row)),
            end_time=_format_ts(_snapshot_end(end_row)),
            matched_begin_time=_format_ts(_snapshot_begin(matched)),
            matched_end_time=_format_ts(_snapshot_end(matched)),
            instance_count=int(matched.get("instance_count") or 0),
            instance_rows_found=int(matched.get("instance_rows_found") or 0),
            mapping_quality=quality,
            notes=notes,
        )

    containing = next((row for row in logical_snapshots if _snapshot_contains(row, target_dt)), None)
    if containing is not None:
        containing_index = logical_snapshots.index(containing)
        previous_row = logical_snapshots[containing_index - 1] if containing_index > 0 else None
        begin_row = previous_row or containing
        end_row = containing
        notes = [
            (
                f"Run timestamp mapped inside SNAP {int(containing.get('snap_id') or 0)}; "
                "snapshot interval selected from logical per-SNAP aggregation."
            )
        ]
        if previous_row is not None:
            notes.append(
                f"Expanded begin SNAP to {int(previous_row.get('snap_id') or 0)} for delta-friendly extraction."
            )
        return AwrSnapshotWindowMapping(
            dbid=dbid,
            begin_snap_id=_safe_int(begin_row.get("snap_id")),
            end_snap_id=_safe_int(end_row.get("snap_id")),
            matched_snap_id=_safe_int(containing.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(begin_row)),
            end_time=_format_ts(_snapshot_end(end_row)),
            matched_begin_time=_format_ts(_snapshot_begin(containing)),
            matched_end_time=_format_ts(_snapshot_end(containing)),
            instance_count=int(containing.get("instance_count") or 0),
            instance_rows_found=int(containing.get("instance_rows_found") or 0),
            mapping_quality="HIGH",
            notes=notes,
        )

    previous_candidates = [row for row in logical_snapshots if _snapshot_end(row) <= target_dt]
    next_candidates = [row for row in logical_snapshots if _snapshot_begin(row) >= target_dt]
    previous_row = previous_candidates[-1] if previous_candidates else None
    next_row = next_candidates[0] if next_candidates else None

    if previous_row is not None and next_row is not None and (_safe_int(next_row.get("snap_id")) or 0) > (_safe_int(previous_row.get("snap_id")) or 0):
        previous_distance = _distance_seconds(target_dt, _snapshot_end(previous_row))
        next_distance = _distance_seconds(_snapshot_begin(next_row), target_dt)
        matched = previous_row if previous_distance <= next_distance else next_row
        return AwrSnapshotWindowMapping(
            dbid=dbid,
            begin_snap_id=_safe_int(previous_row.get("snap_id")),
            end_snap_id=_safe_int(next_row.get("snap_id")),
            matched_snap_id=_safe_int(matched.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(previous_row)),
            end_time=_format_ts(_snapshot_end(next_row)),
            matched_begin_time=_format_ts(_snapshot_begin(matched)),
            matched_end_time=_format_ts(_snapshot_end(matched)),
            instance_count=int(matched.get("instance_count") or 0),
            instance_rows_found=int(matched.get("instance_rows_found") or 0),
            mapping_quality="MEDIUM",
            notes=["Run timestamp bridged nearest snapshots; mapped to adjacent SNAP interval pair."],
        )

    if previous_row is not None:
        return AwrSnapshotWindowMapping(
            dbid=dbid,
            begin_snap_id=_safe_int(previous_row.get("snap_id")),
            end_snap_id=_safe_int(previous_row.get("snap_id")),
            matched_snap_id=_safe_int(previous_row.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(previous_row)),
            end_time=_format_ts(_snapshot_end(previous_row)),
            matched_begin_time=_format_ts(_snapshot_begin(previous_row)),
            matched_end_time=_format_ts(_snapshot_end(previous_row)),
            instance_count=int(previous_row.get("instance_count") or 0),
            instance_rows_found=int(previous_row.get("instance_rows_found") or 0),
            mapping_quality="LOW",
            notes=["Only a previous logical SNAP interval could be mapped for this run timestamp."],
        )

    if next_row is not None:
        return AwrSnapshotWindowMapping(
            dbid=dbid,
            begin_snap_id=_safe_int(next_row.get("snap_id")),
            end_snap_id=_safe_int(next_row.get("snap_id")),
            matched_snap_id=_safe_int(next_row.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(next_row)),
            end_time=_format_ts(_snapshot_end(next_row)),
            matched_begin_time=_format_ts(_snapshot_begin(next_row)),
            matched_end_time=_format_ts(_snapshot_end(next_row)),
            instance_count=int(next_row.get("instance_count") or 0),
            instance_rows_found=int(next_row.get("instance_rows_found") or 0),
            mapping_quality="LOW",
            notes=["Only a future logical SNAP interval could be mapped for this run timestamp."],
        )

    return AwrSnapshotWindowMapping(
        dbid=dbid,
        mapping_quality="NONE",
        notes=["No AWR snapshot rows were available around the run timestamp."],
    )



def map_run_pair_to_awr_windows(
    previous_run_completed_at: str | datetime | None,
    current_run_completed_at: str | datetime | None,
    dbid: int | None = None,
    *,
    previous_window_start: str | datetime | None = None,
    previous_window_end: str | datetime | None = None,
    current_window_start: str | datetime | None = None,
    current_window_end: str | datetime | None = None,
) -> AwrRunPairWindowMapping:
    previous = map_run_to_snapshot_window(
        previous_run_completed_at,
        dbid=dbid,
        window_start=previous_window_start,
        window_end=previous_window_end,
    )
    current = map_run_to_snapshot_window(
        current_run_completed_at,
        dbid=dbid,
        window_start=current_window_start,
        window_end=current_window_end,
    )

    notes: list[str] = []
    notes.extend([f"previous: {note}" for note in previous.notes])
    notes.extend([f"current: {note}" for note in current.notes])

    prev_quality = _mapping_quality_score(previous.mapping_quality)
    curr_quality = _mapping_quality_score(current.mapping_quality)
    comparability = min(prev_quality, curr_quality)

    if previous.begin_snap_id is not None and current.end_snap_id is not None:
        if current.end_snap_id <= previous.begin_snap_id:
            comparability *= 0.5
            notes.append("Current mapped snapshots did not move forward from previous run.")
    if (
        previous.begin_snap_id is not None
        and previous.end_snap_id is not None
        and current.begin_snap_id is not None
        and current.end_snap_id is not None
        and previous.begin_snap_id == current.begin_snap_id
        and previous.end_snap_id == current.end_snap_id
    ):
        comparability *= 0.4
        notes.append("Both runs map to the same snapshot window; AWR transition confidence is low.")

    previous_run_dt = _coerce_dt(previous_run_completed_at)
    current_run_dt = _coerce_dt(current_run_completed_at)
    same_matched_snap = (
        previous.matched_snap_id is not None
        and current.matched_snap_id is not None
        and previous.matched_snap_id == current.matched_snap_id
    )
    if same_matched_snap:
        comparability *= 0.5
        notes.append("Both runs mapped to the same matched SNAP_ID; comparison is weak but still reported.")

    confidence = _comparability_to_confidence(comparability)
    debug = {
        "previous_run_timestamp": _format_ts(previous_run_dt),
        "current_run_timestamp": _format_ts(current_run_dt),
        "mapped_previous_snap": previous.matched_snap_id or previous.end_snap_id or previous.begin_snap_id,
        "mapped_current_snap": current.matched_snap_id or current.end_snap_id or current.begin_snap_id,
        "previous_instance_rows_found": previous.instance_rows_found,
        "current_instance_rows_found": current.instance_rows_found,
        "previous_instance_count": previous.instance_count,
        "current_instance_count": current.instance_count,
        "same_snap_selected": same_matched_snap,
        "begin_end_snap_pair": {
            "previous": [previous.begin_snap_id, previous.end_snap_id],
            "current": [current.begin_snap_id, current.end_snap_id],
        },
    }
    return AwrRunPairWindowMapping(
        previous=previous,
        current=current,
        comparability_score=round(comparability, 2),
        confidence=confidence,
        notes=notes,
        debug=debug,
    )


def build_awr_state_diff(
    *,
    window_mapping: AwrRunPairWindowMapping,
    capabilities: AwrCapabilities | None = None,
) -> AwrStateDiff:
    caps = capabilities or get_awr_capabilities()
    if not caps.available:
        return AwrStateDiff(
            available=False,
            capabilities=caps,
            window_mapping=window_mapping,
            snapshot_quality=AwrSnapshotQuality(
                coverage_quality="NONE",
                comparability_score=0.0,
                confidence="LOW",
                notes=["AWR required views were unavailable."],
            ),
            notes=["AWR state-diff skipped because required AWR components are unavailable."],
        )

    prev = window_mapping.previous
    curr = window_mapping.current
    if not _valid_window(prev) or not _valid_window(curr):
        return AwrStateDiff(
            available=False,
            capabilities=caps,
            window_mapping=window_mapping,
            snapshot_quality=AwrSnapshotQuality(
                coverage_quality="LOW",
                comparability_score=window_mapping.comparability_score,
                confidence="LOW",
                notes=["Snapshot mapping was incomplete for one or both runs."],
            ),
            notes=["AWR state-diff skipped because run-to-snapshot mapping was incomplete."],
        )

    notes: list[str] = []
    if window_mapping.debug:
        mapped_prev = window_mapping.debug.get("mapped_previous_snap")
        mapped_curr = window_mapping.debug.get("mapped_current_snap")
        notes.append(
            f"Mapped run pair to SNAPs previous={mapped_prev}, current={mapped_curr} "
            f"(same_snap_selected={window_mapping.debug.get('same_snap_selected')})."
        )
    load_prev = _collect_load_profile(prev, notes, label="previous")
    load_curr = _collect_load_profile(curr, notes, label="current")
    load_profile = [_metric_diff(name, load_prev.get(name), load_curr.get(name)) for name in _LOAD_PROFILE_METRIC_ORDER]
    workload_metrics = [_to_metric_delta(metric) for metric in load_profile]
    workload_interpretation = _build_workload_interpretation(workload_metrics)

    wait_shift = _build_wait_class_shift(prev, curr, load_prev, load_curr, notes)
    wait_shift_summary = AwrWaitShiftSummary(
        previous_dominant_wait_class=wait_shift.dominant_wait_class_previous,
        current_dominant_wait_class=wait_shift.dominant_wait_class_current,
        previous_top_event=wait_shift.previous_top_event,
        current_top_event=wait_shift.current_top_event,
        wait_class_shift_flag=wait_shift.wait_class_shift_flag,
        cpu_to_io_shift=wait_shift.cpu_to_io_shift,
        cpu_to_concurrency_shift=wait_shift.cpu_to_concurrency_shift,
        interpretation=wait_shift.interpretation,
    )
    time_model = _build_time_model_state(prev, curr, notes)
    host_cpu_state = _build_host_cpu_state(prev, curr, load_prev, load_curr, wait_shift, notes)
    io_profile = _build_io_profile_state(prev, curr, notes)
    memory_state = _build_memory_state(prev, curr, load_prev, load_curr, notes)
    sql_change = _build_sql_change_intel(prev, curr, notes)
    sql_change_summary = AwrSqlChangeSummary(
        dominant_sql_id_previous=sql_change.dominant_sql_id_previous,
        dominant_sql_id_current=sql_change.dominant_sql_id_current,
        dominant_sql_schema_previous=sql_change.dominant_sql_schema_previous,
        dominant_sql_schema_current=sql_change.dominant_sql_schema_current,
        dominant_sql_module_previous=sql_change.dominant_sql_module_previous,
        dominant_sql_module_current=sql_change.dominant_sql_module_current,
        dominant_sql_class_previous=sql_change.dominant_sql_class_previous,
        dominant_sql_class_current=sql_change.dominant_sql_class_current,
        sql_regression_flag=sql_change.sql_regression_flag,
        sql_regression_severity=sql_change.sql_regression_severity,
        plan_hash_changed_flag=sql_change.plan_hash_changed_flag,
        elapsed_per_exec_spike=sql_change.elapsed_per_exec_spike,
        cpu_per_exec_spike=sql_change.cpu_per_exec_spike,
        interpretation=sql_change.interpretation,
    )

    prefer_hist_ash = "DBA_HIST_ACTIVE_SESS_HISTORY" not in caps.missing_components
    ash_prev = get_ash_window_state(
        begin_time=prev.begin_time,
        end_time=prev.end_time,
        begin_snap_id=prev.begin_snap_id,
        end_snap_id=prev.end_snap_id,
        dbid=prev.dbid,
        prefer_awr=prefer_hist_ash,
    )
    ash_curr = get_ash_window_state(
        begin_time=curr.begin_time,
        end_time=curr.end_time,
        begin_snap_id=curr.begin_snap_id,
        end_snap_id=curr.end_snap_id,
        dbid=curr.dbid,
        prefer_awr=prefer_hist_ash,
    )
    ash_state = AwrAshState(
        source=(ash_curr.get("source") or ash_prev.get("source")),
        aas_proxy_previous=_safe_float(ash_prev.get("aas_proxy")),
        aas_proxy_current=_safe_float(ash_curr.get("aas_proxy")),
        top_sql_previous=list(ash_prev.get("top_sql") or []),
        top_sql_current=list(ash_curr.get("top_sql") or []),
        wait_profile_previous=list(ash_prev.get("wait_profile") or []),
        wait_profile_current=list(ash_curr.get("wait_profile") or []),
        blocking_previous=list(ash_prev.get("blocking") or []),
        blocking_current=list(ash_curr.get("blocking") or []),
    )
    notes.extend([f"ASH previous: {note}" for note in (ash_prev.get("notes") or [])])
    notes.extend([f"ASH current: {note}" for note in (ash_curr.get("notes") or [])])

    section_scores = [
        1.0 if any(item.previous is not None or item.current is not None for item in load_profile) else 0.0,
        1.0 if (wait_shift.top_foreground_events_previous or wait_shift.top_foreground_events_current) else 0.0,
        1.0 if time_model.metrics else 0.0,
        1.0 if host_cpu_state.metrics else 0.0,
        1.0 if io_profile.metrics else 0.0,
        1.0 if memory_state.metrics else 0.0,
        1.0 if (sql_change.top_sql_by_elapsed_previous or sql_change.top_sql_by_elapsed_current) else 0.0,
        1.0 if ash_state.source else 0.0,
    ]
    coverage_ratio = sum(section_scores) / len(section_scores) if section_scores else 0.0
    comparability = max(0.0, min(1.0, coverage_ratio * window_mapping.comparability_score))
    snapshot_quality = AwrSnapshotQuality(
        coverage_quality=_coverage_quality(coverage_ratio),
        comparability_score=round(comparability, 2),
        confidence=_comparability_to_confidence(comparability),
        notes=_quality_notes(coverage_ratio, window_mapping),
    )

    if snapshot_quality.coverage_quality in {"LOW", "NONE"}:
        notes.append("AWR snapshots were mapped but metric rows were incomplete; partial AWR comparison was produced.")
    if window_mapping.debug.get("same_snap_selected"):
        notes.append("AWR snapshots mapped successfully but both runs resolved to the same SNAP_ID; comparison is weak.")

    return AwrStateDiff(
        available=True,
        capabilities=caps,
        window_mapping=window_mapping,
        load_profile=load_profile,
        workload_metrics=workload_metrics,
        workload_interpretation=workload_interpretation,
        wait_class_shift=wait_shift,
        wait_shift_summary=wait_shift_summary,
        time_model=time_model,
        host_cpu_state=host_cpu_state,
        io_profile=io_profile,
        memory_state=memory_state,
        sql_change=sql_change,
        sql_change_summary=sql_change_summary,
        ash_state=ash_state,
        snapshot_quality=snapshot_quality,
        notes=notes,
    )


def get_top_sql_from_awr(limit: int = 10) -> list[dict]:
    return fetch_all(
        """
        select * from (
            select sql_id,
                   plan_hash_value,
                   round(sum(elapsed_time_delta)/1e6,3) as elapsed_s,
                   round(sum(cpu_time_delta)/1e6,3) as cpu_s,
                   sum(executions_delta) as executions
            from dba_hist_sqlstat
            group by sql_id, plan_hash_value
            order by elapsed_s desc
        ) where rownum <= :lim
        """,
        {"lim": int(limit)},
    )


def _collect_load_profile(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> dict[str, float | None]:
    out: dict[str, float | None] = {}
    time_model = _collect_time_model(window, notes, label=label)
    sysstat = _collect_sysstat(window, notes, label=label)

    out["DB Time"] = time_model.get("DB time")
    out["DB CPU"] = time_model.get("DB CPU")
    out["Background CPU"] = time_model.get("background cpu time")
    out["Logical Reads"] = sysstat.get("session logical reads")
    out["Physical Reads"] = sysstat.get("physical reads")
    out["Physical Writes"] = sysstat.get("physical writes")
    out["Read IO Requests"] = sysstat.get("physical read total io requests")
    out["Write IO Requests"] = sysstat.get("physical write total io requests")
    out["Redo Size"] = sysstat.get("redo size")
    out["Parses"] = sysstat.get("parse count (total)")
    out["Hard Parses"] = sysstat.get("parse count (hard)")
    out["Executes"] = sysstat.get("execute count")
    out["Transactions"] = _sum_values(sysstat, ["user commits", "user rollbacks"])
    return out


def _build_wait_class_shift(
    prev: AwrSnapshotWindowMapping,
    curr: AwrSnapshotWindowMapping,
    load_prev: dict[str, float | None],
    load_curr: dict[str, float | None],
    notes: list[str],
) -> AwrWaitClassShift:
    prev_events = _collect_top_events(prev, notes, label="previous")
    curr_events = _collect_top_events(curr, notes, label="current")
    prev_classes = _collect_wait_class_time(prev_events)
    curr_classes = _collect_wait_class_time(curr_events)

    prev_db_cpu = _safe_float(load_prev.get("DB CPU"))
    prev_db_time = _safe_float(load_prev.get("DB Time"))
    curr_db_cpu = _safe_float(load_curr.get("DB CPU"))
    curr_db_time = _safe_float(load_curr.get("DB Time"))

    db_cpu_pct_prev = _pct(prev_db_cpu, prev_db_time)
    db_cpu_pct_curr = _pct(curr_db_cpu, curr_db_time)

    dominant_prev = _dominant_wait_class(prev_classes, db_cpu_pct_prev)
    dominant_curr = _dominant_wait_class(curr_classes, db_cpu_pct_curr)

    wait_class_shift_flag = bool(dominant_prev and dominant_curr and dominant_prev != dominant_curr)
    cpu_to_io_shift = dominant_prev == "CPU" and dominant_curr in {"User I/O", "System I/O"}
    cpu_to_concurrency_shift = dominant_prev == "CPU" and dominant_curr in {"Concurrency", "Application"}

    all_event_names = " ".join(str(row.get("event_name") or "").lower() for row in curr_events)
    lock_contention_flag = "enq: tx" in all_event_names or dominant_curr in {"Application", "Concurrency"}
    scheduler_pressure_flag = "resmgr" in all_event_names or "scheduler" in all_event_names
    previous_top_event = _event_name(prev_events[0] if prev_events else None)
    current_top_event = _event_name(curr_events[0] if curr_events else None)
    interpretation = _wait_shift_interpretation(
        dominant_previous=dominant_prev,
        dominant_current=dominant_curr,
        previous_top_event=previous_top_event,
        current_top_event=current_top_event,
        wait_class_shift_flag=wait_class_shift_flag,
        cpu_to_io_shift=cpu_to_io_shift,
        cpu_to_concurrency_shift=cpu_to_concurrency_shift,
    )

    return AwrWaitClassShift(
        top_foreground_events_previous=prev_events,
        top_foreground_events_current=curr_events,
        wait_classes_previous=prev_classes,
        wait_classes_current=curr_classes,
        db_cpu_pct_previous=db_cpu_pct_prev,
        db_cpu_pct_current=db_cpu_pct_curr,
        dominant_wait_class_previous=dominant_prev,
        dominant_wait_class_current=dominant_curr,
        wait_class_shift_flag=wait_class_shift_flag,
        cpu_to_io_shift=cpu_to_io_shift,
        cpu_to_concurrency_shift=cpu_to_concurrency_shift,
        lock_contention_flag=lock_contention_flag,
        scheduler_pressure_flag=scheduler_pressure_flag,
        previous_top_event=previous_top_event,
        current_top_event=current_top_event,
        interpretation=interpretation,
    )


def _build_time_model_state(prev: AwrSnapshotWindowMapping, curr: AwrSnapshotWindowMapping, notes: list[str]) -> AwrTimeModelState:
    prev_tm = _collect_time_model(prev, notes, label="previous")
    curr_tm = _collect_time_model(curr, notes, label="current")

    metric_map = {
        "DB time": "DB time",
        "DB CPU": "DB CPU",
        "sql execute elapsed time": "sql execute elapsed time",
        "parse time elapsed": "parse time elapsed",
        "hard parse elapsed time": "hard parse elapsed time",
        "PL/SQL execution time": "PL/SQL execution elapsed time",
        "background elapsed time": "background elapsed time",
    }
    metrics = [_metric_diff(out_name, prev_tm.get(in_name), curr_tm.get(in_name)) for out_name, in_name in metric_map.items()]

    sql_elapsed_diff = _find_metric(metrics, "sql execute elapsed time")
    parse_diff = _find_metric(metrics, "parse time elapsed")
    hard_parse_diff = _find_metric(metrics, "hard parse elapsed time")
    cpu_diff = _find_metric(metrics, "DB CPU")

    return AwrTimeModelState(
        metrics=metrics,
        sql_elapsed_spike_flag=bool((sql_elapsed_diff.pct_change or 0) >= 30 if sql_elapsed_diff else False),
        parse_regression_flag=bool(((parse_diff.pct_change or 0) >= 25 if parse_diff else False) or ((hard_parse_diff.pct_change or 0) >= 25 if hard_parse_diff else False)),
        cpu_growth_flag=bool((cpu_diff.pct_change or 0) >= 20 if cpu_diff else False),
    )


def _build_host_cpu_state(
    prev: AwrSnapshotWindowMapping,
    curr: AwrSnapshotWindowMapping,
    load_prev: dict[str, float | None],
    load_curr: dict[str, float | None],
    wait_shift: AwrWaitClassShift,
    notes: list[str],
) -> AwrHostCpuState:
    prev_host = _collect_host_cpu(prev, notes, label="previous")
    curr_host = _collect_host_cpu(curr, notes, label="current")

    db_cpu_prev = _safe_float(load_prev.get("DB CPU"))
    db_cpu_curr = _safe_float(load_curr.get("DB CPU"))
    host_busy_prev = _safe_float(prev_host.get("busy_time"))
    host_busy_curr = _safe_float(curr_host.get("busy_time"))

    metrics = [
        _metric_diff("%User", prev_host.get("user_pct"), curr_host.get("user_pct")),
        _metric_diff("%System", prev_host.get("system_pct"), curr_host.get("system_pct")),
        _metric_diff("%Idle", prev_host.get("idle_pct"), curr_host.get("idle_pct")),
        _metric_diff("%IOWait", prev_host.get("iowait_pct"), curr_host.get("iowait_pct")),
        _metric_diff("Host CPU usage", prev_host.get("host_cpu_usage_pct"), curr_host.get("host_cpu_usage_pct")),
        _metric_diff("DB CPU vs host CPU", _ratio(db_cpu_prev, host_busy_prev), _ratio(db_cpu_curr, host_busy_curr)),
    ]

    host_cpu = _safe_float(curr_host.get("host_cpu_usage_pct"))
    iowait_spike = (_safe_float(curr_host.get("iowait_pct")) or 0.0) - (_safe_float(prev_host.get("iowait_pct")) or 0.0)
    resource_manager_wait_flag = wait_shift.scheduler_pressure_flag
    cpu_pressure_flag = bool((host_cpu is not None and host_cpu >= 85.0) or wait_shift.dominant_wait_class_current == "CPU")

    return AwrHostCpuState(
        metrics=metrics,
        cpu_pressure_flag=cpu_pressure_flag,
        resource_manager_wait_flag=resource_manager_wait_flag,
        host_iowait_spike=bool(iowait_spike >= 10.0),
    )


def _build_io_profile_state(prev: AwrSnapshotWindowMapping, curr: AwrSnapshotWindowMapping, notes: list[str]) -> AwrIoProfileState:
    prev_sys = _collect_sysstat(prev, notes, label="previous")
    curr_sys = _collect_sysstat(curr, notes, label="current")

    prev_total_io = _sum_values(prev_sys, ["physical read total io requests", "physical write total io requests"])
    curr_total_io = _sum_values(curr_sys, ["physical read total io requests", "physical write total io requests"])

    prev_read_mb = _to_mb(prev_sys.get("physical read total bytes"))
    curr_read_mb = _to_mb(curr_sys.get("physical read total bytes"))
    prev_write_mb = _to_mb(prev_sys.get("physical write total bytes"))
    curr_write_mb = _to_mb(curr_sys.get("physical write total bytes"))

    prev_redo_io = _safe_float(prev_sys.get("redo writes"))
    curr_redo_io = _safe_float(curr_sys.get("redo writes"))

    prev_direct = _sum_values(prev_sys, ["physical reads direct", "physical writes direct"])
    curr_direct = _sum_values(curr_sys, ["physical reads direct", "physical writes direct"])

    metrics = [
        _metric_diff("total IO requests", prev_total_io, curr_total_io),
        _metric_diff("read MB", prev_read_mb, curr_read_mb),
        _metric_diff("write MB", prev_write_mb, curr_write_mb),
        _metric_diff("redo IO", prev_redo_io, curr_redo_io),
        _metric_diff("direct IO", prev_direct, curr_direct),
    ]

    total_io_diff = _find_metric(metrics, "total IO requests")
    redo_diff = _find_metric(metrics, "redo IO")
    direct_ratio_curr = _ratio(curr_direct, curr_total_io)

    return AwrIoProfileState(
        metrics=metrics,
        io_pressure_flag=bool((total_io_diff.pct_change or 0) >= 30 if total_io_diff else False),
        redo_spike_flag=bool((redo_diff.pct_change or 0) >= 35 if redo_diff else False),
        buffer_cache_bypass=bool((direct_ratio_curr or 0.0) >= 0.2),
    )


def _build_memory_state(
    prev: AwrSnapshotWindowMapping,
    curr: AwrSnapshotWindowMapping,
    load_prev: dict[str, float | None],
    load_curr: dict[str, float | None],
    notes: list[str],
) -> AwrMemoryState:
    prev_mem = _collect_memory(prev, notes, label="previous")
    curr_mem = _collect_memory(curr, notes, label="current")

    parse_prev = _safe_float(load_prev.get("Parses"))
    hard_prev = _safe_float(load_prev.get("Hard Parses"))
    parse_curr = _safe_float(load_curr.get("Parses"))
    hard_curr = _safe_float(load_curr.get("Hard Parses"))
    reuse_prev = _pct((parse_prev or 0.0) - (hard_prev or 0.0), parse_prev)
    reuse_curr = _pct((parse_curr or 0.0) - (hard_curr or 0.0), parse_curr)

    metrics = [
        _metric_diff("SGA usage", prev_mem.get("sga_mb"), curr_mem.get("sga_mb")),
        _metric_diff("PGA usage", prev_mem.get("pga_alloc_mb"), curr_mem.get("pga_alloc_mb")),
        _metric_diff("Shared Pool usage", prev_mem.get("shared_pool_mb"), curr_mem.get("shared_pool_mb")),
        _metric_diff("SQL reuse %", reuse_prev, reuse_curr),
    ]

    pga_diff = _find_metric(metrics, "PGA usage")
    shared_pool_diff = _find_metric(metrics, "Shared Pool usage")
    reuse_diff = _find_metric(metrics, "SQL reuse %")

    return AwrMemoryState(
        metrics=metrics,
        memory_pressure_flag=bool((pga_diff.pct_change or 0) >= 25 if pga_diff else False),
        shared_pool_pressure=bool((shared_pool_diff.pct_change or 0) <= -15 if shared_pool_diff else False),
        cursor_reuse_change=bool(abs((reuse_diff.delta or 0.0)) >= 10.0 if reuse_diff else False),
    )


def _build_sql_change_intel(prev: AwrSnapshotWindowMapping, curr: AwrSnapshotWindowMapping, notes: list[str]) -> AwrSqlChangeIntelligence:
    top_elapsed_prev = _collect_top_sql(prev, notes, label="previous", order="elapsed")
    top_elapsed_curr = _collect_top_sql(curr, notes, label="current", order="elapsed")
    top_cpu_prev = _collect_top_sql(prev, notes, label="previous", order="cpu")
    top_cpu_curr = _collect_top_sql(curr, notes, label="current", order="cpu")

    dominant_prev = _dominant_sql(top_elapsed_prev, top_cpu_prev)
    dominant_curr = _dominant_sql(top_elapsed_curr, top_cpu_curr)

    dominant_changed = bool(dominant_prev and dominant_curr and dominant_prev != dominant_curr)

    prev_dom = _find_sql(top_elapsed_prev, dominant_prev)
    curr_dom = _find_sql(top_elapsed_curr, dominant_curr)
    prev_elapsed_per_exec = _safe_float((prev_dom or {}).get("elapsed_per_exec_s"))
    curr_elapsed_per_exec = _safe_float((curr_dom or {}).get("elapsed_per_exec_s"))
    prev_cpu_per_exec = _safe_float((prev_dom or {}).get("cpu_per_exec_s"))
    curr_cpu_per_exec = _safe_float((curr_dom or {}).get("cpu_per_exec_s"))

    elapsed_pct = _pct_change(prev_elapsed_per_exec, curr_elapsed_per_exec)
    cpu_pct = _pct_change(prev_cpu_per_exec, curr_cpu_per_exec)
    elapsed_spike = bool((elapsed_pct or 0.0) >= 30.0)
    cpu_spike = bool((cpu_pct or 0.0) >= 30.0)
    plan_hash_changed = bool((_safe_int((curr_dom or {}).get("plan_hash_count")) or 0) > 1 and not dominant_changed)
    severity = _sql_regression_severity(elapsed_spike=elapsed_spike, cpu_spike=cpu_spike, dominant_changed=dominant_changed)
    previous_schema = _text_or_none((prev_dom or {}).get("parsing_schema_name"))
    current_schema = _text_or_none((curr_dom or {}).get("parsing_schema_name"))
    previous_module = _text_or_none((prev_dom or {}).get("module"))
    current_module = _text_or_none((curr_dom or {}).get("module"))
    previous_class = _classify_sql_workload(dominant_prev, previous_schema, previous_module)
    current_class = _classify_sql_workload(dominant_curr, current_schema, current_module)
    interpretation = _sql_change_interpretation(
        dominant_previous=dominant_prev,
        dominant_current=dominant_curr,
        previous_class=previous_class,
        current_class=current_class,
        severity=severity,
        plan_hash_changed=plan_hash_changed,
    )

    return AwrSqlChangeIntelligence(
        top_sql_by_elapsed_previous=top_elapsed_prev,
        top_sql_by_elapsed_current=top_elapsed_curr,
        top_sql_by_cpu_previous=top_cpu_prev,
        top_sql_by_cpu_current=top_cpu_curr,
        dominant_sql_id_previous=dominant_prev,
        dominant_sql_id_current=dominant_curr,
        dominant_sql_schema_previous=previous_schema,
        dominant_sql_schema_current=current_schema,
        dominant_sql_module_previous=previous_module,
        dominant_sql_module_current=current_module,
        dominant_sql_class_previous=previous_class,
        dominant_sql_class_current=current_class,
        dominant_sql_changed_flag=dominant_changed,
        sql_regression_flag=bool(elapsed_spike or cpu_spike),
        sql_regression_severity=severity,
        plan_hash_changed_flag=plan_hash_changed,
        elapsed_per_exec_spike=elapsed_spike,
        cpu_per_exec_spike=cpu_spike,
        interpretation=interpretation,
    )


def _collect_top_events(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> list[dict[str, Any]]:
    binds = {"begin_snap_id": window.begin_snap_id, "end_snap_id": window.end_snap_id, "dbid": window.dbid}
    try:
        return fetch_all(
            """
            select * from (
                select event_name,
                       wait_class,
                       round(sum(time_waited_micro_delta)/1e6, 3) as time_waited_s,
                       sum(total_waits_delta) as waits
                from dba_hist_system_event
                where snap_id > :begin_snap_id
                  and snap_id <= :end_snap_id
                  and (:dbid is null or dbid = :dbid)
                  and wait_class <> 'Idle'
                group by event_name, wait_class
                order by time_waited_s desc
            ) where rownum <= 10
            """,
            binds,
        )
    except Exception as exc:
        notes.append(f"{label} wait-event extraction failed: {exc}")
        return []


def _collect_wait_class_time(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    totals: dict[str, float] = {}
    for row in events:
        wait_class = str(row.get("wait_class") or "Other")
        waited = _safe_float(row.get("time_waited_s")) or 0.0
        totals[wait_class] = totals.get(wait_class, 0.0) + waited
    ordered = sorted(totals.items(), key=lambda item: item[1], reverse=True)
    return [{"wait_class": wait_class, "time_waited_s": round(waited, 3)} for wait_class, waited in ordered]


def _collect_time_model(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> dict[str, float]:
    stat_names = [
        "DB time",
        "DB CPU",
        "background cpu time",
        "sql execute elapsed time",
        "parse time elapsed",
        "hard parse elapsed time",
        "PL/SQL execution elapsed time",
        "background elapsed time",
    ]
    try:
        binds = {"begin_snap_id": window.begin_snap_id, "end_snap_id": window.end_snap_id, "dbid": window.dbid}
        rows = fetch_all(
            """
            with tm as (
                select instance_number,
                       stat_name,
                       snap_id,
                       value,
                       lag(value) over (partition by instance_number, stat_name order by snap_id) as prev_value
                from dba_hist_sys_time_model
                where snap_id >= :begin_snap_id
                  and snap_id <= :end_snap_id
                  and (:dbid is null or dbid = :dbid)
                  and stat_name in (
                      'DB time',
                      'DB CPU',
                      'background cpu time',
                      'sql execute elapsed time',
                      'parse time elapsed',
                      'hard parse elapsed time',
                      'PL/SQL execution elapsed time',
                      'background elapsed time'
                  )
            )
            select stat_name,
                   round(sum(greatest(value - nvl(prev_value, value), 0))/1e6, 3) as value_s
            from tm
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
            group by stat_name
            """,
            binds,
        )
    except Exception as exc:
        notes.append(f"{label} time-model extraction failed: {exc}")
        return {}

    out = {str(row.get("stat_name") or ""): _safe_float(row.get("value_s")) for row in rows}
    for name in stat_names:
        out.setdefault(name, None)
    return out


def _collect_sysstat(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> dict[str, float]:
    stats = [
        "session logical reads",
        "physical reads",
        "physical writes",
        "physical read total IO requests",
        "physical write total IO requests",
        "physical read total bytes",
        "physical write total bytes",
        "redo size",
        "redo writes",
        "parse count (total)",
        "parse count (hard)",
        "execute count",
        "user commits",
        "user rollbacks",
        "physical reads direct",
        "physical writes direct",
    ]
    try:
        binds = {"begin_snap_id": window.begin_snap_id, "end_snap_id": window.end_snap_id, "dbid": window.dbid}
        rows = fetch_all(
            """
            with ss as (
                select s.instance_number,
                       n.stat_name,
                       s.snap_id,
                       s.value,
                       lag(s.value) over (partition by s.instance_number, s.stat_id order by s.snap_id) as prev_value
                from dba_hist_sysstat s
                join dba_hist_stat_name n
                  on n.dbid = s.dbid
                 and n.stat_id = s.stat_id
                where s.snap_id >= :begin_snap_id
                  and s.snap_id <= :end_snap_id
                  and (:dbid is null or s.dbid = :dbid)
                  and lower(n.stat_name) in (
                      'session logical reads',
                      'physical reads',
                      'physical writes',
                      'physical read total io requests',
                      'physical write total io requests',
                      'physical read total bytes',
                      'physical write total bytes',
                      'redo size',
                      'redo writes',
                      'parse count (total)',
                      'parse count (hard)',
                      'execute count',
                      'user commits',
                      'user rollbacks',
                      'physical reads direct',
                      'physical writes direct'
                  )
            )
            select lower(stat_name) as stat_name,
                   round(sum(greatest(value - nvl(prev_value, value), 0)), 3) as value
            from ss
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
            group by lower(stat_name)
            """,
            binds,
        )
    except Exception as exc:
        notes.append(f"{label} sysstat extraction failed: {exc}")
        return {}

    out = {str(row.get("stat_name") or "").lower(): _safe_float(row.get("value")) for row in rows}
    for stat in stats:
        out.setdefault(stat.lower(), None)
    return out


def _collect_host_cpu(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> dict[str, float | None]:
    try:
        binds = {"begin_snap_id": window.begin_snap_id, "end_snap_id": window.end_snap_id, "dbid": window.dbid}
        rows = fetch_all(
            """
            with os as (
                select instance_number,
                       stat_name,
                       snap_id,
                       value,
                       lag(value) over (partition by instance_number, stat_name order by snap_id) as prev_value
                from dba_hist_osstat
                where snap_id >= :begin_snap_id
                  and snap_id <= :end_snap_id
                  and (:dbid is null or dbid = :dbid)
                  and stat_name in ('BUSY_TIME', 'IDLE_TIME', 'USER_TIME', 'SYS_TIME', 'IOWAIT_TIME')
            )
            select stat_name,
                   round(sum(greatest(value - nvl(prev_value, value), 0)), 3) as value
            from os
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
            group by stat_name
            """,
            binds,
        )
    except Exception as exc:
        notes.append(f"{label} host CPU extraction failed: {exc}")
        return {}

    values = {str(row.get("stat_name") or "").upper(): _safe_float(row.get("value")) for row in rows}
    busy = values.get("BUSY_TIME")
    idle = values.get("IDLE_TIME")
    user = values.get("USER_TIME")
    system = values.get("SYS_TIME")
    iowait = values.get("IOWAIT_TIME")
    total = (busy + idle) if busy is not None and idle is not None else None
    return {
        "busy_time": busy,
        "idle_time": idle,
        "user_pct": _pct(user, total),
        "system_pct": _pct(system, total),
        "idle_pct": _pct(idle, total),
        "iowait_pct": _pct(iowait, total),
        "host_cpu_usage_pct": _pct(busy, total),
    }


def _collect_memory(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> dict[str, float | None]:
    out: dict[str, float | None] = {
        "sga_mb": None,
        "shared_pool_mb": None,
        "pga_alloc_mb": None,
    }

    try:
        binds = {"begin_snap_id": window.begin_snap_id, "end_snap_id": window.end_snap_id, "dbid": window.dbid}
        sga_row = fetch_one(
            """
            with snap_sga as (
                select snap_id,
                       instance_number,
                       sum(bytes) as sga_bytes,
                       sum(case when lower(pool) = 'shared pool' then bytes else 0 end) as shared_pool_bytes
                from dba_hist_sgastat
                where snap_id > :begin_snap_id
                  and snap_id <= :end_snap_id
                  and (:dbid is null or dbid = :dbid)
                group by snap_id, instance_number
            )
            select round(avg(sga_bytes)/1024/1024, 3) as sga_mb,
                   round(avg(shared_pool_bytes)/1024/1024, 3) as shared_pool_mb
            from snap_sga
            """,
            binds,
        ) or {}
        out["sga_mb"] = _safe_float(sga_row.get("sga_mb"))
        out["shared_pool_mb"] = _safe_float(sga_row.get("shared_pool_mb"))
    except Exception as exc:
        notes.append(f"{label} SGA extraction failed: {exc}")

    try:
        binds = {"begin_snap_id": window.begin_snap_id, "end_snap_id": window.end_snap_id, "dbid": window.dbid}
        pga_rows = fetch_all(
            """
            select lower(name) as name,
                   round(avg(value)/1024/1024, 3) as mb
            from dba_hist_pgastat
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
              and (:dbid is null or dbid = :dbid)
              and lower(name) in ('total pga allocated', 'total pga inuse')
            group by lower(name)
            """,
            binds,
        )
        pga_map = {str(row.get("name") or "").lower(): _safe_float(row.get("mb")) for row in pga_rows}
        out["pga_alloc_mb"] = pga_map.get("total pga allocated") or pga_map.get("total pga inuse")
    except Exception as exc:
        notes.append(f"{label} PGA extraction failed: {exc}")

    return out


def _collect_top_sql(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str, order: str) -> list[dict[str, Any]]:
    order_expr = "elapsed_s desc" if order == "elapsed" else "cpu_s desc"
    binds = {"begin_snap_id": window.begin_snap_id, "end_snap_id": window.end_snap_id, "dbid": window.dbid}
    with_schema_module = f"""
        select * from (
            select sql_id,
                   round(sum(elapsed_time_delta)/1e6, 3) as elapsed_s,
                   round(sum(cpu_time_delta)/1e6, 3) as cpu_s,
                   sum(executions_delta) as executions,
                   round((sum(elapsed_time_delta)/1e6) / nullif(sum(executions_delta), 0), 6) as elapsed_per_exec_s,
                   round((sum(cpu_time_delta)/1e6) / nullif(sum(executions_delta), 0), 6) as cpu_per_exec_s,
                   count(distinct plan_hash_value) as plan_hash_count,
                   max(parsing_schema_name) as parsing_schema_name,
                   max(module) as module
            from dba_hist_sqlstat
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
              and (:dbid is null or dbid = :dbid)
              and sql_id is not null
            group by sql_id
            order by {order_expr}
        ) where rownum <= 10
    """
    without_schema_module = f"""
        select * from (
            select sql_id,
                   round(sum(elapsed_time_delta)/1e6, 3) as elapsed_s,
                   round(sum(cpu_time_delta)/1e6, 3) as cpu_s,
                   sum(executions_delta) as executions,
                   round((sum(elapsed_time_delta)/1e6) / nullif(sum(executions_delta), 0), 6) as elapsed_per_exec_s,
                   round((sum(cpu_time_delta)/1e6) / nullif(sum(executions_delta), 0), 6) as cpu_per_exec_s,
                   count(distinct plan_hash_value) as plan_hash_count
            from dba_hist_sqlstat
            where snap_id > :begin_snap_id
              and snap_id <= :end_snap_id
              and (:dbid is null or dbid = :dbid)
              and sql_id is not null
            group by sql_id
            order by {order_expr}
        ) where rownum <= 10
    """
    try:
        return fetch_all(with_schema_module, binds)
    except Exception as exc:
        notes.append(f"{label} top SQL ({order}) extraction with schema/module failed: {exc}")
        try:
            return fetch_all(without_schema_module, binds)
        except Exception as fallback_exc:
            notes.append(f"{label} top SQL ({order}) extraction failed: {fallback_exc}")
            return []


def _metric_diff(name: str, previous: float | None, current: float | None) -> AwrMetricDiff:
    prev_value = _safe_float(previous)
    curr_value = _safe_float(current)
    delta = (curr_value - prev_value) if prev_value is not None and curr_value is not None else None
    pct_change = _pct_change(prev_value, curr_value) if prev_value is not None and curr_value is not None else None
    significance = _significance(delta, pct_change)
    return AwrMetricDiff(
        metric_name=name,
        previous=prev_value,
        current=curr_value,
        delta=delta,
        pct_change=pct_change,
        significance=significance,
        interpretation=_metric_change_interpretation(name, prev_value, curr_value, delta, pct_change, significance),
    )


def _load_logical_snapshots(
    *,
    dbid: int | None,
    scan_start: datetime,
    scan_end: datetime,
) -> list[dict[str, Any]]:
    rows = fetch_all(
        """
        select snap_id,
               instance_number,
               to_char(begin_interval_time, 'YYYY-MM-DD"T"HH24:MI:SS') as begin_time,
               to_char(end_interval_time, 'YYYY-MM-DD"T"HH24:MI:SS') as end_time
        from dba_hist_snapshot
        where (:dbid is null or dbid = :dbid)
          and end_interval_time >= :scan_start
          and begin_interval_time <= :scan_end
        order by snap_id, instance_number
        """,
        {"dbid": dbid, "scan_start": scan_start, "scan_end": scan_end},
    )
    if not rows:
        return []
    by_snap: dict[int, dict[str, Any]] = {}
    for row in rows:
        snap_id = _safe_int(row.get("snap_id"))
        if snap_id is None:
            continue
        begin_dt = _coerce_dt(row.get("begin_time"))
        end_dt = _coerce_dt(row.get("end_time"))
        if begin_dt is None or end_dt is None:
            continue
        current = by_snap.get(snap_id)
        if current is None:
            current = {
                "snap_id": snap_id,
                "begin_dt": begin_dt,
                "end_dt": end_dt,
                "instance_numbers": set(),
                "instance_rows_found": 0,
            }
            by_snap[snap_id] = current
        current["begin_dt"] = min(current["begin_dt"], begin_dt)
        current["end_dt"] = max(current["end_dt"], end_dt)
        inst_num = _safe_int(row.get("instance_number"))
        if inst_num is not None:
            current["instance_numbers"].add(inst_num)
        current["instance_rows_found"] = int(current["instance_rows_found"]) + 1

    logical = []
    for snap_id in sorted(by_snap):
        row = by_snap[snap_id]
        logical.append(
            {
                "snap_id": snap_id,
                "begin_dt": row["begin_dt"],
                "end_dt": row["end_dt"],
                "instance_count": len(row["instance_numbers"]),
                "instance_rows_found": int(row["instance_rows_found"]),
            }
        )
    return logical


def _match_snapshot_for_target(rows: list[dict[str, Any]], target_dt: datetime) -> dict[str, Any] | None:
    containing = [row for row in rows if _snapshot_contains(row, target_dt)]
    if containing:
        containing.sort(key=lambda row: (_snapshot_begin(row), _snapshot_end(row)))
        return containing[-1]
    if not rows:
        return None
    return min(rows, key=lambda row: _distance_seconds(_snapshot_center(row), target_dt))


def _snapshot_begin(row: dict[str, Any]) -> datetime:
    return row.get("begin_dt")


def _snapshot_end(row: dict[str, Any]) -> datetime:
    return row.get("end_dt")


def _snapshot_center(row: dict[str, Any]) -> datetime:
    begin_dt = _snapshot_begin(row)
    end_dt = _snapshot_end(row)
    return begin_dt + ((end_dt - begin_dt) / 2)


def _snapshot_contains(row: dict[str, Any], target_dt: datetime) -> bool:
    return _snapshot_begin(row) <= target_dt < _snapshot_end(row)


def _distance_seconds(left: datetime, right: datetime) -> float:
    return abs((left - right).total_seconds())


def _format_ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")


def _quality_notes(coverage_ratio: float, window_mapping: AwrRunPairWindowMapping) -> list[str]:
    notes = list(window_mapping.notes)
    if coverage_ratio >= 0.8:
        notes.append("Most AWR sections were available for both windows.")
    elif coverage_ratio >= 0.5:
        notes.append("Some AWR sections were missing; transition inferences are partial.")
    else:
        notes.append("AWR section coverage was weak; use transition findings with caution.")
    return notes


def _significance(delta: float | None, pct_change: float | None) -> str:
    if delta is None and pct_change is None:
        return "LOW"
    magnitude = abs(pct_change or 0.0)
    if magnitude >= 40:
        return "HIGH"
    if magnitude >= 15:
        return "MEDIUM"
    if abs(delta or 0.0) > 0:
        return "LOW"
    return "LOW"


def _coverage_quality(score: float) -> str:
    if score >= 0.8:
        return "HIGH"
    if score >= 0.5:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _dominant_wait_class(wait_classes: list[dict[str, Any]], db_cpu_pct: float | None) -> str | None:
    if db_cpu_pct is not None and db_cpu_pct >= 50.0:
        return "CPU"
    if not wait_classes:
        return "CPU" if db_cpu_pct and db_cpu_pct > 0 else None
    return str(wait_classes[0].get("wait_class") or "Unknown")


def _mapping_quality_score(quality: str | None) -> float:
    normalized = (quality or "NONE").upper()
    return {
        "HIGH": 1.0,
        "MEDIUM": 0.75,
        "LOW": 0.4,
        "NONE": 0.0,
    }.get(normalized, 0.0)


def _comparability_to_confidence(score: float) -> str:
    if score >= 0.8:
        return "HIGH"
    if score >= 0.5:
        return "MEDIUM"
    return "LOW"


def _valid_window(window: AwrSnapshotWindowMapping) -> bool:
    return window.begin_snap_id is not None and window.end_snap_id is not None and window.end_snap_id >= window.begin_snap_id


def _pct(numerator: float | None, denominator: float | None) -> float | None:
    num = _safe_float(numerator)
    den = _safe_float(denominator)
    if num is None or den is None or den == 0:
        return None
    return round((num / den) * 100.0, 2)


def _pct_change(previous: float | None, current: float | None) -> float | None:
    prev = _safe_float(previous)
    curr = _safe_float(current)
    if prev is None or curr is None:
        return None
    if prev == 0:
        if curr == 0:
            return 0.0
        return 100.0
    return round(((curr - prev) / abs(prev)) * 100.0, 2)


def _ratio(numerator: float | None, denominator: float | None) -> float | None:
    num = _safe_float(numerator)
    den = _safe_float(denominator)
    if num is None or den is None or den == 0:
        return None
    return round(num / den, 4)


def _find_metric(metrics: list[AwrMetricDiff], metric_name: str) -> AwrMetricDiff | None:
    for metric in metrics:
        if metric.metric_name == metric_name:
            return metric
    return None


def _sum_values(values: dict[str, float | None], keys: list[str]) -> float | None:
    total = 0.0
    found = False
    for key in keys:
        value = _safe_float(values.get(key.lower()) if key.lower() in values else values.get(key))
        if value is None:
            continue
        found = True
        total += value
    return round(total, 3) if found else None


def _dominant_sql(top_elapsed: list[dict[str, Any]], top_cpu: list[dict[str, Any]]) -> str | None:
    if top_elapsed:
        candidate = str(top_elapsed[0].get("sql_id") or "").strip()
        if candidate:
            return candidate
    if top_cpu:
        candidate = str(top_cpu[0].get("sql_id") or "").strip()
        if candidate:
            return candidate
    return None


def _find_sql(rows: list[dict[str, Any]], sql_id: str | None) -> dict[str, Any] | None:
    if not sql_id:
        return None
    for row in rows:
        if str(row.get("sql_id") or "") == sql_id:
            return row
    return None


def _to_metric_delta(metric: AwrMetricDiff) -> AwrMetricDelta:
    return AwrMetricDelta(
        metric_name=metric.metric_name,
        previous_value=metric.previous,
        current_value=metric.current,
        delta_value=metric.delta,
        percent_delta=metric.pct_change,
        significance=metric.significance,
        interpretation=metric.interpretation,
    )


def _build_workload_interpretation(workload_metrics: list[AwrMetricDelta]) -> AwrWorkloadInterpretation:
    if not workload_metrics:
        return AwrWorkloadInterpretation(
            summary="AWR workload metrics were unavailable; trend inference used non-AWR signals.",
            material_change_detected=False,
            low_significance_majority=False,
            high_or_medium_metric_count=0,
            low_metric_count=0,
            unavailable_metric_count=0,
        )

    unavailable = sum(1 for metric in workload_metrics if metric.previous_value is None or metric.current_value is None)
    high_or_medium = sum(1 for metric in workload_metrics if metric.significance in {"HIGH", "MEDIUM"})
    low = sum(1 for metric in workload_metrics if metric.significance == "LOW")
    material = high_or_medium > 0
    low_majority = low > high_or_medium

    if material:
        summary = (
            f"AWR workload metrics show material movement in {high_or_medium}/{len(workload_metrics)} key metrics."
        )
    elif low_majority:
        summary = (
            "AWR workload deltas were mostly LOW significance; state transition is likely driven by transactional or issue-state changes."
        )
    else:
        summary = "AWR workload metrics were mostly stable with limited directional change."

    return AwrWorkloadInterpretation(
        summary=summary,
        material_change_detected=material,
        low_significance_majority=low_majority,
        high_or_medium_metric_count=high_or_medium,
        low_metric_count=low,
        unavailable_metric_count=unavailable,
    )


def _event_name(row: dict[str, Any] | None) -> str | None:
    if not row:
        return None
    name = str(row.get("event_name") or "").strip()
    return name or None


def _wait_shift_interpretation(
    *,
    dominant_previous: str | None,
    dominant_current: str | None,
    previous_top_event: str | None,
    current_top_event: str | None,
    wait_class_shift_flag: bool,
    cpu_to_io_shift: bool,
    cpu_to_concurrency_shift: bool,
) -> str:
    if not dominant_previous and not dominant_current:
        return "Wait-class shift interpretation unavailable due to incomplete AWR wait-event rows."
    if wait_class_shift_flag:
        if cpu_to_io_shift:
            return "Material wait shift from CPU-bound activity to I/O-bound activity."
        if cpu_to_concurrency_shift:
            return "Material wait shift from CPU-bound activity to concurrency/contention pressure."
        return f"Material wait-class shift detected from {dominant_previous or '-'} to {dominant_current or '-'}."
    if previous_top_event and current_top_event and previous_top_event != current_top_event:
        return "Dominant wait class stayed stable, but top event changed within the same class."
    return "No material wait-class shift detected."


def _sql_regression_severity(*, elapsed_spike: bool, cpu_spike: bool, dominant_changed: bool) -> str:
    if elapsed_spike and cpu_spike and dominant_changed:
        return "HIGH"
    if elapsed_spike and cpu_spike:
        return "MEDIUM"
    if elapsed_spike or cpu_spike:
        return "LOW"
    return "NONE"


def _text_or_none(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _classify_sql_workload(sql_id: str | None, schema_name: str | None, module: str | None) -> str | None:
    schema = (schema_name or "").upper()
    mod = (module or "").upper()
    if "SCHEDULER" in mod or "DBMS_SCHEDULER" in mod or "CJQ" in mod:
        return "scheduler_sql"
    if schema in {"SYS", "SYSTEM", "DBSNMP", "XDB", "SYSMAN"}:
        return "oracle_internal_sql"
    if schema and schema not in {"UNKNOWN"}:
        return "app_sql"
    if sql_id:
        return "unknown"
    return None


def _sql_change_interpretation(
    *,
    dominant_previous: str | None,
    dominant_current: str | None,
    previous_class: str | None,
    current_class: str | None,
    severity: str,
    plan_hash_changed: bool,
) -> str:
    if dominant_previous and dominant_current and dominant_previous != dominant_current:
        shift = (
            f"Dominant SQL shifted from {dominant_previous} ({previous_class or 'unknown'}) "
            f"to {dominant_current} ({current_class or 'unknown'})."
        )
    elif dominant_current:
        shift = f"Dominant SQL remained {dominant_current} ({current_class or 'unknown'})."
    else:
        shift = "Dominant SQL could not be identified from AWR SQLSTAT rows."

    regression = f" SQL regression severity is {severity}."
    plan = " Plan-hash variability was detected." if plan_hash_changed else " No plan-hash change was detected."
    return shift + regression + plan


def _metric_change_interpretation(
    metric_name: str,
    previous: float | None,
    current: float | None,
    delta: float | None,
    pct_change: float | None,
    significance: str,
) -> str:
    if previous is None and current is None:
        return f"{metric_name} was unavailable in both windows."
    if previous is None or current is None:
        return f"{metric_name} was partially available; comparison confidence is limited."
    direction = "increased" if (delta or 0.0) > 0 else ("decreased" if (delta or 0.0) < 0 else "remained stable")
    if pct_change is None:
        return f"{metric_name} {direction}; significance={significance}."
    return f"{metric_name} {direction} by {abs(pct_change):.2f}% ({significance})."


def _safe_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        return None


def _to_mb(value: float | None) -> float | None:
    if value is None:
        return None
    return round(float(value) / 1024.0 / 1024.0, 3)


def _probe_component(sql: str) -> bool:
    try:
        fetch_all(sql)
        return True
    except Exception:
        return False


def _coerce_dt(value: str | datetime | None) -> datetime | None:
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


def _interval_to_minutes(value: Any) -> float | None:
    if value is None:
        return None
    if hasattr(value, "total_seconds"):
        try:
            return round(float(value.total_seconds()) / 60.0, 2)
        except Exception:
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        # Oracle interval text example: +000000000 01:00:00.000000
        parts = text.split()
        day_part = 0.0
        time_part = parts[-1] if parts else ""
        if len(parts) == 2:
            day_part = float(parts[0].replace("+", ""))
        hour, minute, second = time_part.split(":")
        return round((day_part * 24 * 60) + (float(hour) * 60) + float(minute) + (float(second) / 60.0), 2)
    except Exception:
        return None
