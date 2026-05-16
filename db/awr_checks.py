from __future__ import annotations

import re
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
    AwrReportTextSummary,
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
    "GV$ACTIVE_SESSION_HISTORY": "select 1 as x from gv$active_session_history where rownum = 1",
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

_TIME_MODEL_STAT_NAMES = [
    "DB time",
    "DB CPU",
    "background elapsed time",
    "background cpu time",
    "sql execute elapsed time",
    "parse time elapsed",
    "hard parse elapsed time",
]

_SYSSTAT_NAMES = [
    "execute count",
    "parse count (total)",
    "parse count (hard)",
    "user commits",
    "user rollbacks",
    "redo size",
    "session logical reads",
    "physical reads",
    "physical writes",
    "db block changes",
    "opened cursors cumulative",
    "logons cumulative",
    "physical read total io requests",
    "physical write total io requests",
    "physical read total bytes",
    "physical write total bytes",
    "redo writes",
    "physical reads direct",
    "physical writes direct",
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
    ash_available = "GV$ACTIVE_SESSION_HISTORY" not in missing or "DBA_HIST_ACTIVE_SESS_HISTORY" not in missing

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
    identity = _current_awr_identity(dbid_hint=dbid)
    effective_dbid = _safe_int(dbid) or _safe_int(identity.get("dbid"))
    effective_instance = _safe_int(identity.get("instance_number"))
    effective_startup_dt = identity.get("startup_dt")
    effective_startup = _format_ts(effective_startup_dt)
    if target_dt is None:
        return AwrSnapshotWindowMapping(
            dbid=effective_dbid,
            instance_number=effective_instance,
            startup_time=effective_startup,
            mapping_quality="NONE",
            window_use="context_only",
            window_reason="Run timestamp was missing or malformed.",
            notes=["Run timestamp was missing or malformed; cannot map to AWR snapshot window."],
        )
    start_dt = _coerce_dt(window_start) or target_dt
    end_dt = _coerce_dt(window_end) or target_dt
    if end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt

    chains = _load_snapshot_chains(
        dbid=effective_dbid,
        scan_start=min(start_dt, target_dt) - timedelta(hours=6),
        scan_end=max(end_dt, target_dt) + timedelta(hours=6),
    )
    selected_key, selection_note, ambiguity = _select_snapshot_chain(
        chains=chains,
        target_dt=target_dt,
        start_dt=start_dt,
        end_dt=end_dt,
        preferred_dbid=effective_dbid,
        preferred_instance=effective_instance,
        preferred_startup=effective_startup_dt,
    )
    logical_snapshots = chains.get(selected_key, []) if selected_key is not None else []
    if not logical_snapshots:
        return AwrSnapshotWindowMapping(
            dbid=effective_dbid,
            instance_number=effective_instance,
            startup_time=effective_startup,
            mapping_quality="NONE",
            window_use="context_only",
            window_reason="No AWR snapshot rows were available for the current DBID/instance chain.",
            notes=["No AWR snapshot rows were available around the run timestamp."],
        )
    chain_dbid = _safe_int(logical_snapshots[0].get("dbid")) or effective_dbid
    chain_instance = _safe_int(logical_snapshots[0].get("instance_number")) or effective_instance
    chain_startup = _format_ts(_coerce_dt(logical_snapshots[0].get("startup_time"))) or effective_startup

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
        begin_snap_id = _safe_int(begin_row.get("snap_id"))
        end_snap_id = _safe_int(end_row.get("snap_id"))
        if begin_snap_id is not None and end_snap_id is not None and begin_snap_id == end_snap_id and not contains_target:
            quality = "LOW"
        else:
            quality = "HIGH" if contains_target else "MEDIUM"
        notes = [
            (
                f"Window-based mapping used {len(overlapping)} logical snapshot interval(s); "
                f"matched SNAP {int(matched.get('snap_id') or 0)}."
            )
        ]
        if selection_note:
            notes.append(selection_note)
        if ambiguity:
            notes.append(
                "Multiple AWR snapshot chains exist for this time range. AutoDBA selected snapshots matching current DBID/instance/startup chain. Other chains were ignored."
            )
        if len(overlapping) == 1 and begin_row.get("snap_id") != end_row.get("snap_id"):
            notes.append(
                f"Expanded window to SNAP {int(begin_row.get('snap_id') or 0)}..{int(end_row.get('snap_id') or 0)} for delta extraction."
            )
        duration_minutes = _duration_minutes(_snapshot_begin(begin_row), _snapshot_end(end_row))
        if begin_snap_id is not None and end_snap_id is not None and begin_snap_id < end_snap_id:
            use_mode = "structured_delta"
        else:
            use_mode = "rca" if quality == "HIGH" and (duration_minutes or 0.0) >= 10.0 else "context_only"
        return AwrSnapshotWindowMapping(
            dbid=chain_dbid,
            instance_number=chain_instance,
            startup_time=chain_startup,
            begin_snap_id=_safe_int(begin_row.get("snap_id")),
            end_snap_id=_safe_int(end_row.get("snap_id")),
            matched_snap_id=_safe_int(matched.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(begin_row)),
            end_time=_format_ts(_snapshot_end(end_row)),
            matched_begin_time=_format_ts(_snapshot_begin(matched)),
            matched_end_time=_format_ts(_snapshot_end(matched)),
            duration_minutes=duration_minutes,
            instance_count=int(matched.get("instance_count") or 0),
            instance_rows_found=int(matched.get("instance_rows_found") or 0),
            window_use=use_mode,
            window_reason="Run timestamp is mapped to selected DBID/instance/startup snapshot chain.",
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
        if selection_note:
            notes.append(selection_note)
        if ambiguity:
            notes.append(
                "Multiple AWR snapshot chains exist for this time range. AutoDBA selected snapshots matching current DBID/instance/startup chain. Other chains were ignored."
            )
        duration_minutes = _duration_minutes(_snapshot_begin(begin_row), _snapshot_end(end_row))
        return AwrSnapshotWindowMapping(
            dbid=chain_dbid,
            instance_number=chain_instance,
            startup_time=chain_startup,
            begin_snap_id=_safe_int(begin_row.get("snap_id")),
            end_snap_id=_safe_int(end_row.get("snap_id")),
            matched_snap_id=_safe_int(containing.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(begin_row)),
            end_time=_format_ts(_snapshot_end(end_row)),
            matched_begin_time=_format_ts(_snapshot_begin(containing)),
            matched_end_time=_format_ts(_snapshot_end(containing)),
            duration_minutes=duration_minutes,
            instance_count=int(containing.get("instance_count") or 0),
            instance_rows_found=int(containing.get("instance_rows_found") or 0),
            window_use="rca" if (duration_minutes or 0.0) >= 10.0 else "context_only",
            window_reason="Run timestamp is contained within selected snapshot interval.",
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
        duration_minutes = _duration_minutes(_snapshot_begin(previous_row), _snapshot_end(next_row))
        notes = ["Run timestamp bridged nearest snapshots; mapped to adjacent SNAP interval pair."]
        if selection_note:
            notes.append(selection_note)
        if ambiguity:
            notes.append(
                "Multiple AWR snapshot chains exist for this time range. AutoDBA selected snapshots matching current DBID/instance/startup chain. Other chains were ignored."
            )
        return AwrSnapshotWindowMapping(
            dbid=chain_dbid,
            instance_number=chain_instance,
            startup_time=chain_startup,
            begin_snap_id=_safe_int(previous_row.get("snap_id")),
            end_snap_id=_safe_int(next_row.get("snap_id")),
            matched_snap_id=_safe_int(matched.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(previous_row)),
            end_time=_format_ts(_snapshot_end(next_row)),
            matched_begin_time=_format_ts(_snapshot_begin(matched)),
            matched_end_time=_format_ts(_snapshot_end(matched)),
            duration_minutes=duration_minutes,
            instance_count=int(matched.get("instance_count") or 0),
            instance_rows_found=int(matched.get("instance_rows_found") or 0),
            window_use="context_only",
            window_reason="Mapped using adjacent snapshots because no direct overlap was found.",
            mapping_quality="MEDIUM",
            notes=notes,
        )

    if previous_row is not None:
        previous_index = logical_snapshots.index(previous_row)
        prior_row = logical_snapshots[previous_index - 1] if previous_index > 0 else None
        if prior_row is not None:
            begin_row = prior_row
            end_row = previous_row
            duration_minutes = _duration_minutes(_snapshot_begin(begin_row), _snapshot_end(end_row))
            notes = ["Run timestamp is after latest completed snapshot; using adjacent completed interval for delta."]
            if selection_note:
                notes.append(selection_note)
            return AwrSnapshotWindowMapping(
                dbid=chain_dbid,
                instance_number=chain_instance,
                startup_time=chain_startup,
                begin_snap_id=_safe_int(begin_row.get("snap_id")),
                end_snap_id=_safe_int(end_row.get("snap_id")),
                matched_snap_id=_safe_int(end_row.get("snap_id")),
                begin_time=_format_ts(_snapshot_begin(begin_row)),
                end_time=_format_ts(_snapshot_end(end_row)),
                matched_begin_time=_format_ts(_snapshot_begin(end_row)),
                matched_end_time=_format_ts(_snapshot_end(end_row)),
                duration_minutes=duration_minutes,
                instance_count=int(end_row.get("instance_count") or 0),
                instance_rows_found=int(end_row.get("instance_rows_found") or 0),
                window_use="structured_delta" if (duration_minutes or 0.0) > 0 else "context_only",
                window_reason="Adjacent completed snapshots were used for delta interval mapping.",
                mapping_quality="HIGH" if (duration_minutes or 0.0) >= 10.0 else "MEDIUM",
                notes=notes,
            )
        duration_minutes = _duration_minutes(_snapshot_begin(previous_row), _snapshot_end(previous_row))
        notes = ["Only a previous logical SNAP interval could be mapped for this run timestamp."]
        if selection_note:
            notes.append(selection_note)
        return AwrSnapshotWindowMapping(
            dbid=chain_dbid,
            instance_number=chain_instance,
            startup_time=chain_startup,
            begin_snap_id=_safe_int(previous_row.get("snap_id")),
            end_snap_id=_safe_int(previous_row.get("snap_id")),
            matched_snap_id=_safe_int(previous_row.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(previous_row)),
            end_time=_format_ts(_snapshot_end(previous_row)),
            matched_begin_time=_format_ts(_snapshot_begin(previous_row)),
            matched_end_time=_format_ts(_snapshot_end(previous_row)),
            duration_minutes=duration_minutes,
            instance_count=int(previous_row.get("instance_count") or 0),
            instance_rows_found=int(previous_row.get("instance_rows_found") or 0),
            window_use="context_only",
            window_reason="Only one completed snapshot was available; adjacent snapshot was missing.",
            mapping_quality="LOW",
            notes=notes,
        )

    if next_row is not None:
        duration_minutes = _duration_minutes(_snapshot_begin(next_row), _snapshot_end(next_row))
        notes = ["Only a future logical SNAP interval could be mapped for this run timestamp."]
        if selection_note:
            notes.append(selection_note)
        return AwrSnapshotWindowMapping(
            dbid=chain_dbid,
            instance_number=chain_instance,
            startup_time=chain_startup,
            begin_snap_id=_safe_int(next_row.get("snap_id")),
            end_snap_id=_safe_int(next_row.get("snap_id")),
            matched_snap_id=_safe_int(next_row.get("snap_id")),
            begin_time=_format_ts(_snapshot_begin(next_row)),
            end_time=_format_ts(_snapshot_end(next_row)),
            matched_begin_time=_format_ts(_snapshot_begin(next_row)),
            matched_end_time=_format_ts(_snapshot_end(next_row)),
            duration_minutes=duration_minutes,
            instance_count=int(next_row.get("instance_count") or 0),
            instance_rows_found=int(next_row.get("instance_rows_found") or 0),
            window_use="context_only",
            window_reason="Only a future snapshot interval was available.",
            mapping_quality="LOW",
            notes=notes,
        )

    return AwrSnapshotWindowMapping(
        dbid=effective_dbid,
        instance_number=effective_instance,
        startup_time=effective_startup,
        mapping_quality="NONE",
        window_use="context_only",
        window_reason="No snapshot rows matched the selected DBID/instance/startup chain.",
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
    previous_run_dt = _coerce_dt(previous_run_completed_at)
    current_run_dt = _coerce_dt(current_run_completed_at)

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

    expansion_applied = False
    adjacent_interval_mode = False

    previous, current, adjacent_notes, adjacent_interval_mode = _map_same_snap_pair_to_adjacent_intervals(
        previous=previous,
        current=current,
        dbid=dbid,
        previous_run_dt=previous_run_dt,
        current_run_dt=current_run_dt,
    )
    notes.extend(adjacent_notes)
    prev_quality = _mapping_quality_score(previous.mapping_quality)
    curr_quality = _mapping_quality_score(current.mapping_quality)
    comparability = min(prev_quality, curr_quality)
    if previous.dbid is not None and current.dbid is not None and previous.dbid != current.dbid:
        comparability = 0.0
        notes.append("AWR windows map to different DBID values; cross-DB comparison is not allowed.")
    if (
        previous.instance_number is not None
        and current.instance_number is not None
        and previous.instance_number != current.instance_number
    ):
        comparability = min(comparability, 0.2)
        notes.append("AWR windows map to different instance_number values; comparability is low.")
    if previous.startup_time and current.startup_time and previous.startup_time != current.startup_time:
        comparability = min(comparability, 0.6)
        notes.append("AWR windows map to different startup chains; comparison is medium-confidence context.")
    prev_duration = _safe_float(previous.duration_minutes)
    curr_duration = _safe_float(current.duration_minutes)
    if (prev_duration is not None and prev_duration <= 0) or (curr_duration is not None and curr_duration <= 0):
        comparability = min(comparability, 0.2)
        notes.append("One or more AWR windows have non-positive duration.")
    if (prev_duration is not None and prev_duration < 10.0) or (curr_duration is not None and curr_duration < 10.0):
        comparability = min(comparability, 0.6)
        notes.append("One or more AWR windows are shorter than 10 minutes.")

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
        if adjacent_interval_mode:
            comparability = min(comparability, 0.65)
        else:
            comparability = min(comparability, 0.2)
            notes.append("AWR trend comparison unavailable because previous and current runs map to the same snapshot window.")

    same_matched_snap = (
        previous.matched_snap_id is not None
        and current.matched_snap_id is not None
        and previous.matched_snap_id == current.matched_snap_id
    )
    if same_matched_snap and not expansion_applied and not adjacent_interval_mode:
        comparability *= 0.5
        notes.append("Both runs mapped to the same matched SNAP_ID; comparison is weak but still reported.")
    elif same_matched_snap and expansion_applied:
        notes.append("Matched SNAP_ID remained the same after expansion.")
    elif same_matched_snap and adjacent_interval_mode:
        comparability = min(comparability, 0.7)
        notes.append(
            "Both health runs mapped to the same completed AWR snapshot; AutoDBA used adjacent completed AWR intervals for structured comparison."
        )

    if adjacent_interval_mode and _valid_window(previous) and _valid_window(current):
        prev_dur = _safe_float(previous.duration_minutes) or 0.0
        curr_dur = _safe_float(current.duration_minutes) or 0.0
        if prev_dur > 0 and curr_dur > 0:
            comparability = max(comparability, 0.6)

    confidence = _comparability_to_confidence(comparability)
    same_snap_selected = same_matched_snap and not expansion_applied and not adjacent_interval_mode
    debug = {
        "previous_run_timestamp": _format_ts(previous_run_dt),
        "current_run_timestamp": _format_ts(current_run_dt),
        "mapped_previous_snap": previous.matched_snap_id or previous.end_snap_id or previous.begin_snap_id,
        "mapped_current_snap": current.matched_snap_id or current.end_snap_id or current.begin_snap_id,
        "previous_dbid": previous.dbid,
        "current_dbid": current.dbid,
        "previous_instance_number": previous.instance_number,
        "current_instance_number": current.instance_number,
        "previous_startup_time": previous.startup_time,
        "current_startup_time": current.startup_time,
        "previous_duration_min": previous.duration_minutes,
        "current_duration_min": current.duration_minutes,
        "previous_instance_rows_found": previous.instance_rows_found,
        "current_instance_rows_found": current.instance_rows_found,
        "previous_instance_count": previous.instance_count,
        "current_instance_count": current.instance_count,
        "same_snap_selected": same_snap_selected,
        "same_snap_adjacent_interval_mode": adjacent_interval_mode,
        "same_window_expansion_applied": expansion_applied,
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


def _expand_same_window_pair_if_needed(
    *,
    previous: AwrSnapshotWindowMapping,
    current: AwrSnapshotWindowMapping,
    dbid: int | None,
    previous_run_dt: datetime | None,
    current_run_dt: datetime | None,
) -> tuple[AwrSnapshotWindowMapping, AwrSnapshotWindowMapping, list[str], bool]:
    if not _valid_window(previous) or not _valid_window(current):
        return previous, current, [], False
    same_window = (
        previous.begin_snap_id is not None
        and previous.end_snap_id is not None
        and previous.begin_snap_id == current.begin_snap_id
        and previous.end_snap_id == current.end_snap_id
    )
    same_matched = (
        previous.matched_snap_id is not None
        and current.matched_snap_id is not None
        and previous.matched_snap_id == current.matched_snap_id
    )
    if not (same_window or same_matched):
        return previous, current, [], False

    if previous_run_dt is None or current_run_dt is None:
        return previous, current, [], False

    logical_snapshots = _load_logical_snapshots(
        dbid=dbid,
        instance_number=previous.instance_number or current.instance_number,
        startup_time=previous.startup_time or current.startup_time,
        scan_start=min(previous_run_dt, current_run_dt) - timedelta(hours=12),
        scan_end=max(previous_run_dt, current_run_dt) + timedelta(hours=12),
    )
    if not logical_snapshots:
        return previous, current, [], False

    ordered = sorted(logical_snapshots, key=lambda row: int(row.get("snap_id") or 0))
    snap_ids = [int(row.get("snap_id") or 0) for row in ordered]
    target_snap_id = _safe_int(previous.matched_snap_id) or _safe_int(previous.end_snap_id)
    if target_snap_id is None or target_snap_id not in snap_ids:
        return previous, current, [], False

    index = snap_ids.index(target_snap_id)
    if len(ordered) < 2:
        return previous, current, [], False

    prev_begin_idx = max(index - 1, 0)
    prev_end_idx = index
    curr_begin_idx = index
    curr_end_idx = min(index + 1, len(ordered) - 1)

    if prev_begin_idx == prev_end_idx and prev_end_idx < (len(ordered) - 1):
        prev_end_idx = prev_end_idx + 1
    if curr_begin_idx == curr_end_idx and curr_begin_idx > 0:
        curr_begin_idx = curr_begin_idx - 1

    previous_expanded = _expanded_window_from_rows(
        begin_row=ordered[prev_begin_idx],
        end_row=ordered[prev_end_idx],
        matched_row=ordered[index],
        dbid=dbid,
        instance_number=previous.instance_number or current.instance_number,
        startup_time=previous.startup_time or current.startup_time,
        note=(
            "Expanded previous run to nearest earlier snapshot interval to avoid same-window comparison."
        ),
    )
    current_expanded = _expanded_window_from_rows(
        begin_row=ordered[curr_begin_idx],
        end_row=ordered[curr_end_idx],
        matched_row=ordered[index],
        dbid=dbid,
        instance_number=previous.instance_number or current.instance_number,
        startup_time=previous.startup_time or current.startup_time,
        note=(
            "Expanded current run to nearest later snapshot interval to avoid same-window comparison."
        ),
    )
    notes = [
        "Detected same-window/same-SNAP mapping for run pair; attempted interval expansion for AWR comparability.",
        f"Expanded run-pair windows to previous SNAP {previous_expanded.begin_snap_id}..{previous_expanded.end_snap_id} "
        f"and current SNAP {current_expanded.begin_snap_id}..{current_expanded.end_snap_id}.",
    ]
    return previous_expanded, current_expanded, notes, True


def _map_same_snap_pair_to_adjacent_intervals(
    *,
    previous: AwrSnapshotWindowMapping,
    current: AwrSnapshotWindowMapping,
    dbid: int | None,
    previous_run_dt: datetime | None,
    current_run_dt: datetime | None,
) -> tuple[AwrSnapshotWindowMapping, AwrSnapshotWindowMapping, list[str], bool]:
    same_matched = (
        previous.matched_snap_id is not None
        and current.matched_snap_id is not None
        and previous.matched_snap_id == current.matched_snap_id
    )
    same_window = (
        previous.begin_snap_id is not None
        and previous.end_snap_id is not None
        and previous.begin_snap_id == current.begin_snap_id
        and previous.end_snap_id == current.end_snap_id
    )
    if not (same_matched or same_window):
        return previous, current, [], False

    if current_run_dt is None and previous_run_dt is None:
        return previous, current, [], False
    scan_anchor = current_run_dt or previous_run_dt
    assert scan_anchor is not None
    logical_snapshots = _load_logical_snapshots(
        dbid=dbid,
        instance_number=current.instance_number or previous.instance_number,
        startup_time=current.startup_time or previous.startup_time,
        scan_start=scan_anchor - timedelta(hours=24),
        scan_end=scan_anchor + timedelta(hours=2),
    )
    if not logical_snapshots:
        return previous, current, [], False

    ordered = sorted(logical_snapshots, key=lambda row: int(row.get("snap_id") or 0))
    target_snap_id = _safe_int(current.matched_snap_id) or _safe_int(current.end_snap_id) or _safe_int(previous.end_snap_id)
    if target_snap_id is None:
        return previous, current, [], False
    snap_ids = [int(row.get("snap_id") or 0) for row in ordered]
    if target_snap_id not in snap_ids:
        return previous, current, [], False
    idx_n = snap_ids.index(target_snap_id)

    notes: list[str] = []
    chain_dbid = _safe_int(current.dbid or previous.dbid or dbid)
    chain_inst = _safe_int(current.instance_number or previous.instance_number)
    chain_startup = current.startup_time or previous.startup_time
    if idx_n >= 1:
        curr_begin = ordered[idx_n - 1]
        curr_end = ordered[idx_n]
        current = _expanded_window_from_rows(
            begin_row=curr_begin,
            end_row=curr_end,
            matched_row=curr_end,
            dbid=chain_dbid,
            instance_number=chain_inst,
            startup_time=chain_startup,
            note="Current window mapped to adjacent completed interval N-1..N.",
        ).model_copy(
            update={
                "mapping_quality": "MEDIUM",
                "window_use": "structured_delta",
                "window_reason": "Adjacent completed snapshots were used for current structured delta window.",
            }
        )
    if idx_n >= 2:
        prev_begin = ordered[idx_n - 2]
        prev_end = ordered[idx_n - 1]
        previous = _expanded_window_from_rows(
            begin_row=prev_begin,
            end_row=prev_end,
            matched_row=prev_end,
            dbid=chain_dbid,
            instance_number=chain_inst,
            startup_time=chain_startup,
            note="Previous window mapped to adjacent completed interval N-2..N-1.",
        ).model_copy(
            update={
                "mapping_quality": "MEDIUM",
                "window_use": "baseline",
                "window_reason": "Adjacent completed snapshots were used for baseline delta window.",
            }
        )
        notes.append(
            "Both health runs mapped to the same completed AWR snapshot; AutoDBA used adjacent completed AWR intervals for structured comparison."
        )
        return previous, current, notes, True

    if idx_n < 2:
        previous = AwrSnapshotWindowMapping(
            dbid=chain_dbid,
            instance_number=chain_inst,
            startup_time=chain_startup,
            mapping_quality="LOW",
            window_use="context_only",
            window_reason="missing_previous_adjacent_snapshot",
            notes=["Previous adjacent snapshot (N-2..N-1) was not available."],
        )
        notes.append("Previous adjacent snapshot was missing; current interval is shown in single-window context mode.")
        return previous, current, notes, True

    return previous, current, notes, False


def _expanded_window_from_rows(
    *,
    begin_row: dict[str, Any],
    end_row: dict[str, Any],
    matched_row: dict[str, Any],
    dbid: int | None,
    instance_number: int | None,
    startup_time: str | None,
    note: str,
) -> AwrSnapshotWindowMapping:
    begin_time = _format_ts(_snapshot_begin(begin_row))
    end_time = _format_ts(_snapshot_end(end_row))
    matched_begin = _format_ts(_snapshot_begin(matched_row))
    matched_end = _format_ts(_snapshot_end(matched_row))
    instance_count = max(int(begin_row.get("instance_count") or 0), int(end_row.get("instance_count") or 0))
    instance_rows_found = max(int(begin_row.get("instance_rows_found") or 0), int(end_row.get("instance_rows_found") or 0))
    duration_minutes = _duration_minutes(_snapshot_begin(begin_row), _snapshot_end(end_row))
    return AwrSnapshotWindowMapping(
        dbid=_safe_int(dbid),
        instance_number=_safe_int(instance_number),
        startup_time=startup_time,
        begin_snap_id=_safe_int(begin_row.get("snap_id")),
        end_snap_id=_safe_int(end_row.get("snap_id")),
        matched_snap_id=_safe_int(matched_row.get("snap_id")),
        begin_time=begin_time,
        end_time=end_time,
        matched_begin_time=matched_begin,
        matched_end_time=matched_end,
        duration_minutes=duration_minutes,
        instance_count=instance_count,
        instance_rows_found=instance_rows_found,
        window_use="context_only",
        window_reason="Window expansion was used to avoid same-window comparison.",
        mapping_quality="MEDIUM",
        notes=[note],
    )


def _current_awr_identity(*, dbid_hint: int | None = None) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "dbid": _safe_int(dbid_hint),
        "instance_number": None,
        "instance_name": None,
        "startup_dt": None,
        "startup_time": None,
        "database_name": None,
        "database_role": None,
        "open_mode": None,
    }
    try:
        db_row = fetch_one(
            """
            select dbid, name, database_role, open_mode
            from v$database
            """
        ) or {}
        identity["dbid"] = _safe_int(db_row.get("dbid")) or identity["dbid"]
        identity["database_name"] = db_row.get("name")
        identity["database_role"] = db_row.get("database_role")
        identity["open_mode"] = db_row.get("open_mode")
    except Exception:
        pass
    try:
        rows = fetch_all(
            """
            select inst_id,
                   instance_number,
                   instance_name,
                   to_char(startup_time, 'YYYY-MM-DD"T"HH24:MI:SS') as startup_time,
                   case when inst_id = to_number(sys_context('USERENV', 'INSTANCE')) then 1 else 0 end as is_current
            from gv$instance
            order by is_current desc, inst_id
            """
        )
        row = rows[0] if rows else {}
        identity["instance_number"] = _safe_int(row.get("instance_number"))
        identity["instance_name"] = row.get("instance_name")
        startup_dt = _coerce_dt(row.get("startup_time"))
        identity["startup_dt"] = startup_dt
        identity["startup_time"] = _format_ts(startup_dt)
    except Exception:
        try:
            row = fetch_one(
                """
                select instance_number,
                       instance_name,
                       to_char(startup_time, 'YYYY-MM-DD"T"HH24:MI:SS') as startup_time
                from v$instance
                """
            ) or {}
            identity["instance_number"] = _safe_int(row.get("instance_number"))
            identity["instance_name"] = row.get("instance_name")
            startup_dt = _coerce_dt(row.get("startup_time"))
            identity["startup_dt"] = startup_dt
            identity["startup_time"] = _format_ts(startup_dt)
        except Exception:
            pass
    return identity


def _select_snapshot_chain(
    *,
    chains: dict[tuple[int | None, int | None, str | None], list[dict[str, Any]]],
    target_dt: datetime,
    start_dt: datetime,
    end_dt: datetime,
    preferred_dbid: int | None,
    preferred_instance: int | None,
    preferred_startup: datetime | None,
) -> tuple[tuple[int | None, int | None, str | None] | None, str, bool]:
    if not chains:
        return None, "", False
    ranked: list[tuple[float, tuple[int | None, int | None, str | None], str]] = []
    for key, rows in chains.items():
        if not rows:
            continue
        dbid_value, inst_value, startup_value = key
        contains_target = any(_snapshot_contains(row, target_dt) for row in rows)
        overlaps_window = any(_snapshot_end(row) > start_dt and _snapshot_begin(row) < end_dt for row in rows)
        score = 0.0
        reasons: list[str] = []
        if preferred_dbid is not None and dbid_value == preferred_dbid:
            score += 100.0
            reasons.append("dbid")
        if preferred_instance is not None and inst_value == preferred_instance:
            score += 40.0
            reasons.append("instance")
        startup_dt = _coerce_dt(startup_value)
        if preferred_startup is not None and startup_dt == preferred_startup:
            score += 60.0
            reasons.append("startup")
        if contains_target:
            score += 20.0
            reasons.append("contains_target")
        if overlaps_window:
            score += 10.0
            reasons.append("window_overlap")
        ranked.append((score, key, ",".join(reasons)))
    if not ranked:
        return None, "", False
    ranked.sort(key=lambda row: (row[0], _coerce_dt(row[1][2]) or datetime.min.replace(tzinfo=UTC)), reverse=True)
    selected = ranked[0]
    ambiguous = len(ranked) > 1 and abs(float(ranked[0][0]) - float(ranked[1][0])) < 5.0
    key = selected[1]
    note = (
        "Selected snapshot chain "
        f"DBID={key[0]}, instance={key[1]}, startup={key[2]} "
        f"(selection_score={selected[0]:.1f}, criteria={selected[2] or 'time_only'})."
    )
    return key, note, ambiguous


def _select_first_chain(
    chains: dict[tuple[int | None, int | None, str | None], list[dict[str, Any]]]
) -> tuple[int | None, int | None, str | None]:
    keys = sorted(chains.keys(), key=lambda key: (_coerce_dt(key[2]) or datetime.min.replace(tzinfo=UTC), key[0] or -1, key[1] or -1), reverse=True)
    return keys[0]


def build_awr_state_diff(
    *,
    window_mapping: AwrRunPairWindowMapping,
    capabilities: AwrCapabilities | None = None,
) -> AwrStateDiff:
    caps = capabilities or get_awr_capabilities()
    awr_mode = _awr_mode_for_mapping(window_mapping)
    diagnostic_rows = _build_snapshot_chain_diagnostic(window_mapping=window_mapping, dbid=(caps.dbid if caps else None))
    window_quality, window_use, window_reason, window_rows, window_notes = _assess_snapshot_windows(window_mapping)
    base_quality = AwrSnapshotQuality(
        window_quality=window_quality,
        usage=window_use,
        reason=window_reason,
        coverage_quality="LOW" if window_quality in {"LOW", "NONE"} else "MEDIUM",
        comparability_score=window_mapping.comparability_score,
        confidence="LOW" if window_quality in {"LOW", "NONE"} else window_mapping.confidence,
        diagnostic_rows=diagnostic_rows,
        window_rows=window_rows,
        notes=list(window_notes),
    )
    if not caps.available:
        return AwrStateDiff(
            available=False,
            awr_mode=awr_mode,
            capabilities=caps,
            window_mapping=window_mapping,
            snapshot_quality=base_quality.model_copy(
                update={
                    "coverage_quality": "NONE",
                    "comparability_score": 0.0,
                    "confidence": "LOW",
                    "notes": [*base_quality.notes, "AWR required views were unavailable."],
                }
            ),
            notes=["AWR state-diff skipped because required AWR components are unavailable."],
        )

    prev = window_mapping.previous
    curr = window_mapping.current
    if not _valid_window(prev) or not _valid_window(curr):
        if _valid_window(curr):
            notes = [
                "Previous adjacent AWR interval is missing; current AWR interval is available in single-window context mode.",
            ]
            snapshot_quality = base_quality.model_copy(
                update={
                    "window_quality": "LOW",
                    "usage": "context_only",
                    "reason": prev.window_reason or "missing_previous_adjacent_snapshot",
                    "coverage_quality": "LOW",
                    "comparability_score": min(window_mapping.comparability_score, 0.4),
                    "confidence": "LOW",
                    "notes": [*base_quality.notes, *notes],
                }
            )
            return AwrStateDiff(
                available=True,
                awr_mode="single_window_interpretation",
                capabilities=caps,
                window_mapping=window_mapping,
                snapshot_quality=snapshot_quality,
                notes=notes,
            )
        return AwrStateDiff(
            available=False,
            awr_mode=awr_mode,
            capabilities=caps,
            window_mapping=window_mapping,
            snapshot_quality=base_quality.model_copy(
                update={
                    "coverage_quality": "LOW",
                    "comparability_score": window_mapping.comparability_score,
                    "confidence": "LOW",
                    "notes": [*base_quality.notes, "Snapshot mapping was incomplete for one or both runs."],
                }
            ),
            notes=["AWR state-diff skipped because run-to-snapshot mapping was incomplete."],
        )

    if (
        prev.begin_snap_id is not None
        and prev.end_snap_id is not None
        and curr.begin_snap_id is not None
        and curr.end_snap_id is not None
        and prev.begin_snap_id == curr.begin_snap_id
        and prev.end_snap_id == curr.end_snap_id
    ):
        return AwrStateDiff(
            available=False,
            awr_mode="single_window_interpretation",
            capabilities=caps,
            window_mapping=window_mapping,
            snapshot_quality=base_quality.model_copy(
                update={
                    "window_quality": "LOW",
                    "usage": "context_only",
                    "reason": "Previous and current AWR windows map to the same snapshot interval.",
                    "coverage_quality": "LOW",
                    "comparability_score": min(window_mapping.comparability_score, 0.2),
                    "confidence": "LOW",
                    "notes": [
                        *base_quality.notes,
                        "AWR trend comparison unavailable because previous and current runs map to the same snapshot window.",
                    ],
                }
            ),
            notes=["AWR trend comparison unavailable because previous and current runs map to the same snapshot window."],
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
        window_quality=window_quality,
        usage=window_use,
        reason=window_reason,
        coverage_quality=_coverage_quality(coverage_ratio),
        comparability_score=round(comparability, 2),
        confidence=_comparability_to_confidence(comparability),
        diagnostic_rows=diagnostic_rows,
        window_rows=window_rows,
        notes=[*_quality_notes(coverage_ratio, window_mapping), *window_notes],
    )

    if snapshot_quality.coverage_quality in {"LOW", "NONE"}:
        notes.append("AWR snapshots were mapped but metric rows were incomplete; partial AWR comparison was produced.")
    if window_mapping.debug.get("same_snap_selected"):
        notes.append("AWR snapshots mapped successfully but both runs resolved to the same SNAP_ID; comparison is weak.")
    structured_sections = _build_structured_awr_sections(
        previous_window=prev,
        current_window=curr,
        snapshot_quality=snapshot_quality,
        workload_metrics=workload_metrics,
        wait_shift=wait_shift,
        sql_change=sql_change,
        notes=notes,
    )

    return AwrStateDiff(
        available=True,
        awr_mode=awr_mode,
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
        structured_sections=structured_sections,
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


def generate_awr_report_text(
    *,
    dbid: int | None,
    begin_snap_id: int | None,
    end_snap_id: int | None,
    instance_number: int | None = None,
    max_lines: int = 4000,
) -> list[str]:
    bid = _safe_int(begin_snap_id)
    eid = _safe_int(end_snap_id)
    if bid is None or eid is None or eid < bid:
        return []
    if dbid is None:
        return []

    inst_num = _safe_int(instance_number) or _default_awr_instance_number() or 1
    rows = fetch_all(
        """
        select output
        from table(dbms_workload_repository.awr_report_text(:dbid, :inst_num, :begin_snap_id, :end_snap_id, 0))
        """,
        {
            "dbid": int(dbid),
            "inst_num": int(inst_num),
            "begin_snap_id": int(bid),
            "end_snap_id": int(eid),
        },
    )
    lines: list[str] = []
    for row in rows[: max(int(max_lines), 1)]:
        text = str((row or {}).get("output") or "").rstrip()
        if text:
            lines.append(text)
    return lines


def summarize_awr_report_text(
    report_lines: list[str],
    *,
    dbid: int | None,
    instance_number: int | None,
    begin_snap_id: int | None,
    end_snap_id: int | None,
) -> AwrReportTextSummary:
    cleaned = [str(line).rstrip() for line in report_lines if str(line or "").strip()]
    if not cleaned:
        return AwrReportTextSummary(
            available=False,
            source="DBMS_WORKLOAD_REPOSITORY.AWR_REPORT_TEXT",
            dbid=dbid,
            instance_number=instance_number,
            begin_snap_id=begin_snap_id,
            end_snap_id=end_snap_id,
            notes=["AWR report text returned no lines for this snapshot interval."],
        )

    load_profile_summary = _build_awr_load_profile_summary(cleaned)
    main_bottlenecks = _build_awr_bottleneck_summary(cleaned)
    sql_contributors = _extract_awr_sql_contributors(
        cleaned,
        max_items=6,
        db_time_s=_extract_db_time_seconds(cleaned),
    )
    recommended_follow_up = _derive_awr_follow_up(
        load_profile_summary=load_profile_summary,
        main_bottlenecks=main_bottlenecks,
        sql_contributors=sql_contributors,
    )
    interpretation_summary = _build_awr_interpretation_summary(
        load_profile_summary=load_profile_summary,
        main_bottlenecks=main_bottlenecks,
        sql_contributors=sql_contributors,
    )

    return AwrReportTextSummary(
        available=True,
        source="DBMS_WORKLOAD_REPOSITORY.AWR_REPORT_TEXT",
        dbid=dbid,
        instance_number=instance_number,
        begin_snap_id=begin_snap_id,
        end_snap_id=end_snap_id,
        line_count=len(cleaned),
        load_profile_summary=load_profile_summary,
        main_bottlenecks=main_bottlenecks,
        sql_contributors=sql_contributors,
        recommended_follow_up=recommended_follow_up,
        interpretation_summary=interpretation_summary,
    )


def get_awr_report_text_summary_for_window(
    *,
    window: AwrSnapshotWindowMapping,
    dbid: int | None = None,
    instance_number: int | None = None,
) -> AwrReportTextSummary:
    effective_dbid = _safe_int(dbid) or _safe_int(window.dbid)
    bid = _safe_int(window.begin_snap_id)
    eid = _safe_int(window.end_snap_id)
    if effective_dbid is None or bid is None or eid is None or eid < bid:
        return AwrReportTextSummary(
            available=False,
            source="DBMS_WORKLOAD_REPOSITORY.AWR_REPORT_TEXT",
            dbid=effective_dbid,
            instance_number=_safe_int(instance_number),
            begin_snap_id=bid,
            end_snap_id=eid,
            notes=["Snapshot interval was incomplete; AWR report text summary was skipped."],
        )
    try:
        effective_inst = _safe_int(instance_number) or _default_awr_instance_number() or 1
        lines = generate_awr_report_text(
            dbid=effective_dbid,
            begin_snap_id=bid,
            end_snap_id=eid,
            instance_number=effective_inst,
        )
        return summarize_awr_report_text(
            lines,
            dbid=effective_dbid,
            instance_number=effective_inst,
            begin_snap_id=bid,
            end_snap_id=eid,
        )
    except Exception as exc:
        return AwrReportTextSummary(
            available=False,
            source="DBMS_WORKLOAD_REPOSITORY.AWR_REPORT_TEXT",
            dbid=effective_dbid,
            instance_number=_safe_int(instance_number),
            begin_snap_id=bid,
            end_snap_id=eid,
            notes=[f"AWR report text summary failed: {exc}"],
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


def _window_binds(window: AwrSnapshotWindowMapping) -> dict[str, Any] | None:
    dbid = _safe_int(window.dbid)
    instance_number = _safe_int(window.instance_number)
    begin_snap_id = _safe_int(window.begin_snap_id)
    end_snap_id = _safe_int(window.end_snap_id)
    if dbid is None or instance_number is None or begin_snap_id is None or end_snap_id is None:
        return None
    return {
        "dbid": dbid,
        "instance_number": instance_number,
        "startup_time": window.startup_time,
        "begin_snap_id": begin_snap_id,
        "end_snap_id": end_snap_id,
    }


def _build_structured_awr_sections(
    *,
    previous_window: AwrSnapshotWindowMapping,
    current_window: AwrSnapshotWindowMapping,
    snapshot_quality: AwrSnapshotQuality,
    workload_metrics: list[AwrMetricDelta],
    wait_shift: AwrWaitClassShift,
    sql_change: AwrSqlChangeIntelligence,
    notes: list[str],
) -> dict[str, Any]:
    unavailable_reasons: list[str] = []
    if not _valid_window(previous_window):
        unavailable_reasons.append(previous_window.window_reason or "missing_previous_adjacent_snapshot")
    if not _valid_window(current_window):
        unavailable_reasons.append(current_window.window_reason or "missing_current_adjacent_snapshot")
    if previous_window.dbid and current_window.dbid and previous_window.dbid != current_window.dbid:
        unavailable_reasons.append("dbid_mismatch")
    if (
        previous_window.instance_number
        and current_window.instance_number
        and previous_window.instance_number != current_window.instance_number
    ):
        unavailable_reasons.append("instance_mismatch")
    current_duration = _safe_float(current_window.duration_minutes)
    prev_time_model, prev_time_reasons = _collect_counter_deltas(
        window=previous_window,
        notes=notes,
        label="previous_structured_workload_tm",
        source_name="dba_hist_sys_time_model",
        stat_names=_TIME_MODEL_STAT_NAMES,
        sql="""
            select tm.stat_name as stat_name,
                   s.snap_id as snap_id,
                   tm.value as value
            from dba_hist_sys_time_model tm
            join dba_hist_snapshot s
              on s.dbid = tm.dbid
             and s.instance_number = tm.instance_number
             and s.snap_id = tm.snap_id
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id in (:begin_snap_id, :end_snap_id)
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and tm.stat_name in (
                  'DB time',
                  'DB CPU',
                  'background elapsed time',
                  'background cpu time',
                  'sql execute elapsed time',
                  'parse time elapsed',
                  'hard parse elapsed time'
              )
        """,
        scale=1e6,
        normalize=False,
    )
    curr_time_model, curr_time_reasons = _collect_counter_deltas(
        window=current_window,
        notes=notes,
        label="current_structured_workload_tm",
        source_name="dba_hist_sys_time_model",
        stat_names=_TIME_MODEL_STAT_NAMES,
        sql="""
            select tm.stat_name as stat_name,
                   s.snap_id as snap_id,
                   tm.value as value
            from dba_hist_sys_time_model tm
            join dba_hist_snapshot s
              on s.dbid = tm.dbid
             and s.instance_number = tm.instance_number
             and s.snap_id = tm.snap_id
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id in (:begin_snap_id, :end_snap_id)
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and tm.stat_name in (
                  'DB time',
                  'DB CPU',
                  'background elapsed time',
                  'background cpu time',
                  'sql execute elapsed time',
                  'parse time elapsed',
                  'hard parse elapsed time'
              )
        """,
        scale=1e6,
        normalize=False,
    )
    prev_sysstat, prev_sys_reasons = _collect_counter_deltas(
        window=previous_window,
        notes=notes,
        label="previous_structured_workload_sysstat",
        source_name="dba_hist_sysstat",
        stat_names=_SYSSTAT_NAMES,
        sql="""
            select lower(n.stat_name) as stat_name,
                   snap.snap_id as snap_id,
                   s.value as value
            from dba_hist_sysstat s
            join dba_hist_stat_name n
              on n.dbid = s.dbid
             and n.stat_id = s.stat_id
            join dba_hist_snapshot snap
              on snap.dbid = s.dbid
             and snap.instance_number = s.instance_number
             and snap.snap_id = s.snap_id
            where snap.dbid = :dbid
              and snap.instance_number = :instance_number
              and snap.snap_id in (:begin_snap_id, :end_snap_id)
              and (:startup_time is null or to_char(snap.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and lower(n.stat_name) in (
                  'execute count',
                  'parse count (total)',
                  'parse count (hard)',
                  'user commits',
                  'user rollbacks',
                  'redo size',
                  'session logical reads',
                  'physical reads',
                  'physical writes',
                  'db block changes',
                  'opened cursors cumulative',
                  'logons cumulative',
                  'physical read total io requests',
                  'physical write total io requests',
                  'physical read total bytes',
                  'physical write total bytes',
                  'redo writes',
                  'physical reads direct',
                  'physical writes direct'
              )
        """,
        scale=1.0,
        normalize=True,
    )
    curr_sysstat, curr_sys_reasons = _collect_counter_deltas(
        window=current_window,
        notes=notes,
        label="current_structured_workload_sysstat",
        source_name="dba_hist_sysstat",
        stat_names=_SYSSTAT_NAMES,
        sql="""
            select lower(n.stat_name) as stat_name,
                   snap.snap_id as snap_id,
                   s.value as value
            from dba_hist_sysstat s
            join dba_hist_stat_name n
              on n.dbid = s.dbid
             and n.stat_id = s.stat_id
            join dba_hist_snapshot snap
              on snap.dbid = s.dbid
             and snap.instance_number = s.instance_number
             and snap.snap_id = s.snap_id
            where snap.dbid = :dbid
              and snap.instance_number = :instance_number
              and snap.snap_id in (:begin_snap_id, :end_snap_id)
              and (:startup_time is null or to_char(snap.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and lower(n.stat_name) in (
                  'execute count',
                  'parse count (total)',
                  'parse count (hard)',
                  'user commits',
                  'user rollbacks',
                  'redo size',
                  'session logical reads',
                  'physical reads',
                  'physical writes',
                  'db block changes',
                  'opened cursors cumulative',
                  'logons cumulative',
                  'physical read total io requests',
                  'physical write total io requests',
                  'physical read total bytes',
                  'physical write total bytes',
                  'redo writes',
                  'physical reads direct',
                  'physical writes direct'
              )
        """,
        scale=1.0,
        normalize=True,
    )
    metric_sources: list[tuple[str, str, dict[str, float | None], dict[str, str], dict[str, float | None], dict[str, str]]] = [
        ("DB Time", "DB time", prev_time_model, prev_time_reasons, curr_time_model, curr_time_reasons),
        ("DB CPU", "DB CPU", prev_time_model, prev_time_reasons, curr_time_model, curr_time_reasons),
        ("background elapsed time", "background elapsed time", prev_time_model, prev_time_reasons, curr_time_model, curr_time_reasons),
        ("background cpu time", "background cpu time", prev_time_model, prev_time_reasons, curr_time_model, curr_time_reasons),
        ("sql execute elapsed time", "sql execute elapsed time", prev_time_model, prev_time_reasons, curr_time_model, curr_time_reasons),
        ("parse time elapsed", "parse time elapsed", prev_time_model, prev_time_reasons, curr_time_model, curr_time_reasons),
        ("hard parse elapsed time", "hard parse elapsed time", prev_time_model, prev_time_reasons, curr_time_model, curr_time_reasons),
        ("execute count", "execute count", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("parse count (total)", "parse count (total)", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("parse count (hard)", "parse count (hard)", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("user commits", "user commits", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("user rollbacks", "user rollbacks", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("redo size", "redo size", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("session logical reads", "session logical reads", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("physical reads", "physical reads", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("physical writes", "physical writes", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
        ("db block changes", "db block changes", prev_sysstat, prev_sys_reasons, curr_sysstat, curr_sys_reasons),
    ]
    workload_rows: list[dict[str, Any]] = []
    for display_name, stat_key, prev_values, prev_reasons, curr_values, curr_reasons in metric_sources:
        prev_val = _safe_float(prev_values.get(stat_key))
        curr_val = _safe_float(curr_values.get(stat_key))
        delta_val = _delta(prev_val, curr_val)
        per_min = (curr_val / current_duration) if curr_val is not None and current_duration and current_duration > 0 else None
        reason_prev = prev_reasons.get(stat_key)
        reason_curr = curr_reasons.get(stat_key)
        interpretation = (
            _metric_change_interpretation(display_name, prev_val, curr_val, delta_val, _pct_change(prev_val, curr_val), "LOW")
            if prev_val is not None and curr_val is not None
            else _compose_unavailable_reason(reason_prev=reason_prev, reason_curr=reason_curr)
        )
        workload_rows.append(
            {
                "Metric": display_name,
                "Previous": prev_val,
                "Current": curr_val,
                "Delta": delta_val,
                "Per Min": round(per_min, 3) if per_min is not None else None,
                "Interpretation": interpretation,
            }
        )

    db_time_prev = _safe_float(prev_time_model.get("DB time"))
    db_time_curr = _safe_float(curr_time_model.get("DB time"))

    wait_prev = {str(row.get("wait_class") or "Other"): _safe_float(row.get("time_waited_s")) or 0.0 for row in wait_shift.wait_classes_previous}
    wait_curr = {str(row.get("wait_class") or "Other"): _safe_float(row.get("time_waited_s")) or 0.0 for row in wait_shift.wait_classes_current}
    wait_rows: list[dict[str, Any]] = []
    for wait_class in sorted(set(wait_prev) | set(wait_curr)):
        prev_v = wait_prev.get(wait_class, 0.0)
        curr_v = wait_curr.get(wait_class, 0.0)
        delta_v = curr_v - prev_v
        wait_rows.append(
            {
                "Wait Class": wait_class,
                "Previous Wait s": round(prev_v, 3),
                "Current Wait s": round(curr_v, 3),
                "Delta s": round(delta_v, 3),
                "Current % DB Time": round(((curr_v / db_time_curr) * 100.0), 2) if db_time_curr and db_time_curr > 0 else None,
                "Interpretation": _wait_class_shift_interpretation(wait_class=wait_class, delta_s=delta_v),
            }
        )
    if not wait_rows:
        unavailable_reasons.append("no_rows_in_dba_hist_system_event_for_window")

    wait_event_rows = _build_top_wait_event_rows(
        previous_events=wait_shift.top_foreground_events_previous,
        current_events=wait_shift.top_foreground_events_current,
    )
    if not wait_event_rows:
        unavailable_reasons.append("no_rows_in_dba_hist_system_event_for_window")
        wait_query_errors = [
            str(note).split("query_error=", 1)[1].strip()
            for note in notes
            if "wait-event extraction failed: query_error=" in str(note)
        ]
        if wait_query_errors:
            unavailable_reasons.append(f"query_error={wait_query_errors[-1]}")
    sql_delta_rows = _build_sql_delta_rows(
        previous_rows=sql_change.top_sql_by_elapsed_previous,
        current_rows=sql_change.top_sql_by_elapsed_current,
        db_time_current=db_time_curr,
    )
    plan_rows = _build_plan_stability_rows(
        previous_rows=sql_change.top_sql_by_elapsed_previous,
        current_rows=sql_change.top_sql_by_elapsed_current,
    )
    ash_rows = _collect_ash_concurrency_rows(current_window, notes=notes, label="current")
    object_rows = _collect_object_hotspot_rows(current_window, notes=notes, label="current")
    redo_rows = _build_redo_commit_rows(
        previous_window=previous_window,
        current_window=current_window,
        notes=notes,
    )
    recommendation_rows = _build_awr_recommendations(
        snapshot_quality=snapshot_quality,
        wait_event_rows=wait_event_rows,
        sql_delta_rows=sql_delta_rows,
        ash_rows=ash_rows,
        db_time_current=db_time_curr,
        db_time_previous=db_time_prev,
    )
    confidence_rows = [
        {"Item": "AWR mode", "Value": "structured DBA_HIST comparison"},
        {"Item": "Previous window", "Value": f"snap {previous_window.begin_snap_id}..{previous_window.end_snap_id}"},
        {"Item": "Current window", "Value": f"snap {current_window.begin_snap_id}..{current_window.end_snap_id}"},
        {"Item": "Current window quality", "Value": snapshot_quality.window_quality},
        {"Item": "Confidence cap", "Value": "LOW" if snapshot_quality.window_quality == "LOW" else snapshot_quality.confidence},
        {"Item": "Missing data", "Value": "; ".join(_missing_section_items(sql_delta_rows, ash_rows, object_rows)) or "none"},
    ]
    unavailable_reasons = list(dict.fromkeys(unavailable_reasons))

    return {
        "snapshot_chain_diagnostic": snapshot_quality.diagnostic_rows,
        "snapshot_windows": snapshot_quality.window_rows,
        "snapshot_quality": {
            "quality": snapshot_quality.window_quality,
            "use": snapshot_quality.usage,
            "reason": snapshot_quality.reason,
        },
        "workload_delta": workload_rows,
        "wait_class_shift": wait_rows,
        "top_wait_events": wait_event_rows,
        "sql_delta": sql_delta_rows,
        "plan_stability": plan_rows,
        "ash_blocking": ash_rows,
        "object_hotspots": object_rows,
        "redo_commit_profile": redo_rows,
        "current_correlation": [],
        "dba_recommendations": recommendation_rows,
        "confidence_coverage": confidence_rows,
        "unavailable_reasons": unavailable_reasons,
    }


def _metric_value(metrics: list[AwrMetricDelta], metric_name: str, *, field: str) -> float | None:
    for metric in metrics:
        if metric.metric_name == metric_name:
            return _safe_float(getattr(metric, field, None))
    return None


def _wait_class_shift_interpretation(*, wait_class: str, delta_s: float) -> str:
    lowered = wait_class.lower()
    if delta_s <= 0:
        return "stable_or_lower"
    if lowered in {"application", "concurrency"}:
        return "growth suggests blocking/contention pressure."
    if lowered in {"user i/o", "system i/o"}:
        return "validate latency before concluding I/O bottleneck."
    if lowered == "commit":
        return "check log file sync and log file parallel write latency."
    return "increased wait contribution."


def _build_top_wait_event_rows(*, previous_events: list[dict[str, Any]], current_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prev_map = {str(row.get("event_name") or ""): row for row in previous_events}
    curr_map = {str(row.get("event_name") or ""): row for row in current_events}
    rows: list[dict[str, Any]] = []
    for event_name in list(curr_map.keys())[:15]:
        curr = curr_map.get(event_name) or {}
        prev = prev_map.get(event_name) or {}
        prev_wait_s = _safe_float(prev.get("time_waited_s")) or 0.0
        curr_wait_s = _safe_float(curr.get("time_waited_s")) or 0.0
        waits = _safe_float(curr.get("waits")) or 0.0
        avg_wait_ms = (curr_wait_s * 1000.0 / waits) if waits > 0 else None
        impact = _wait_latency_impact(avg_wait_ms=avg_wait_ms, wait_s=curr_wait_s)
        rows.append(
            {
                "Event": event_name,
                "Wait Class": curr.get("wait_class") or prev.get("wait_class") or "Other",
                "Prev Wait s": round(prev_wait_s, 3),
                "Curr Wait s": round(curr_wait_s, 3),
                "Delta s": round(curr_wait_s - prev_wait_s, 3),
                "Waits": int(waits) if waits else 0,
                "Avg Latency": round(avg_wait_ms, 3) if avg_wait_ms is not None else None,
                "Impact": impact,
                "DBA Interpretation": _event_interpretation(event=event_name, impact=impact),
            }
        )
    return rows


def _wait_latency_impact(*, avg_wait_ms: float | None, wait_s: float) -> str:
    if avg_wait_ms is None:
        return "candidate"
    if avg_wait_ms < 1.0:
        return "negligible"
    if avg_wait_ms < 10.0:
        return "noticeable"
    if avg_wait_ms < 20.0:
        return "warning"
    if wait_s < 5.0:
        return "warning"
    return "high_candidate"


def _event_interpretation(*, event: str, impact: str) -> str:
    lowered = event.lower()
    if "enq: tx" in lowered:
        return "row-lock contention candidate." if impact != "negligible" else "low-latency lock signal; watch only."
    if "log file sync" in lowered:
        return "commit latency signal."
    if "db file sequential read" in lowered and impact == "negligible":
        return "I/O latency negligible in this window."
    return f"impact={impact}"


def _build_sql_delta_rows(
    *,
    previous_rows: list[dict[str, Any]],
    current_rows: list[dict[str, Any]],
    db_time_current: float | None,
) -> list[dict[str, Any]]:
    prev_map = {str(row.get("sql_id") or ""): row for row in previous_rows}
    rows: list[dict[str, Any]] = []
    for row in current_rows[:20]:
        sql_id = str(row.get("sql_id") or "")
        prev = prev_map.get(sql_id) or {}
        execs = _safe_float(row.get("executions")) or 0.0
        elapsed_s = _safe_float(row.get("elapsed_s")) or 0.0
        elapsed_per_exec = _safe_float(row.get("elapsed_per_exec_s")) if execs > 0 else None
        db_time_share = ((elapsed_s / db_time_current) * 100.0) if db_time_current and db_time_current > 0 else None
        plan_hash_value = _safe_int(row.get("plan_hash_value")) or 0
        app_wait_s = _safe_float(row.get("app_wait_s")) or 0.0
        io_wait_s = _safe_float(row.get("io_wait_s")) or 0.0
        conc_wait_s = _safe_float(row.get("conc_wait_s")) or 0.0
        cpu_s = _safe_float(row.get("cpu_s")) or 0.0
        classification = _sql_row_classification(
            sql_id=sql_id,
            plan_hash_value=plan_hash_value,
            elapsed_s=elapsed_s,
            db_time_current=db_time_current,
            db_time_share=db_time_share,
        )
        interpretation = _sql_delta_interpretation(
            plan_hash_value=plan_hash_value,
            elapsed_s=elapsed_s,
            app_wait_s=app_wait_s,
            io_wait_s=io_wait_s,
            conc_wait_s=conc_wait_s,
            cpu_s=cpu_s,
        )
        rows.append(
            {
                "SQL_ID": sql_id,
                "Plan": plan_hash_value,
                "Schema": row.get("parsing_schema_name"),
                "Module": row.get("module"),
                "Execs": int(execs),
                "Elapsed s": round(elapsed_s, 3),
                "Elapsed/Exec s": round(elapsed_per_exec, 6) if elapsed_per_exec is not None else "N/A",
                "CPU s": round(cpu_s, 3),
                "I/O Wait s": round(io_wait_s, 3),
                "App Wait s": round(app_wait_s, 3),
                "Conc Wait s": round(conc_wait_s, 3),
                "Gets/Exec": row.get("gets_per_exec"),
                "Reads/Exec": row.get("reads_per_exec"),
                "DB Time %": round(db_time_share, 2) if db_time_share is not None else None,
                "Classification": classification,
                "sql_text_sample": row.get("sql_text_sample"),
                "Interpretation": interpretation,
                "previous_elapsed_s": _safe_float(prev.get("elapsed_s")),
            }
        )
    return rows


def _sql_delta_interpretation(
    *,
    plan_hash_value: int,
    elapsed_s: float,
    app_wait_s: float,
    io_wait_s: float,
    conc_wait_s: float,
    cpu_s: float,
) -> str:
    if plan_hash_value == 0 and app_wait_s >= max(io_wait_s, conc_wait_s, cpu_s) and app_wait_s >= (elapsed_s * 0.5):
        return "PL/SQL/internal wrapper dominated by Application wait; correlate with AWR ASH blocking/object hotspot."
    if elapsed_s < 30.0:
        return "Low elapsed contribution in this AWR window; candidate only."
    return "Review with current evidence to confirm active contributor."


def _sql_row_classification(
    *,
    sql_id: str,
    plan_hash_value: int,
    elapsed_s: float,
    db_time_current: float | None,
    db_time_share: float | None,
) -> str:
    if plan_hash_value == 0:
        return "PL_SQL_WRAPPER_OR_INTERNAL"
    if elapsed_s < 30.0 and (db_time_current or 0.0) < 60.0:
        return "candidate_only"
    if elapsed_s >= 30.0 or (db_time_share or 0.0) >= 20.0:
        return "significant_contributor"
    if not sql_id:
        return "unknown"
    return "candidate"


def _build_plan_stability_rows(
    *,
    previous_rows: list[dict[str, Any]],
    current_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if current_rows and all((_safe_int(row.get("plan_hash_value")) or 0) == 0 for row in current_rows[:12]):
        return [
            {
                "SQL_ID": "N/A",
                "Plans": 0,
                "Previous Plan": 0,
                "Current Plan": 0,
                "Plan Changed": False,
                "Prev Elapsed/Exec": None,
                "Curr Elapsed/Exec": None,
                "Regression Evidence": "Plan stability not evaluated because top AWR SQL rows have plan_hash_value=0 (PL/SQL wrapper/internal statements).",
            }
        ]
    prev_map = {str(row.get("sql_id") or ""): row for row in previous_rows}
    rows: list[dict[str, Any]] = []
    for row in current_rows[:12]:
        sql_id = str(row.get("sql_id") or "")
        prev = prev_map.get(sql_id) or {}
        curr_plan = _safe_int(row.get("plan_hash_value")) or 0
        prev_plan = _safe_int(prev.get("plan_hash_value")) or 0
        if curr_plan == 0:
            regression = "plan hash is 0; plan churn not evaluated."
        else:
            prev_per_exec = _safe_float(prev.get("elapsed_per_exec_s"))
            curr_per_exec = _safe_float(row.get("elapsed_per_exec_s"))
            regressed = prev_per_exec is not None and curr_per_exec is not None and curr_per_exec > (prev_per_exec * 1.3)
            regression = "worsened per-exec elapsed after plan change." if regressed and prev_plan != curr_plan else "no material plan regression evidence."
        rows.append(
            {
                "SQL_ID": sql_id,
                "Plans": _safe_int(row.get("plan_hash_count")) or 0,
                "Previous Plan": prev_plan,
                "Current Plan": curr_plan,
                "Plan Changed": bool(prev_plan and curr_plan and prev_plan != curr_plan),
                "Prev Elapsed/Exec": prev.get("elapsed_per_exec_s"),
                "Curr Elapsed/Exec": row.get("elapsed_per_exec_s"),
                "Regression Evidence": regression,
            }
        )
    return rows


def _collect_ash_concurrency_rows(window: AwrSnapshotWindowMapping, *, notes: list[str], label: str) -> list[dict[str, Any]]:
    binds = _window_binds(window)
    if binds is None:
        return []
    try:
        rows = fetch_all(
            """
            select ash.event,
                   ash.wait_class,
                   ash.blocking_inst_id,
                   ash.blocking_session as blocking_sid,
                   ash.sql_id,
                   ash.current_obj#,
                   count(*) as samples,
                   count(distinct ash.session_id) as distinct_waiters
            from dba_hist_active_sess_history ash
            join dba_hist_snapshot s
              on s.dbid = ash.dbid
             and s.instance_number = ash.instance_number
             and s.snap_id = ash.snap_id
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id between :begin_snap_id and :end_snap_id
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and (
                    ash.wait_class in ('Application','Concurrency')
                    or ash.event like 'enq:%'
                    or ash.blocking_session is not null
              )
            group by ash.event, ash.wait_class, ash.blocking_inst_id, ash.blocking_session, ash.sql_id, ash.current_obj#
            order by samples desc
            fetch first 20 rows only
            """,
            binds,
        )
        return [
            {
                "Event": row.get("event"),
                "Wait Class": row.get("wait_class"),
                "Samples": _safe_int(row.get("samples")) or 0,
                "Distinct Waiters": _safe_int(row.get("distinct_waiters")) or 0,
                "Blocking Inst": _safe_int(row.get("blocking_inst_id")),
                "Blocking SID": _safe_int(row.get("blocking_sid")),
                "Top SQL_ID": row.get("sql_id"),
                "Object": row.get("current_obj#"),
                "Interpretation": "blocking/concurrency sample",
            }
            for row in rows
        ]
    except Exception as exc:
        notes.append(f"{label} ASH concurrency extraction failed: {exc}")
        return []


def _collect_object_hotspot_rows(window: AwrSnapshotWindowMapping, *, notes: list[str], label: str) -> list[dict[str, Any]]:
    binds = _window_binds(window)
    if binds is None:
        return []
    try:
        rows = fetch_all(
            """
            select o.owner || '.' || o.object_name as object_name,
                   o.object_type,
                   ash.event,
                   ash.wait_class,
                   ash.sql_id,
                   count(*) as samples
            from dba_hist_active_sess_history ash
            join dba_hist_snapshot s
              on s.dbid = ash.dbid
             and s.instance_number = ash.instance_number
             and s.snap_id = ash.snap_id
            join dba_objects o
              on o.object_id = ash.current_obj#
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id between :begin_snap_id and :end_snap_id
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and ash.current_obj# > 0
            group by o.owner, o.object_name, o.object_type, ash.event, ash.wait_class, ash.sql_id
            order by samples desc
            fetch first 20 rows only
            """,
            binds,
        )
        return [
            {
                "Object": row.get("object_name"),
                "Object Type": row.get("object_type"),
                "Event": row.get("event"),
                "Wait Class": row.get("wait_class"),
                "Samples": _safe_int(row.get("samples")) or 0,
                "Top SQL_ID": row.get("sql_id"),
                "Interpretation": "object hotspot candidate",
            }
            for row in rows
        ]
    except Exception as exc:
        notes.append(f"{label} ASH object-hotspot extraction failed: {exc}")
        return []


def _build_redo_commit_rows(
    *,
    previous_window: AwrSnapshotWindowMapping,
    current_window: AwrSnapshotWindowMapping,
    notes: list[str],
) -> list[dict[str, Any]]:
    prev_stats = _collect_sysstat(previous_window, notes, label="previous_redo")
    curr_stats = _collect_sysstat(current_window, notes, label="current_redo")
    prev_redo = _safe_float(prev_stats.get("redo size"))
    curr_redo = _safe_float(curr_stats.get("redo size"))
    prev_commits = _safe_float(prev_stats.get("user commits"))
    curr_commits = _safe_float(curr_stats.get("user commits"))
    prev_rollbacks = _safe_float(prev_stats.get("user rollbacks"))
    curr_rollbacks = _safe_float(curr_stats.get("user rollbacks"))
    prev_redo_per_commit = _ratio(prev_redo, prev_commits)
    curr_redo_per_commit = _ratio(curr_redo, curr_commits)
    prev_waits, prev_wait_reasons = _collect_wait_event_deltas(
        previous_window,
        event_names=["log file sync", "log file parallel write"],
        notes=notes,
        label="previous_redo_wait",
    )
    curr_waits, curr_wait_reasons = _collect_wait_event_deltas(
        current_window,
        event_names=["log file sync", "log file parallel write"],
        notes=notes,
        label="current_redo_wait",
    )

    def _latency(event_name: str, rows: dict[str, dict[str, float]]) -> float | None:
        return _safe_float((rows.get(event_name.lower()) or {}).get("avg_wait_ms"))

    prev_lfs = _latency("log file sync", prev_waits)
    curr_lfs = _latency("log file sync", curr_waits)
    prev_lfpw = _latency("log file parallel write", prev_waits)
    curr_lfpw = _latency("log file parallel write", curr_waits)

    missing_wait_reason = (
        prev_wait_reasons.get("log file sync")
        or curr_wait_reasons.get("log file sync")
        or prev_wait_reasons.get("log file parallel write")
        or curr_wait_reasons.get("log file parallel write")
    )

    return [
        {"Metric": "redo size", "Previous": prev_redo, "Current": curr_redo, "Delta": _delta(prev_redo, curr_redo), "Interpretation": "redo volume context"},
        {"Metric": "user commits", "Previous": prev_commits, "Current": curr_commits, "Delta": _delta(prev_commits, curr_commits), "Interpretation": "commit volume context"},
        {"Metric": "user rollbacks", "Previous": prev_rollbacks, "Current": curr_rollbacks, "Delta": _delta(prev_rollbacks, curr_rollbacks), "Interpretation": "rollback volume context"},
        {"Metric": "redo per commit", "Previous": prev_redo_per_commit, "Current": curr_redo_per_commit, "Delta": _delta(prev_redo_per_commit, curr_redo_per_commit), "Interpretation": "redo footprint per commit"},
        {
            "Metric": "log file sync avg ms",
            "Previous": prev_lfs,
            "Current": curr_lfs,
            "Delta": _delta(prev_lfs, curr_lfs),
            "Interpretation": "commit latency signal" if prev_lfs is not None and curr_lfs is not None else (missing_wait_reason or "stat_name_not_found"),
        },
        {
            "Metric": "log file parallel write avg ms",
            "Previous": prev_lfpw,
            "Current": curr_lfpw,
            "Delta": _delta(prev_lfpw, curr_lfpw),
            "Interpretation": "redo write latency signal" if prev_lfpw is not None and curr_lfpw is not None else (missing_wait_reason or "stat_name_not_found"),
        },
    ]


def _build_awr_recommendations(
    *,
    snapshot_quality: AwrSnapshotQuality,
    wait_event_rows: list[dict[str, Any]],
    sql_delta_rows: list[dict[str, Any]],
    ash_rows: list[dict[str, Any]],
    db_time_current: float | None,
    db_time_previous: float | None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if snapshot_quality.window_quality == "LOW":
        out.append({"Priority": 1, "Recommendation": "Capture a fresh AWR comparison window.", "Reason": snapshot_quality.reason})
    if any("enq: tx" in str(row.get("Event") or "").lower() for row in wait_event_rows):
        out.append(
            {
                "Priority": 1,
                "Recommendation": "Validate live blocking chain and blocker ownership.",
                "Reason": "AWR shows row-lock contention; confirm active blocker session, SQL, and object ownership.",
            }
        )
    if any(str(row.get("Classification") or "") == "significant_contributor" for row in sql_delta_rows):
        out.append(
            {
                "Priority": 2,
                "Recommendation": "Run SQL_ID deep dive for top SQL contributors.",
                "Reason": "AWR SQL delta shows materially significant contributors.",
            }
        )
    if not out and db_time_current is not None and db_time_previous is not None and db_time_current <= db_time_previous:
        out.append({"Priority": 3, "Recommendation": "Continue monitoring with next run pair.", "Reason": "No strong worsening trend in AWR workload deltas."})
    if not out:
        out.append({"Priority": 3, "Recommendation": "Collect additional evidence.", "Reason": "AWR signals were limited; correlate with current health run evidence."})
    if ash_rows:
        out.append({"Priority": 2, "Recommendation": "Inspect ASH blockers and hotspot objects.", "Reason": "Concurrency-related ASH samples were captured."})
    return out[:6]


def _missing_section_items(
    sql_rows: list[dict[str, Any]],
    ash_rows: list[dict[str, Any]],
    object_rows: list[dict[str, Any]],
) -> list[str]:
    missing: list[str] = []
    if not sql_rows:
        missing.append("sql delta")
    if not ash_rows:
        missing.append("ash")
    if not object_rows:
        missing.append("object hotspots")
    return missing


def _delta(previous: float | None, current: float | None) -> float | None:
    if previous is None or current is None:
        return None
    return round(current - previous, 3)


def _compose_unavailable_reason(*, reason_prev: str | None, reason_curr: str | None) -> str:
    rp = str(reason_prev or "").strip() or "stat_name_not_found"
    rc = str(reason_curr or "").strip() or "stat_name_not_found"
    if rp == rc:
        return rp
    return f"previous={rp}; current={rc}"


def _collect_top_events(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> list[dict[str, Any]]:
    event_map, reasons = _collect_wait_event_deltas(window, event_names=None, notes=notes, label=label)
    rows: list[dict[str, Any]] = []
    for event_name, payload in sorted(event_map.items(), key=lambda item: float(item[1].get("time_waited_s") or 0.0), reverse=True)[:10]:
        rows.append(
            {
                "event_name": event_name,
                "wait_class": payload.get("wait_class") or "Other",
                "time_waited_s": round(_safe_float(payload.get("time_waited_s")) or 0.0, 3),
                "waits": int(_safe_float(payload.get("waits")) or 0.0),
                "avg_wait_ms": _safe_float(payload.get("avg_wait_ms")),
            }
        )
    if not rows and not reasons:
        notes.append(f"{label} wait-event extraction produced no rows: no_rows_in_dba_hist_system_event_for_window")
    return rows


def _collect_wait_class_time(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    totals: dict[str, float] = {}
    for row in events:
        wait_class = str(row.get("wait_class") or "Other")
        waited = _safe_float(row.get("time_waited_s")) or 0.0
        totals[wait_class] = totals.get(wait_class, 0.0) + waited
    ordered = sorted(totals.items(), key=lambda item: item[1], reverse=True)
    return [{"wait_class": wait_class, "time_waited_s": round(waited, 3)} for wait_class, waited in ordered]


def _collect_time_model(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> dict[str, float | None]:
    values, _reasons = _collect_counter_deltas(
        window=window,
        notes=notes,
        label=label,
        source_name="dba_hist_sys_time_model",
        stat_names=_TIME_MODEL_STAT_NAMES,
        sql="""
            select tm.stat_name as stat_name,
                   s.snap_id as snap_id,
                   tm.value as value
            from dba_hist_sys_time_model tm
            join dba_hist_snapshot s
              on s.dbid = tm.dbid
             and s.instance_number = tm.instance_number
             and s.snap_id = tm.snap_id
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id in (:begin_snap_id, :end_snap_id)
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and tm.stat_name in (
                  'DB time',
                  'DB CPU',
                  'background elapsed time',
                  'background cpu time',
                  'sql execute elapsed time',
                  'parse time elapsed',
                  'hard parse elapsed time'
              )
        """,
        scale=1e6,
        normalize=False,
    )
    return values


def _collect_sysstat(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> dict[str, float | None]:
    values, _reasons = _collect_counter_deltas(
        window=window,
        notes=notes,
        label=label,
        source_name="dba_hist_sysstat",
        stat_names=_SYSSTAT_NAMES,
        sql="""
            select lower(n.stat_name) as stat_name,
                   snap.snap_id as snap_id,
                   s.value as value
            from dba_hist_sysstat s
            join dba_hist_stat_name n
              on n.dbid = s.dbid
             and n.stat_id = s.stat_id
            join dba_hist_snapshot snap
              on snap.dbid = s.dbid
             and snap.instance_number = s.instance_number
             and snap.snap_id = s.snap_id
            where snap.dbid = :dbid
              and snap.instance_number = :instance_number
              and snap.snap_id in (:begin_snap_id, :end_snap_id)
              and (:startup_time is null or to_char(snap.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and lower(n.stat_name) in (
                  'execute count',
                  'parse count (total)',
                  'parse count (hard)',
                  'user commits',
                  'user rollbacks',
                  'redo size',
                  'session logical reads',
                  'physical reads',
                  'physical writes',
                  'db block changes',
                  'opened cursors cumulative',
                  'logons cumulative',
                  'physical read total io requests',
                  'physical write total io requests',
                  'physical read total bytes',
                  'physical write total bytes',
                  'redo writes',
                  'physical reads direct',
                  'physical writes direct'
              )
        """,
        scale=1.0,
        normalize=True,
    )
    return values


def _collect_counter_deltas(
    *,
    window: AwrSnapshotWindowMapping,
    notes: list[str],
    label: str,
    source_name: str,
    stat_names: list[str],
    sql: str,
    scale: float,
    normalize: bool,
) -> tuple[dict[str, float | None], dict[str, str]]:
    binds = _window_binds(window)
    normalized_stats = [name.lower() if normalize else name for name in stat_names]
    values: dict[str, float | None] = {key: None for key in normalized_stats}
    reasons: dict[str, str] = {key: "stat_name_not_found" for key in normalized_stats}
    if binds is None:
        notes.append(f"{label} {source_name} extraction skipped because DBID/instance mapping was incomplete.")
        for key in normalized_stats:
            reasons[key] = "begin_snap_missing"
        return values, reasons
    try:
        rows = fetch_all(sql, binds)
    except Exception as exc:
        reason = f"query_error={exc.__class__.__name__}"
        notes.append(f"{label} {source_name} extraction failed: {reason}")
        for key in normalized_stats:
            reasons[key] = reason
        return values, reasons

    begin_snap = _safe_int(binds.get("begin_snap_id"))
    end_snap = _safe_int(binds.get("end_snap_id"))
    by_stat: dict[str, dict[int, float]] = {}
    for row in rows:
        stat_name_raw = str(row.get("stat_name") or "")
        stat_name = stat_name_raw.lower() if normalize else stat_name_raw
        snap_id = _safe_int(row.get("snap_id"))
        stat_value = _safe_float(row.get("value"))
        if not stat_name or snap_id is None or stat_value is None:
            continue
        by_stat.setdefault(stat_name, {})[snap_id] = stat_value

    for stat_name in normalized_stats:
        snap_map = by_stat.get(stat_name)
        if not snap_map:
            values[stat_name] = None
            reasons[stat_name] = "stat_name_not_found"
            continue
        begin_val = snap_map.get(begin_snap) if begin_snap is not None else None
        end_val = snap_map.get(end_snap) if end_snap is not None else None
        if begin_val is None:
            values[stat_name] = None
            reasons[stat_name] = "begin_snap_missing"
            continue
        if end_val is None:
            values[stat_name] = None
            reasons[stat_name] = "end_snap_missing"
            continue
        delta = end_val - begin_val
        if delta < 0:
            values[stat_name] = None
            reasons[stat_name] = "negative_delta"
            continue
        scaled = delta / scale if scale not in {0, 1.0} else delta
        values[stat_name] = round(scaled, 3)
        reasons[stat_name] = "ok"
    return values, reasons


def _collect_wait_event_deltas(
    window: AwrSnapshotWindowMapping,
    *,
    event_names: list[str] | None,
    notes: list[str],
    label: str,
) -> tuple[dict[str, dict[str, float | str | None]], dict[str, str]]:
    binds = _window_binds(window)
    normalized_filter = [name.lower() for name in event_names] if event_names else None
    if binds is None:
        notes.append(f"{label} wait-event extraction skipped because DBID/instance mapping was incomplete.")
        return {}, {name: "begin_snap_missing" for name in (normalized_filter or [])}

    filter_sql = ""
    if normalized_filter:
        filter_sql = " and lower(e.event_name) in (" + ", ".join(f"'{name}'" for name in normalized_filter) + ")"
    try:
        rows = fetch_all(
            f"""
            select lower(e.event_name) as event_name,
                   max(e.wait_class) as wait_class,
                   s.snap_id as snap_id,
                   sum(e.total_waits) as total_waits,
                   sum(e.time_waited_micro) as time_waited_micro
            from dba_hist_system_event e
            join dba_hist_snapshot s
              on s.dbid = e.dbid
             and s.instance_number = e.instance_number
             and s.snap_id = e.snap_id
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id in (:begin_snap_id, :end_snap_id)
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and e.wait_class <> 'Idle'
              {filter_sql}
            group by lower(e.event_name), s.snap_id
            """,
            binds,
        )
    except Exception as exc:
        reason = f"query_error={exc.__class__.__name__}"
        notes.append(f"{label} wait-event extraction failed: {reason}")
        return {}, {name: reason for name in (normalized_filter or [])}

    if not rows:
        notes.append(f"{label} wait-event extraction produced no rows: no_rows_in_dba_hist_system_event_for_window")
        return {}, {name: "no_rows_in_dba_hist_system_event_for_window" for name in (normalized_filter or [])}

    begin_snap = _safe_int(binds.get("begin_snap_id"))
    end_snap = _safe_int(binds.get("end_snap_id"))
    by_event: dict[str, dict[int, dict[str, Any]]] = {}
    for row in rows:
        event_name = str(row.get("event_name") or "")
        snap_id = _safe_int(row.get("snap_id"))
        if not event_name or snap_id is None:
            continue
        by_event.setdefault(event_name, {})[snap_id] = row

    out: dict[str, dict[str, float | str | None]] = {}
    reasons: dict[str, str] = {}
    target_names = normalized_filter or sorted(by_event.keys())
    for event_name in target_names:
        snap_map = by_event.get(event_name)
        if not snap_map:
            reasons[event_name] = "stat_name_not_found"
            continue
        begin_row = snap_map.get(begin_snap) if begin_snap is not None else None
        end_row = snap_map.get(end_snap) if end_snap is not None else None
        if begin_row is None:
            reasons[event_name] = "begin_snap_missing"
            continue
        if end_row is None:
            reasons[event_name] = "end_snap_missing"
            continue
        begin_waits = _safe_float(begin_row.get("total_waits")) or 0.0
        end_waits = _safe_float(end_row.get("total_waits")) or 0.0
        begin_micro = _safe_float(begin_row.get("time_waited_micro")) or 0.0
        end_micro = _safe_float(end_row.get("time_waited_micro")) or 0.0
        delta_waits = end_waits - begin_waits
        delta_time_s = (end_micro - begin_micro) / 1_000_000.0
        if delta_waits < 0 or delta_time_s < 0:
            reasons[event_name] = "negative_delta"
            continue
        avg_wait_ms = ((delta_time_s * 1000.0) / delta_waits) if delta_waits > 0 else None
        out[event_name] = {
            "wait_class": end_row.get("wait_class"),
            "time_waited_s": round(delta_time_s, 3),
            "waits": round(delta_waits, 3),
            "avg_wait_ms": round(avg_wait_ms, 6) if avg_wait_ms is not None else None,
        }
        reasons[event_name] = "ok"
    return out, reasons


def _collect_host_cpu(window: AwrSnapshotWindowMapping, notes: list[str], *, label: str) -> dict[str, float | None]:
    binds = _window_binds(window)
    if binds is None:
        notes.append(f"{label} host CPU extraction skipped because DBID/instance mapping was incomplete.")
        return {}
    try:
        rows = fetch_all(
            """
            with os as (
                select s.instance_number,
                       os.stat_name,
                       s.snap_id,
                       os.value,
                       lag(os.value) over (partition by s.instance_number, os.stat_name order by s.snap_id) as prev_value
                from dba_hist_osstat os
                join dba_hist_snapshot s
                  on s.dbid = os.dbid
                 and s.instance_number = os.instance_number
                 and s.snap_id = os.snap_id
                where s.dbid = :dbid
                  and s.instance_number = :instance_number
                  and s.snap_id >= :begin_snap_id
                  and s.snap_id <= :end_snap_id
                  and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
                  and os.stat_name in ('BUSY_TIME', 'IDLE_TIME', 'USER_TIME', 'SYS_TIME', 'IOWAIT_TIME')
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

    binds = _window_binds(window)
    if binds is None:
        notes.append(f"{label} memory extraction skipped because DBID/instance mapping was incomplete.")
        return out
    try:
        sga_row = fetch_one(
            """
            with snap_sga as (
                select g.snap_id,
                       g.instance_number,
                       sum(g.bytes) as sga_bytes,
                       sum(case when lower(g.pool) = 'shared pool' then g.bytes else 0 end) as shared_pool_bytes
                from dba_hist_sgastat g
                join dba_hist_snapshot s
                  on s.dbid = g.dbid
                 and s.instance_number = g.instance_number
                 and s.snap_id = g.snap_id
                where s.dbid = :dbid
                  and s.instance_number = :instance_number
                  and s.snap_id > :begin_snap_id
                  and s.snap_id <= :end_snap_id
                  and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
                group by g.snap_id, g.instance_number
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
        pga_rows = fetch_all(
            """
            select lower(name) as name,
                   round(avg(value)/1024/1024, 3) as mb
            from dba_hist_pgastat p
            join dba_hist_snapshot s
              on s.dbid = p.dbid
             and s.instance_number = p.instance_number
             and s.snap_id = p.snap_id
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id > :begin_snap_id
              and s.snap_id <= :end_snap_id
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and lower(p.name) in ('total pga allocated', 'total pga inuse')
            group by lower(p.name)
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
    binds = _window_binds(window)
    if binds is None:
        notes.append(f"{label} top SQL ({order}) extraction skipped because DBID/instance mapping was incomplete.")
        return []
    with_schema_module = f"""
        select * from (
            select ss.sql_id,
                   round(sum(ss.elapsed_time_delta)/1e6, 3) as elapsed_s,
                   round(sum(ss.cpu_time_delta)/1e6, 3) as cpu_s,
                   round(sum(ss.iowait_delta)/1e6, 3) as io_wait_s,
                   round(sum(ss.apwait_delta)/1e6, 3) as app_wait_s,
                   round(sum(ss.ccwait_delta)/1e6, 3) as conc_wait_s,
                   sum(ss.executions_delta) as executions,
                   round(sum(ss.buffer_gets_delta), 3) as buffer_gets_delta,
                   round(sum(ss.disk_reads_delta), 3) as disk_reads_delta,
                   round(sum(ss.rows_processed_delta), 3) as rows_processed_delta,
                   round(sum(ss.parse_calls_delta), 3) as parse_calls_delta,
                   round(sum(ss.loads_delta), 3) as loads_delta,
                   round(sum(ss.invalidations_delta), 3) as invalidations_delta,
                   round((sum(ss.elapsed_time_delta)/1e6) / nullif(sum(ss.executions_delta), 0), 6) as elapsed_per_exec_s,
                   round((sum(ss.cpu_time_delta)/1e6) / nullif(sum(ss.executions_delta), 0), 6) as cpu_per_exec_s,
                   round(sum(ss.buffer_gets_delta) / nullif(sum(ss.executions_delta), 0), 3) as gets_per_exec,
                   round(sum(ss.disk_reads_delta) / nullif(sum(ss.executions_delta), 0), 3) as reads_per_exec,
                   round(sum(ss.rows_processed_delta) / nullif(sum(ss.executions_delta), 0), 3) as rows_per_exec,
                   count(distinct ss.plan_hash_value) as plan_hash_count,
                   max(ss.plan_hash_value) as plan_hash_value,
                   max(ss.parsing_schema_name) as parsing_schema_name,
                   max(ss.module) as module,
                   max(substr(t.sql_text, 1, 500)) as sql_text_sample
            from dba_hist_sqlstat ss
            join dba_hist_snapshot s
              on s.dbid = ss.dbid
             and s.instance_number = ss.instance_number
             and s.snap_id = ss.snap_id
            left join dba_hist_sqltext t
              on t.dbid = ss.dbid
             and t.sql_id = ss.sql_id
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id > :begin_snap_id
              and s.snap_id <= :end_snap_id
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and ss.sql_id is not null
            group by ss.sql_id
            order by {order_expr}
        ) where rownum <= 10
    """
    without_schema_module = f"""
        select * from (
            select ss.sql_id,
                   round(sum(ss.elapsed_time_delta)/1e6, 3) as elapsed_s,
                   round(sum(ss.cpu_time_delta)/1e6, 3) as cpu_s,
                   round(sum(ss.iowait_delta)/1e6, 3) as io_wait_s,
                   round(sum(ss.apwait_delta)/1e6, 3) as app_wait_s,
                   round(sum(ss.ccwait_delta)/1e6, 3) as conc_wait_s,
                   sum(ss.executions_delta) as executions,
                   round(sum(ss.buffer_gets_delta), 3) as buffer_gets_delta,
                   round(sum(ss.disk_reads_delta), 3) as disk_reads_delta,
                   round(sum(ss.rows_processed_delta), 3) as rows_processed_delta,
                   round(sum(ss.parse_calls_delta), 3) as parse_calls_delta,
                   round(sum(ss.loads_delta), 3) as loads_delta,
                   round(sum(ss.invalidations_delta), 3) as invalidations_delta,
                   round((sum(ss.elapsed_time_delta)/1e6) / nullif(sum(ss.executions_delta), 0), 6) as elapsed_per_exec_s,
                   round((sum(ss.cpu_time_delta)/1e6) / nullif(sum(ss.executions_delta), 0), 6) as cpu_per_exec_s,
                   round(sum(ss.buffer_gets_delta) / nullif(sum(ss.executions_delta), 0), 3) as gets_per_exec,
                   round(sum(ss.disk_reads_delta) / nullif(sum(ss.executions_delta), 0), 3) as reads_per_exec,
                   round(sum(ss.rows_processed_delta) / nullif(sum(ss.executions_delta), 0), 3) as rows_per_exec,
                   count(distinct ss.plan_hash_value) as plan_hash_count
            from dba_hist_sqlstat ss
            join dba_hist_snapshot s
              on s.dbid = ss.dbid
             and s.instance_number = ss.instance_number
             and s.snap_id = ss.snap_id
            where s.dbid = :dbid
              and s.instance_number = :instance_number
              and s.snap_id > :begin_snap_id
              and s.snap_id <= :end_snap_id
              and (:startup_time is null or to_char(s.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') = :startup_time)
              and ss.sql_id is not null
            group by ss.sql_id
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
    instance_number: int | None = None,
    startup_time: str | None = None,
    scan_start: datetime,
    scan_end: datetime,
) -> list[dict[str, Any]]:
    chains = _load_snapshot_chains(dbid=dbid, scan_start=scan_start, scan_end=scan_end)
    if not chains:
        return []
    if instance_number is None and not startup_time:
        preferred = _select_first_chain(chains)
        return list(chains.get(preferred, []))
    preferred_key = None
    startup_dt = _coerce_dt(startup_time)
    for key, rows in chains.items():
        if not rows:
            continue
        row0 = rows[0]
        if instance_number is not None and _safe_int(row0.get("instance_number")) != _safe_int(instance_number):
            continue
        if startup_dt is not None and _coerce_dt(row0.get("startup_time")) != startup_dt:
            continue
        preferred_key = key
        break
    if preferred_key is None:
        preferred_key = _select_first_chain(chains)
    return list(chains.get(preferred_key, []))


def _load_snapshot_chains(
    *,
    dbid: int | None,
    scan_start: datetime,
    scan_end: datetime,
) -> dict[tuple[int | None, int | None, str | None], list[dict[str, Any]]]:
    rows = fetch_all(
        """
        select dbid,
               snap_id,
               instance_number,
               to_char(startup_time, 'YYYY-MM-DD"T"HH24:MI:SS') as startup_time,
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
        return {}
    by_chain_snap: dict[tuple[int | None, int | None, str | None, int], dict[str, Any]] = {}
    for row in rows:
        snap_id = _safe_int(row.get("snap_id"))
        if snap_id is None:
            continue
        dbid_value = _safe_int(row.get("dbid"))
        instance = _safe_int(row.get("instance_number"))
        startup_raw = _format_ts(_coerce_dt(row.get("startup_time")))
        begin_dt = _coerce_dt(row.get("begin_time"))
        end_dt = _coerce_dt(row.get("end_time"))
        if begin_dt is None or end_dt is None:
            continue
        chain_snap_key = (dbid_value, instance, startup_raw, snap_id)
        current = by_chain_snap.get(chain_snap_key)
        if current is None:
            current = {
                "dbid": dbid_value,
                "instance_number": instance,
                "startup_time": startup_raw,
                "snap_id": snap_id,
                "begin_dt": begin_dt,
                "end_dt": end_dt,
                "instance_rows_found": 0,
                "instance_count": 1 if instance is not None else 0,
            }
            by_chain_snap[chain_snap_key] = current
        current["begin_dt"] = min(current["begin_dt"], begin_dt)
        current["end_dt"] = max(current["end_dt"], end_dt)
        current["instance_rows_found"] = int(current["instance_rows_found"]) + 1

    chains: dict[tuple[int | None, int | None, str | None], list[dict[str, Any]]] = {}
    for (dbid_value, instance, startup_raw, _snap_id), row in by_chain_snap.items():
        chain_key = (dbid_value, instance, startup_raw)
        chains.setdefault(chain_key, []).append(row)
    for key in list(chains.keys()):
        chains[key] = sorted(chains[key], key=lambda item: int(item.get("snap_id") or 0))
    return chains


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


def _duration_minutes(begin_dt: datetime | None, end_dt: datetime | None) -> float | None:
    if begin_dt is None or end_dt is None:
        return None
    return round((end_dt - begin_dt).total_seconds() / 60.0, 2)


def _format_ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")


def _build_snapshot_chain_diagnostic(
    *,
    window_mapping: AwrRunPairWindowMapping,
    dbid: int | None,
) -> list[dict[str, Any]]:
    scan_times: list[datetime] = []
    for window in (window_mapping.previous, window_mapping.current):
        begin_dt = _coerce_dt(window.begin_time)
        end_dt = _coerce_dt(window.end_time)
        if begin_dt is not None:
            scan_times.append(begin_dt)
        if end_dt is not None:
            scan_times.append(end_dt)
    if not scan_times:
        now = datetime.now(tz=UTC)
        scan_start = now - timedelta(hours=12)
        scan_end = now + timedelta(hours=1)
    else:
        scan_start = min(scan_times) - timedelta(hours=2)
        scan_end = max(scan_times) + timedelta(hours=2)

    try:
        rows = fetch_all(
            """
            select dbid,
                   instance_number,
                   to_char(startup_time, 'YYYY-MM-DD"T"HH24:MI:SS') as startup_time,
                   min(snap_id) as snap_min,
                   max(snap_id) as snap_max,
                   to_char(min(begin_interval_time), 'YYYY-MM-DD"T"HH24:MI:SS') as begin_time,
                   to_char(max(end_interval_time), 'YYYY-MM-DD"T"HH24:MI:SS') as end_time,
                   count(*) as rows_count
            from dba_hist_snapshot
            where begin_interval_time >= :scan_start
              and end_interval_time <= :scan_end
              and (:dbid is null or dbid = :dbid)
            group by dbid, instance_number, startup_time
            order by dbid, instance_number, startup_time
            """,
            {"scan_start": scan_start, "scan_end": scan_end, "dbid": dbid},
        )
    except Exception:
        return []
    selected_keys = {
        (window_mapping.previous.dbid, window_mapping.previous.instance_number, window_mapping.previous.startup_time),
        (window_mapping.current.dbid, window_mapping.current.instance_number, window_mapping.current.startup_time),
    }
    out: list[dict[str, Any]] = []
    for row in rows:
        key = (_safe_int(row.get("dbid")), _safe_int(row.get("instance_number")), _format_ts(_coerce_dt(row.get("startup_time"))))
        out.append(
            {
                "DBID": _safe_int(row.get("dbid")),
                "Instance": _safe_int(row.get("instance_number")),
                "Startup Time": _format_ts(_coerce_dt(row.get("startup_time"))),
                "Snap Min": _safe_int(row.get("snap_min")),
                "Snap Max": _safe_int(row.get("snap_max")),
                "Begin Time": _format_ts(_coerce_dt(row.get("begin_time"))),
                "End Time": _format_ts(_coerce_dt(row.get("end_time"))),
                "Rows": _safe_int(row.get("rows_count")),
                "Selected": "yes" if key in selected_keys else "no",
            }
        )
    return out


def _assess_snapshot_windows(
    window_mapping: AwrRunPairWindowMapping,
) -> tuple[str, str, str, list[dict[str, Any]], list[str]]:
    prev = window_mapping.previous
    curr = window_mapping.current
    rows = [
        _snapshot_window_row("previous", prev),
        _snapshot_window_row("current", curr),
    ]
    notes: list[str] = []
    quality = "HIGH"
    reason = "Snapshot windows are DBID/instance/startup aligned and non-overlapping."
    same_snap_adjacent_mode = bool((window_mapping.debug or {}).get("same_snap_adjacent_interval_mode"))

    if not _valid_window(prev) or not _valid_window(curr):
        if _valid_window(curr):
            quality = "LOW"
            reason = f"Previous window unavailable ({prev.window_reason or 'missing_previous_adjacent_snapshot'}); current interval is context only."
        else:
            quality = "LOW"
            reason = "Missing begin/end snapshot IDs for one or both windows."
    elif prev.dbid is None or curr.dbid is None or prev.dbid != curr.dbid:
        quality = "LOW"
        reason = "Previous/current windows map to different DBID values."
    elif prev.instance_number is None or curr.instance_number is None or prev.instance_number != curr.instance_number:
        quality = "LOW"
        reason = "Previous/current windows map to different instance_number values."
    else:
        prev_begin = _coerce_dt(prev.begin_time)
        prev_end = _coerce_dt(prev.end_time)
        curr_begin = _coerce_dt(curr.begin_time)
        curr_end = _coerce_dt(curr.end_time)
        if same_snap_adjacent_mode:
            quality = "MEDIUM"
            reason = "Both runs mapped to the same completed snapshot; adjacent completed intervals were used."
        elif prev.begin_snap_id == prev.end_snap_id or curr.begin_snap_id == curr.end_snap_id:
            quality = "LOW"
            reason = "One or both windows map to a single snapshot (begin_snap=end_snap)."
        elif (
            prev_begin is not None
            and prev_end is not None
            and curr_begin is not None
            and curr_end is not None
            and max(prev_begin, curr_begin) < min(prev_end, curr_end)
        ):
            quality = "LOW"
            reason = "Previous/current windows overlap in time."
        elif prev.startup_time and curr.startup_time and prev.startup_time != curr.startup_time:
            quality = "MEDIUM"
            reason = "Previous/current windows are in different startup chains."
        elif (prev.duration_minutes or 0.0) < 10.0 or (curr.duration_minutes or 0.0) < 10.0:
            quality = "MEDIUM"
            reason = "One or more windows are shorter than 10 minutes."

    if quality in {"LOW", "NONE"}:
        notes.append("AWR current window is low quality; AWR findings are context only and cannot drive CRITICAL RCA alone.")
    if same_snap_adjacent_mode:
        notes.append("Both health runs mapped to the same completed AWR snapshot; AutoDBA used adjacent completed AWR intervals for structured comparison.")
    use = "rca" if quality == "HIGH" else "context_only"
    return quality, use, reason, rows, notes


def _snapshot_window_row(window_name: str, window: AwrSnapshotWindowMapping) -> dict[str, Any]:
    return {
        "Window": window_name,
        "DBID": window.dbid,
        "Instance": window.instance_number,
        "Startup Time": window.startup_time,
        "Begin Snap": window.begin_snap_id,
        "End Snap": window.end_snap_id,
        "Begin Time": window.begin_time,
        "End Time": window.end_time,
        "Duration Min": window.duration_minutes,
        "Quality": window.mapping_quality,
        "Use": window.window_use,
    }


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


def _awr_mode_for_mapping(window_mapping: AwrRunPairWindowMapping) -> str:
    previous = window_mapping.previous
    current = window_mapping.current
    if (
        previous.begin_snap_id is not None
        and previous.end_snap_id is not None
        and previous.begin_snap_id == current.begin_snap_id
        and previous.end_snap_id == current.end_snap_id
    ):
        return "single_window_interpretation"
    return "comparison"


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


def _default_awr_instance_number() -> int | None:
    try:
        row = fetch_one("select min(instance_number) as instance_number from gv$instance") or {}
        candidate = _safe_int(row.get("instance_number"))
        if candidate is not None:
            return candidate
    except Exception:
        pass
    try:
        row = fetch_one("select instance_number from v$instance") or {}
        return _safe_int(row.get("instance_number"))
    except Exception:
        return None


def _build_awr_load_profile_summary(lines: list[str]) -> list[str]:
    metric_lines: dict[str, str] = {}
    for raw in lines:
        lower = raw.lower()
        for key in (
            "db time",
            "db cpu",
            "redo size",
            "parse",
            "execute",
            "transaction",
            "logical read",
            "physical read",
        ):
            if key in lower and key not in metric_lines and _numbers_from_awr_line(raw):
                metric_lines[key] = raw

    out: list[str] = []
    db_time = _best_awr_number(metric_lines.get("db time"))
    if db_time is not None:
        out.append(f"DB Time: {_workload_label(db_time, low=60.0, high=900.0)} workload ({_format_seconds_or_minutes(db_time)} total)")
    db_cpu = _best_awr_number(metric_lines.get("db cpu"))
    if db_cpu is not None:
        out.append(f"DB CPU: {_usage_label(db_cpu, low=30.0, high=600.0)} usage ({_format_seconds_or_minutes(db_cpu)} total)")
    redo = _best_awr_number(metric_lines.get("redo size"))
    if redo is not None:
        out.append(f"Redo Generation: {_volume_label(redo)} ({_format_bytes(redo)})")
    parses = _best_awr_number(metric_lines.get("parse"))
    if parses is not None:
        out.append(f"Parse Activity: {_activity_label(parses, low=100.0, high=5000.0)} ({_format_count(parses)} calls)")
    executes = _best_awr_number(metric_lines.get("execute"))
    if executes is not None:
        out.append(f"SQL Executions: {_activity_label(executes, low=100.0, high=10000.0)} ({_format_count(executes)} executions)")
    transactions = _best_awr_number(metric_lines.get("transaction"))
    if transactions is not None:
        out.append(f"Transactions: {_activity_label(transactions, low=50.0, high=5000.0)} ({_format_count(transactions)} total)")
    logical = _best_awr_number(metric_lines.get("logical read"))
    if logical is not None:
        out.append(f"Logical Reads: {_activity_label(logical, low=10000.0, high=1000000.0)} ({_format_count(logical)} reads)")
    physical = _best_awr_number(metric_lines.get("physical read"))
    if physical is not None:
        out.append(f"Physical Reads: {_activity_label(physical, low=1000.0, high=100000.0)} ({_format_count(physical)} reads)")
    return _dedupe_text(out)[:8]


def _build_awr_bottleneck_summary(lines: list[str]) -> list[str]:
    out: list[str] = []
    seen_events: set[str] = set()
    for raw in lines:
        event = _awr_wait_event_name(raw)
        if not event or event.lower() in seen_events:
            continue
        seen_events.add(event.lower())
        wait_class = _awr_wait_class(event)
        latency = _awr_latency_summary(raw)
        impact = _awr_impact_label(raw, event)
        lines_for_event = [
            event,
            f"  -> {wait_class}",
        ]
        if latency:
            lines_for_event.append(f"  -> avg latency: {latency}")
        lines_for_event.append(f"  -> impact: {impact}")
        out.append("\n".join(lines_for_event))
        if len(out) >= 5:
            break
    return out


def _extract_awr_lines(
    lines: list[str],
    *,
    keywords: tuple[str, ...],
    require_number: bool,
    max_items: int,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        lower = raw.lower()
        if not any(keyword in lower for keyword in keywords):
            continue
        if require_number and not any(char.isdigit() for char in raw):
            continue
        cleaned = " ".join(raw.split())
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned[:160])
        if len(out) >= max_items:
            break
    return out


def _extract_awr_sql_contributors(lines: list[str], *, max_items: int, db_time_s: float | None = None) -> list[str]:
    out: list[str] = []
    seen_sql: set[str] = set()
    for raw in lines:
        sql_ids = _sql_ids_from_line(raw)
        if not sql_ids:
            continue
        sql_id = sql_ids[0]
        if sql_id in seen_sql:
            continue
        seen_sql.add(sql_id)
        numbers = _numbers_from_awr_line(raw)
        elapsed_value = numbers[0] if numbers else None
        if db_time_s and elapsed_value and elapsed_value > (db_time_s * 10.0):
            continue
        elapsed = _format_seconds_or_minutes(elapsed_value) if elapsed_value is not None else "-"
        executions = _format_count(numbers[-1]) if len(numbers) >= 2 else "-"
        classification = _sql_text_classification(raw)
        impact = "dominant workload driver" if len(out) == 0 else "candidate workload contributor"
        out.append(
            "\n".join(
                [
                    f"SQL_ID: {sql_id}",
                    f"  -> elapsed: {elapsed}",
                    f"  -> executions: {executions}",
                    "  -> module: not available in report text",
                    f"  -> classification: {classification}",
                    f"  -> impact: {impact}",
                ]
            )
        )
        if len(out) >= max_items:
            break
    return out


def _sql_ids_from_line(text: str) -> list[str]:
    candidate = str(text or "").lower()
    out: list[str] = []
    for token in re.findall(r"\b[0-9a-z]{13}\b", candidate):
        if token.isdigit():
            continue
        if token.isalpha():
            continue
        out.append(token)
    return out


def _extract_db_time_seconds(lines: list[str]) -> float | None:
    for raw in lines:
        lower = str(raw).lower()
        if "db time" not in lower:
            continue
        numbers = _numbers_from_awr_line(raw)
        if not numbers:
            continue
        value = max(numbers)
        if value <= 0:
            continue
        return float(value)
    return None


def _numbers_from_awr_line(text: Any) -> list[float]:
    cleaned = str(text or "").replace(",", "")
    values: list[float] = []
    for match in re.finditer(r"(?<![A-Za-z0-9_])-?\d+(?:\.\d+)?(?![A-Za-z0-9_])", cleaned):
        try:
            values.append(float(match.group(0)))
        except Exception:
            continue
    return values


def _best_awr_number(text: str | None) -> float | None:
    numbers = _numbers_from_awr_line(text)
    if not numbers:
        return None
    return max(abs(number) for number in numbers)


def _workload_label(value: float, *, low: float, high: float) -> str:
    if value < low:
        return "low"
    if value >= high:
        return "high"
    return "moderate"


def _usage_label(value: float, *, low: float, high: float) -> str:
    if value < low:
        return "minimal"
    if value >= high:
        return "high"
    return "moderate"


def _activity_label(value: float, *, low: float, high: float) -> str:
    if value < low:
        return "low"
    if value >= high:
        return "high"
    return "moderate"


def _volume_label(value: float) -> str:
    if value < 1024.0 * 1024.0:
        return "very low"
    if value >= 1024.0 * 1024.0 * 1024.0:
        return "high"
    return "moderate"


def _format_seconds_or_minutes(value: float | None) -> str:
    if value is None:
        return "-"
    if abs(value) >= 60.0:
        return f"{value / 60.0:.2f} mins"
    return f"{value:.2f} secs"


def _format_count(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:,.0f}"


def _format_bytes(value: float | None) -> str:
    if value is None:
        return "-"
    abs_value = abs(value)
    if abs_value >= 1024.0 * 1024.0 * 1024.0:
        return f"{value / (1024.0 * 1024.0 * 1024.0):.2f} GB"
    if abs_value >= 1024.0 * 1024.0:
        return f"{value / (1024.0 * 1024.0):.2f} MB"
    if abs_value >= 1024.0:
        return f"{value / 1024.0:.2f} KB"
    return f"{value:.0f} bytes"


def _awr_wait_event_name(raw: str) -> str | None:
    text = " ".join(str(raw or "").split())
    lower = text.lower()
    known_events = (
        "db file sequential read",
        "db file scattered read",
        "log file sync",
        "log file parallel write",
        "direct path read",
        "direct path write",
        "enq: tx - row lock contention",
        "enq: tm - contention",
        "resmgr:cpu quantum",
        "library cache lock",
        "library cache: mutex",
        "latch free",
        "cpu time",
    )
    for event in known_events:
        if event in lower:
            return event
    if lower.startswith("enq:"):
        return text.split("  ")[0].strip() or text
    return None


def _awr_wait_class(event: str) -> str:
    lower = event.lower()
    if "db file" in lower or "direct path" in lower:
        return "dominant User I/O wait"
    if "log file sync" in lower:
        return "commit latency"
    if "log file parallel" in lower:
        return "redo write latency"
    if "enq:" in lower:
        return "application/concurrency wait"
    if "resmgr" in lower:
        return "Resource Manager CPU scheduling wait"
    if "library cache" in lower or "latch" in lower:
        return "shared pool/library cache serialization"
    if "cpu" in lower:
        return "CPU service time"
    return "foreground wait event"


def _awr_latency_summary(raw: str) -> str:
    lower = str(raw or "").lower()
    numbers = _numbers_from_awr_line(raw)
    if not numbers:
        return ""
    candidate = numbers[-1]
    if "us" in lower or "micro" in lower:
        return f"{candidate:.0f} us"
    if "ms" in lower or candidate < 100.0:
        return f"{candidate:.2f} ms"
    return f"{candidate:.0f} us"


def _awr_impact_label(raw: str, event: str) -> str:
    lower = f"{raw} {event}".lower()
    numbers = _numbers_from_awr_line(raw)
    peak = max(numbers) if numbers else 0.0
    if "log file sync" in lower and peak >= 3.0:
        return "noticeable"
    if "enq:" in lower:
        return "contention-sensitive"
    if peak >= 1000.0:
        return "high"
    if peak > 0:
        return "moderate"
    return "low"


def _sql_text_classification(raw: str) -> str:
    lower = str(raw or "").lower()
    if "scheduler" in lower or "dbms_scheduler" in lower:
        return "scheduler/internal SQL"
    if "sys" in lower or "system" in lower:
        return "oracle internal SQL"
    return "SQL contributor from AWR text"


def _build_awr_interpretation_summary(
    *,
    load_profile_summary: list[str],
    main_bottlenecks: list[str],
    sql_contributors: list[str],
) -> list[str]:
    joined_load = " ".join(load_profile_summary).lower()
    joined_bottlenecks = " ".join(main_bottlenecks).lower()
    out: list[str] = []
    if "low workload" in joined_load or "minimal usage" in joined_load:
        out.append("Workload is low overall with no clear system-level saturation in the AWR window.")
    elif load_profile_summary:
        out.append("Workload is measurable in the AWR window; validate whether the sampled interval matches the incident.")
    if sql_contributors:
        out.append("SQL contributor evidence is available; review the listed SQL_IDs before assuming host-level pressure.")
    else:
        out.append("SQL contributor details were not available for this snapshot window.")
    if "user i/o" in joined_bottlenecks:
        out.append("Dominant waits are I/O-related; impact should be judged with latency and SQL plan context.")
    if "commit latency" in joined_bottlenecks:
        out.append("Commit latency is visible; review log file sync and redo write behavior if application commits are frequent.")
    if "contention" in joined_bottlenecks:
        out.append("Contention waits appear in the AWR window; verify whether blockers were transient or still active.")
    if not main_bottlenecks:
        out.append("No dominant wait-event bottleneck was parsed from AWR report text.")
    out.append("AWR findings should be correlated with health-run evidence because snapshot windows may not line up exactly with symptoms.")
    return _dedupe_text(out)[:6]


def _dedupe_text(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _derive_awr_follow_up(
    *,
    load_profile_summary: list[str],
    main_bottlenecks: list[str],
    sql_contributors: list[str],
) -> list[str]:
    lower_bottlenecks = " ".join(main_bottlenecks).lower()
    follow_up: list[str] = []
    if "enq: tx" in lower_bottlenecks or "concurrency" in lower_bottlenecks:
        follow_up.append("Review historical and live blocking chains for transient row-lock contention.")
    if "db file" in lower_bottlenecks or "direct path" in lower_bottlenecks:
        follow_up.append("Validate storage latency and top I/O SQL plans for the AWR window.")
    if "resmgr" in lower_bottlenecks:
        follow_up.append("Inspect Resource Manager directives and scheduler workload concurrency.")
    if sql_contributors:
        follow_up.append("Drill into listed SQL contributors with SQL Monitor/ASH for execution-plan stability.")
    if not follow_up and load_profile_summary:
        follow_up.append("Cross-check load-profile signals against host/container utilization for the same AWR window.")
    if not follow_up:
        follow_up.append("Capture an explicit AWR interval around the incident and compare with ASH top waits.")
    return follow_up[:4]


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
