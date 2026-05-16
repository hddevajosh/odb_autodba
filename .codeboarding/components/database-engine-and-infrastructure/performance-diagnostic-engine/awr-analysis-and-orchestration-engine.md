---
component_id: 4.2.1
component_name: AWR Analysis & Orchestration Engine
---

# AWR Analysis & Orchestration Engine

## Component Description

The primary controller for historical performance analysis. It manages the lifecycle of an AWR diagnostic request, from resolving time windows into valid snapshot pairs to generating high-level narrative summaries and detailed metric differentials.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/db/awr_checks.py (lines 112-283)
```
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
```


## Source Files:

- `db/awr_checks.py`

