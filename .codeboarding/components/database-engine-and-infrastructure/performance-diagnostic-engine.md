---
component_id: 4.2
component_name: Performance Diagnostic Engine
---

# Performance Diagnostic Engine

## Component Description

The primary analytical engine of the subsystem. It orchestrates the collection and comparison of historical performance data (AWR) and real-time session activity (ASH). It is responsible for mapping time windows to snapshots, calculating performance deltas, and identifying regressions or bottlenecks in system-wide behavior.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/db/awr_checks.py (lines 497-657)
```
def build_awr_state_diff(
    *,
    window_mapping: AwrRunPairWindowMapping,
    capabilities: AwrCapabilities | None = None,
) -> AwrStateDiff:
    caps = capabilities or get_awr_capabilities()
    awr_mode = _awr_mode_for_mapping(window_mapping)
    if not caps.available:
        return AwrStateDiff(
            available=False,
            awr_mode=awr_mode,
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
            awr_mode=awr_mode,
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
        notes=notes,
    )
```

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

### /home/neha/projects/agents/odb_autodba/db/ash_checks.py (lines 32-73)
```
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
```

### /home/neha/projects/agents/odb_autodba/db/health_checks.py (lines 278-360)
```
def collect_health_snapshot(db_key: str | None = None) -> HealthSnapshot:
    with db_key_context(db_key):
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
        top_session_candidates = get_top_session_resource_candidates(limit=10)
        try:
            current_sql_candidates = summarize_current_sql(limit=10)
        except Exception:
            current_sql_candidates = []

        plan_evidence = collect_plan_evidence_for_top_sql([row.sql_id for row in top_elapsed[:5]])
        extended_sections, actionable_items, raw_evidence = collect_extended_health(window_hours=window_hours)
        host_cfg = resolve_host_check_config()
        host_snapshot, host_check = collect_host_snapshot_for_mode(host_cfg)
        raw_evidence["host_check"] = dict(host_check)
        if host_check.get("host_check_warning"):
            notes.append(str(host_check.get("host_check_warning")))
        raw_evidence["top_session_resource_candidates"] = top_session_candidates
        raw_evidence["current_sql_candidates"] = current_sql_candidates

        if host_snapshot is not None:
            host_snapshot = _correlate_host_hotspots_with_db(
                host_snapshot,
                notes=notes,
                top_sql_by_cpu=top_cpu,
                top_session_candidates=top_session_candidates,
                current_sql_candidates=current_sql_candidates,
                top_pga_candidates=(raw_evidence.get("memory_config") or {}).get("top_pga_sessions") or [],
            )
            _apply_memory_compact_note(snapshot_sections=extended_sections, host_snapshot=host_snapshot, raw_evidence=raw_evidence, notes=notes)

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
```


## Source Files:

- `db/ash_checks.py`
- `db/awr_checks.py`
- `db/health_checks.py`
- `db/log_checks.py`
- `db/running_sessions.py`

