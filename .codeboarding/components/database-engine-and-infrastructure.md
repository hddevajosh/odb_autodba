---
component_id: 4
component_name: Database Engine & Infrastructure
---

# Database Engine & Infrastructure

## Component Description

Manages the low-level interactions with Oracle databases, including connection pooling, target registration, and the execution of deep diagnostic checks like AWR and ASH analysis.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/db/connection.py (lines 69-77)
```
def db_connection(settings: ConnectionSettings | None = None, *, db_key: str | None = None) -> Iterator[Any]:
    conn = create_connection(settings, db_key=db_key)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass
```

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

### /home/neha/projects/agents/odb_autodba/target_registry.py (lines 24-27)
```
def load_oracle_targets() -> list[OracleTarget]:
    registry_targets = _load_registry_targets_if_present()
    base_targets = registry_targets if registry_targets is not None else [get_default_oracle_target()]
    return _merge_with_transient_targets(base_targets)
```


## Source Files:

- `config.py`
- `db/ash_checks.py`
- `db/awr_checks.py`
- `db/connection.py`
- `db/health_checks.py`
- `db/investigation_sql.py`
- `db/log_checks.py`
- `db/plan_checks.py`
- `db/query_deep_dive.py`
- `db/running_sessions.py`
- `migrate_runtime.py`
- `runtime_migration.py`
- `runtime_paths.py`
- `target_registry.py`
- `utils/oracle_env.py`

