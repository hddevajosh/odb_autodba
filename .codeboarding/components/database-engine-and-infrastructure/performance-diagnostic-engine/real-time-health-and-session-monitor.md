---
component_id: 4.2.2
component_name: Real-time Health & Session Monitor
---

# Real-time Health & Session Monitor

## Component Description

Responsible for capturing the "live" state of the database. It monitors active session history (ASH), identifies resource hotspots (CPU/Memory), and maps complex blocking session chains.

---

## Key References:

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
- `db/health_checks.py`
- `db/running_sessions.py`

