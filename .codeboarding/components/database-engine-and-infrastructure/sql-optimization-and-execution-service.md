---
component_id: 4.3
component_name: SQL Optimization & Execution Service
---

# SQL Optimization & Execution Service

## Component Description

Provides deep-dive capabilities for specific SQL statements. This component extracts execution plans, analyzes wait profiles, and performs deep-dive reporting on individual SQL IDs. It also provides a safe interface for executing ad-hoc investigation queries required by the agents.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/db/query_deep_dive.py (lines 67-150)
```
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
```

### /home/neha/projects/agents/odb_autodba/db/plan_checks.py (lines 52-120)
```
def collect_formatted_execution_plan(
    *,
    sql_id: str,
    current_stats: dict[str, Any] | None = None,
    child_cursors: list[dict[str, Any]] | None = None,
    awr: dict[str, Any] | None = None,
    raw_plan_lines: list[dict[str, Any]] | None = None,
) -> FormattedPlanSection:
    current_stats = current_stats or {}
    child_cursors = child_cursors or []
    awr = awr or {}
    raw_plan_lines = raw_plan_lines or []
    notes: list[str] = []

    preferred_child = _as_int(_first_non_null(child_cursors, "child_number"))
    preferred_plan_hash = _as_int(current_stats.get("plan_hash_value"))

    cursor_section = _from_display_cursor(sql_id=sql_id, preferred_child=preferred_child, notes=notes)
    if cursor_section is not None:
        interpreted = _interpret_plan(raw_plan_lines=raw_plan_lines, rendered_lines=cursor_section.lines)
        return cursor_section.model_copy(
            update={
                "join_types": interpreted["join_types"],
                "access_paths": interpreted["access_paths"],
                "full_scan_objects": interpreted["full_scan_objects"],
                "index_access_objects": interpreted["index_access_objects"],
                "predicate_summary": interpreted["predicate_summary"],
                "interpretation": interpreted["interpretation"],
                "notes": notes + cursor_section.notes,
            }
        )

    awr_section = _from_display_awr(
        sql_id=sql_id,
        preferred_plan_hash=preferred_plan_hash,
        awr_payload=awr,
        notes=notes,
    )
    if awr_section is not None:
        interpreted = _interpret_plan(raw_plan_lines=raw_plan_lines, rendered_lines=awr_section.lines)
        return awr_section.model_copy(
            update={
                "join_types": interpreted["join_types"],
                "access_paths": interpreted["access_paths"],
                "full_scan_objects": interpreted["full_scan_objects"],
                "index_access_objects": interpreted["index_access_objects"],
                "predicate_summary": interpreted["predicate_summary"],
                "interpretation": interpreted["interpretation"],
                "notes": notes + awr_section.notes,
            }
        )

    fallback_lines = _fallback_plan_lines(raw_plan_lines)
    interpreted = _interpret_plan(raw_plan_lines=raw_plan_lines, rendered_lines=fallback_lines)
    return FormattedPlanSection(
        available=bool(fallback_lines),
        source_used="v$sql_plan (fallback)" if fallback_lines else None,
        child_number=preferred_child,
        plan_hash_value=preferred_plan_hash,
        format_used="structured fallback",
        lines=fallback_lines,
        join_types=interpreted["join_types"],
        access_paths=interpreted["access_paths"],
        full_scan_objects=interpreted["full_scan_objects"],
        index_access_objects=interpreted["index_access_objects"],
        predicate_summary=interpreted["predicate_summary"],
        interpretation=interpreted["interpretation"] if fallback_lines else "No execution plan evidence was captured.",
        notes=notes,
    )
```

### /home/neha/projects/agents/odb_autodba/runtime_paths.py (lines 24-27)
```
def get_traces_dir(db_key: str | None = None) -> Path:
    path = get_database_runtime_dir(db_key=db_key) / "traces"
    path.mkdir(parents=True, exist_ok=True)
    return path
```


## Source Files:

- `db/investigation_sql.py`
- `db/plan_checks.py`
- `db/query_deep_dive.py`
- `migrate_runtime.py`
- `runtime_migration.py`
- `runtime_paths.py`

