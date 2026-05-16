---
component_id: 4.3.1
component_name: SQL Diagnostic Engine
---

# SQL Diagnostic Engine

## Component Description

The core analytical engine that synthesizes raw database metrics into structured performance reports. It aggregates wait event profiles and historical execution data to identify bottlenecks for specific SQL identifiers.

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

### /home/neha/projects/agents/odb_autodba/db/query_deep_dive.py (lines 153-196)
```
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
```


## Source Files:

- `db/query_deep_dive.py`

