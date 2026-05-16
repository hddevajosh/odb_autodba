---
component_id: 2.3.1
component_name: Report Orchestrator
---

# Report Orchestrator

## Component Description

The primary entry point for generating high-level, multi-section documents. It coordinates the assembly of executive summaries, health snapshots, and SQL performance deep dives by aggregating data from various database probes.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 449-506)
```
def render_health_snapshot_report(snapshot: HealthSnapshot) -> str:
    database_name = snapshot.instance_info.db_name or snapshot.instance_info.instance_name or "unknown"
    overall_status = _overall_snapshot_status(snapshot)
    lines = [
        "# Oracle AutoDBA Report",
        "",
        f"**Database:** `{database_name}`",
        f"**Open mode / role:** `{snapshot.instance_info.open_mode}` / `{snapshot.instance_info.database_role}`",
        f"**Generated at:** `{snapshot.generated_at}`",
        f"**Overall status:** {_status_badge(overall_status)}",
        "",
        _section_heading("Executive Summary", status=overall_status),
        "",
        _render_executive_summary(snapshot),
        "",
        _section_heading("Key Health Signals", informational=True),
        "",
        _render_key_signals(snapshot),
        "",
        _section_heading("Host Check Scope", informational=True),
        "",
        _render_host_check_scope_section(snapshot),
        "",
        _section_heading("Findings Needing Attention", status=_findings_status(snapshot)),
        "",
        _render_actionable_items(snapshot),
        "",
        _section_heading("Supporting Evidence", informational=True),
        "",
        _render_supporting_evidence(snapshot),
        "",
        _section_heading("Top SQL by CPU", status="WARNING" if snapshot.top_sql_by_cpu else "OK"),
        "",
        _render_top_cpu_sql(snapshot),
        "",
        _section_heading("Top SQL by Elapsed", status="WARNING" if snapshot.top_sql_by_elapsed else "OK"),
        "",
        _render_top_elapsed_sql(snapshot),
        "",
        _top_sql_overlap_note(snapshot),
        "",
        _section_heading("Detailed Evidence", informational=True),
        "",
    ]
    moved_interpretive_notes: list[str] = []
    for section in snapshot.health_sections:
        inline_notes, interpretive_notes = _partition_section_notes(section.name, section.notes)
        moved_interpretive_notes.extend(interpretive_notes)
        lines.extend(_render_health_section(section, notes_override=inline_notes))
    lines.extend(
        [
            _section_heading("AI Investigation Summary", informational=True),
            "",
            _render_ai_investigation_summary(snapshot, moved_interpretive_notes),
            "",
        ]
    )
    return "\n".join(line for line in lines if line is not None).strip()
```

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 934-1055)
```
def render_sql_id_deep_dive_report(deep_dive: SqlIdDeepDive) -> str:
    classification = _deep_dive_mapping(deep_dive.classification)
    wait_profile = _deep_dive_mapping(deep_dive.wait_profile)
    impact = _deep_dive_mapping(deep_dive.impact_summary)
    execution_plan = _deep_dive_mapping(deep_dive.execution_plan)
    dba_recommendation = _deep_dive_mapping(deep_dive.dba_recommendation)
    plan_analysis = _deep_dive_mapping(deep_dive.plan_analysis)
    history_analysis = _deep_dive_mapping(deep_dive.history_analysis)
    risk_summary = _deep_dive_mapping(deep_dive.risk_summary)
    lock_analysis = _deep_dive_mapping(deep_dive.lock_analysis)
    ash = _deep_dive_mapping(deep_dive.ash)
    awr = _deep_dive_mapping(deep_dive.awr)

    wait_events = wait_profile.get("event_breakdown") if isinstance(wait_profile.get("event_breakdown"), list) else []
    plan_lines = execution_plan.get("lines") if isinstance(execution_plan.get("lines"), list) else []
    history_runs = history_analysis.get("matched_runs") if isinstance(history_analysis.get("matched_runs"), list) else []
    risk_reasons = risk_summary.get("reason_lines") if isinstance(risk_summary.get("reason_lines"), list) else []
    lock_rows = lock_analysis.get("blocking_rows") if isinstance(lock_analysis.get("blocking_rows"), list) else []
    awr_plan_changes = awr.get("plan_changes") if isinstance(awr.get("plan_changes"), list) else []
    ash_top_waits = ash.get("top_waits") if isinstance(ash.get("top_waits"), list) else []

    lines = [
        f"# SQL_ID Deep Dive — {deep_dive.sql_id}",
        "",
        "## SQL Text",
        "```sql",
        deep_dive.sql_text or "SQL text not found.",
        "```",
        "",
        "## SQL Classification",
        _render_sql_metric_table(classification, default_text="Classification evidence was not available."),
        "",
        "## Current Cursor Evidence",
        _render_sql_metric_table(deep_dive.current_stats, default_text="No current cursor statistics were captured."),
        "",
        "## Live Session Correlation",
        _render_sql_rows(deep_dive.active_queries[:25], default_text="No live session currently executing this SQL_ID."),
        "",
        _render_sql_rows(lock_rows[:20], default_text="This SQL_ID was not found in current blocking chains."),
        "",
        "## SQL Wait Profile",
        _render_sql_metric_table(
            {k: v for k, v in wait_profile.items() if k not in {"event_breakdown", "notes", "interpretation"}},
            default_text="Wait-profile summary is unavailable.",
        ),
        "",
        _render_sql_rows(wait_events[:15], default_text="No wait-event breakdown rows were captured."),
        "",
        (wait_profile.get("interpretation") or "No wait-profile interpretation available."),
        "",
        "## Impact Summary",
        _render_sql_metric_table(impact, default_text="Impact summary is unavailable."),
        "",
        "## Child Cursor Summary",
        _render_sql_rows(deep_dive.child_cursors[:20], default_text="No child cursor rows were captured."),
        "",
        "## Execution Plan",
        _render_execution_plan_block(plan_lines) if plan_lines else _render_sql_rows(deep_dive.plan_lines[:40], default_text="No execution plan rows were captured."),
        "",
        "## Plan Interpretation",
        (execution_plan.get("interpretation") or "Plan interpretation was not available."),
        "",
        _render_sql_metric_table(
            {
                "source_used": execution_plan.get("source_used"),
                "join_types": execution_plan.get("join_types"),
                "access_paths": execution_plan.get("access_paths"),
                "full_scan_objects": execution_plan.get("full_scan_objects"),
                "index_access_objects": execution_plan.get("index_access_objects"),
                "predicate_summary": execution_plan.get("predicate_summary"),
            },
            default_text="No additional plan interpretation details were captured.",
        ),
        "",
        "## Plan Stability Analysis",
        _render_sql_metric_table(plan_analysis, default_text="Plan stability evidence was unavailable."),
        "",
        _render_sql_metric_table(
            {k: v for k, v in awr.items() if k not in {"plan_changes"}},
            default_text="AWR summary was unavailable.",
        ),
        "",
        _render_sql_rows(awr_plan_changes[:10], default_text="No AWR plan-change rows were captured."),
        "",
        _render_sql_metric_table(
            {k: v for k, v in ash.items() if k not in {"top_waits"}},
            default_text="ASH summary was unavailable.",
        ),
        "",
        _render_sql_rows(ash_top_waits[:10], default_text="No ASH wait rows were captured."),
        "",
        "## Historical Recurrence",
        _render_sql_metric_table(
            {k: v for k, v in history_analysis.items() if k not in {"matched_runs", "cpu_seconds_samples", "elapsed_seconds_samples"}},
            default_text="Historical recurrence evidence was unavailable.",
        ),
        "",
        _render_sql_rows(history_runs[:10], default_text="No historical run matched this SQL_ID in saved traces."),
        "",
        "## Risk Verdict",
        _render_sql_metric_table(
            {k: v for k, v in risk_summary.items() if k != "reason_lines"},
            default_text="Risk summary was unavailable.",
        ),
        "",
        "\n".join(f"- {reason}" for reason in risk_reasons) if risk_reasons else "- No risk reasons were captured.",
        "",
        "## DBA Recommendation",
        _render_sql_metric_table(
            {
                "severity": dba_recommendation.get("severity"),
                "recommendation": dba_recommendation.get("recommendation"),
                "rationale": dba_recommendation.get("rationale"),
                "next_actions": dba_recommendation.get("next_actions"),
            },
            default_text="No DBA recommendation was produced.",
        ),
        "",
        "## Collector Notes",
        "\n".join(f"- {note}" for note in deep_dive.notes[:20]) if deep_dive.notes else "- No collection warnings.",
    ]
    return "\n".join(lines).strip()
```


## Source Files:

- `utils/formatter.py`

