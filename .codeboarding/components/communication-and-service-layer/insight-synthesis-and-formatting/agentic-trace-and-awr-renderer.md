---
component_id: 2.3.2
component_name: Agentic Trace & AWR Renderer
---

# Agentic Trace & AWR Renderer

## Component Description

Specialized in formatting the reasoning aspect of the system. It transforms step-by-step investigation traces, remediation advice, and Oracle AWR (Automatic Workload Repository) history into structured Markdown cards and timelines.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 2028-2062)
```
def render_investigation_final_report(report: InvestigationReport) -> str:
    sections = [
        "# AI Investigation Report",
        "",
        "## Problem Understood",
        report.problem_statement,
        "",
        "## Investigation Summary",
        report.summary,
        "",
        "## Likely Cause",
        report.likely_cause,
        "",
        "## Supporting Evidence",
    ]
    if report.evidence:
        sections.extend(f"- {line}" for line in report.evidence)
    else:
        sections.append("- No strong evidence captured.")
    sections.extend(["", "## Recommended Next Actions"])
    sections.extend(f"- {line}" for line in (report.recommended_next_actions or ["Review the SQL steps and confirm the suspected cause."]))
    sections.extend(["", "## SQL Steps Run"])
    for step in report.steps:
        sections.extend([
            f"### Step {step.step_number}: {step.goal}",
            "",
            "```sql",
            step.sql,
            "```",
            "",
            step.result_preview,
            "",
        ])
        sections.extend(_render_investigation_step_output(step))
    return "\n".join(sections)
```

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 2102-2130)
```
def render_remediation_card_markdown(proposal: RemediationProposal | None, review: RemediationReview | dict[str, Any] | None = None) -> str:
    if proposal is None:
        return "No remediation proposed for the current analysis."
    parsed_review: RemediationReview | None = None
    if isinstance(review, RemediationReview):
        parsed_review = review
    elif isinstance(review, dict):
        try:
            parsed_review = RemediationReview.model_validate(review)
        except Exception:
            parsed_review = None
    why_line = _remediation_why_line(proposal)
    reviewer_line = _reviewer_decision_line(proposal, parsed_review)
    sql = proposal.execution_sql or proposal.sql
    risk_line = _compact_risk_line(proposal)
    lines = [
        "## Proposed Action",
        f"**{proposal.title}**",
        "",
        "### Why it is suggested",
        why_line,
        "",
        "### Reviewer Decision",
        reviewer_line,
    ]
    if risk_line:
        lines.extend(["", risk_line])
    lines.extend(["", "### SQL", "```sql", sql or "-- No executable SQL generated for this proposal.", "```"])
    return "\n".join(lines)
```

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 509-931)
```
def render_history_answer(answer: dict[str, Any]) -> str:
    context: HistoryContext | None = answer.get("context")
    series = answer.get("series") or []
    summary_lines = answer.get("summary_lines") or []
    domain = answer.get("domain")
    time_scope = answer.get("time_scope") or {}
    transition = answer.get("state_transition") or (context.state_transition if context else None)
    transition_data = _history_mapping(transition)
    transition_awr = transition_data.get("awr_state_diff")
    if transition_awr is None and transition is not None and hasattr(transition, "awr_state_diff"):
        transition_awr = getattr(transition, "awr_state_diff")
    awr_state_diff = answer.get("awr_state_diff") or transition_awr
    history_source = answer.get("history_source_summary") or answer.get("history_source_note") or (
        f"History source: {answer.get('history_source_used') or (context.history_source_used if context else 'raw JSONL only')}."
    )
    awr_source_summary = answer.get("awr_source_summary") or transition_data.get("awr_source_summary")
    fallback_summary = answer.get("fallback_summary") or transition_data.get("fallback_summary")
    awr_data = _history_mapping(awr_state_diff)
    window_mapping = _history_mapping(awr_data.get("window_mapping"))
    previous_window = _history_mapping(window_mapping.get("previous"))
    current_window = _history_mapping(window_mapping.get("current"))
    awr_report_text_summary = _history_mapping(awr_data.get("awr_report_text_summary"))
    awr_mode = str(awr_data.get("awr_mode") or _infer_awr_mode(previous_window, current_window))
    single_window_awr = awr_mode == "single_window_interpretation"
    if not awr_source_summary and single_window_awr:
        if awr_report_text_summary.get("available"):
            awr_source_summary = "AWR source: single-window analysis with report-text enrichment (comparison not applicable)"
        else:
            awr_source_summary = "AWR source: single-window analysis (comparison not applicable)"
    transition_learning = transition_data.get("learning_features")
    if transition_learning is None and transition is not None and hasattr(transition, "learning_features"):
        transition_learning = getattr(transition, "learning_features")
    learning_data = _history_mapping(answer.get("learning_features") or transition_learning)
    fallback_info = _history_mapping(transition_data.get("awr_fallback_info"))
    section_naming = _history_mapping(transition_data.get("section_naming"))
    primary_driver_title = section_naming.get("primary_driver_section_title") or _primary_driver_title_for_outcome(
        str(transition_data.get("transition_outcome") or "unchanged")
    )
    secondary_driver_title = section_naming.get("secondary_driver_section_title") or _secondary_driver_title_for_outcome(
        str(transition_data.get("transition_outcome") or "unchanged")
    )
    lines = [
        "# Oracle Historical Trend Analysis",
        "",
    ]
    header_rows: list[tuple[str, Any]] = []
    if time_scope.get("label"):
        header_rows.append(("Window", time_scope["label"]))
    if domain:
        header_rows.append(("Focus", domain))
    if context is not None:
        header_rows.extend(
            [
                ("Saved runs", len(context.recent_runs)),
                ("Recurring findings", len(context.recurring_findings)),
                ("Trace references", len(context.trace_paths)),
            ]
        )
    if header_rows:
        lines.extend(_render_horizontal_kv_block(header_rows, columns=2))
        lines.append("")

    lines.extend([_section_heading("History Source", informational=True), ""])
    lines.append(f"- History source: {_strip_prefixed_label(history_source, 'History source')}")
    if awr_source_summary:
        lines.append(f"- AWR source: {_strip_prefixed_label(awr_source_summary, 'AWR source')}")
    if fallback_summary and str(fallback_summary).strip():
        lines.append(f"- Fallback: {_strip_prefixed_label(fallback_summary, 'Fallback')}")

    lines.extend(["", _section_heading("State Transition Summary", informational=True), ""])
    if transition_data.get("available"):
        outcome = transition_data.get("transition_outcome") or "unchanged"
        lines.append(
            "- "
            + (
                f"Status transition: {transition_data.get('status_transition') or 'unknown'} "
                f"(outcome={outcome}, confidence={transition_data.get('confidence') or 'LOW'})."
            )
        )
    else:
        lines.append("- State transition data unavailable.")
    summary_without_source = [
        line
        for line in (summary_lines or [])
        if not str(line).lower().startswith("history source:")
    ]
    concise_summary_lines = _dedupe_strings(
        [
            str(line).strip()
            for line in summary_without_source
            if str(line).strip() and not str(line).lower().startswith("status transition:")
        ]
    )
    lines.extend(f"- {line}" for line in (concise_summary_lines[:3] or ["No saved Oracle health traces matched this request."]))

    lines.extend(["", _section_heading(primary_driver_title, informational=True), ""])
    recovery_rows = transition_data.get("recovery_drivers") if isinstance(transition_data.get("recovery_drivers"), list) else []
    if recovery_rows:
        rows = [
            {
                "driver": row.get("title"),
                "category": row.get("category"),
                "score": row.get("score"),
                "evidence": "; ".join((row.get("evidence") or [])[:2]),
            }
            for row in recovery_rows[:5]
        ]
        lines.append(_render_table(rows, ["driver", "category", "score", "evidence"]))
    else:
        lines.append(_primary_driver_empty_text(primary_driver_title))

    lines.extend(["", _section_heading(secondary_driver_title, informational=True), ""])
    residual_rows = transition_data.get("residual_warning_drivers") if isinstance(transition_data.get("residual_warning_drivers"), list) else []
    if residual_rows:
        rows = [
            {
                "driver": row.get("title"),
                "category": row.get("category"),
                "score": row.get("score"),
                "evidence": "; ".join((row.get("evidence") or [])[:2]),
                "follow_up": row.get("follow_up_reason"),
            }
            for row in residual_rows[:6]
        ]
        lines.append(_render_table(rows, ["driver", "category", "score", "evidence", "follow_up"]))
    else:
        lines.append(_secondary_driver_empty_text(secondary_driver_title))

    lines.extend(["", _section_heading("Change Since Last Report", informational=True), ""])
    issue_rows = transition_data.get("historical_issue_states") or transition_data.get("issue_transitions")
    if issue_rows:
        cols = ["title", "category", "state_label", "transition", "previous_severity", "current_severity", "impact_changed"]
        lines.append(_render_table(issue_rows[:16], cols))
    else:
        lines.append("No issue-transition rows were captured.")

    workload_metric_rows = awr_data.get("workload_metrics") if isinstance(awr_data.get("workload_metrics"), list) else []
    if not workload_metric_rows:
        load_profile_rows = awr_data.get("load_profile") if isinstance(awr_data.get("load_profile"), list) else []
        workload_metric_rows = [
            {
                "metric_name": row.get("metric_name"),
                "previous_value": row.get("previous"),
                "current_value": row.get("current"),
                "delta_value": row.get("delta"),
                "percent_delta": row.get("pct_change"),
                "significance": row.get("significance"),
                "interpretation": row.get("interpretation"),
            }
            for row in load_profile_rows
        ]
    historical_confidence = _history_mapping(transition_data.get("historical_confidence"))
    awr_rows: list[dict[str, Any]] = []
    if single_window_awr:
        lines.extend(["", _section_heading("AWR Analysis Mode", informational=True), ""])
        lines.append("AWR Analysis Mode: Single-window interpretation (historical context applied)")
    else:
        lines.extend(["", _section_heading("AWR Workload Changes", informational=True), ""])
    if workload_metric_rows and not single_window_awr:
        for row in workload_metric_rows[:20]:
            awr_rows.append(
                {
                    "metric": row.get("metric_name"),
                    "previous": _format_metric_number(row.get("previous_value")),
                    "current": _format_metric_number(row.get("current_value")),
                    "delta": _format_signed_metric_number(row.get("delta_value")),
                    "%delta": _format_percent_delta(row.get("percent_delta")),
                    "significance": row.get("significance") or "-",
                    "interpretation": row.get("interpretation") or "-",
                }
            )
        if should_collapse_unavailable_awr_table(awr_rows, ["previous", "current", "delta"]):
            lines.append(
                render_compact_awr_unavailable_note(
                    "AWR workload metrics were unavailable in the mapped comparison window.",
                    awr_rows,
                    metric_key="metric",
                )
            )
        else:
            lines.append(_render_table(awr_rows, ["metric", "previous", "current", "delta", "%delta", "significance", "interpretation"]))
            awr_workload_interpretation = transition_data.get("awr_workload_interpretation") or _history_mapping(awr_data.get("workload_interpretation")).get("summary")
            if awr_workload_interpretation:
                lines.append(f"- {awr_workload_interpretation}")
    elif not single_window_awr:
        fallback_reason = fallback_info.get("awr_user_message") or historical_confidence.get("fallback_reason") or "AWR workload comparison unavailable; JSONL fallback used."
        lines.append(f"AWR workload comparison fallback: {fallback_reason}")

    lines.extend(["", _section_heading("Wait Event Profile" if single_window_awr else "Wait Class Shift", informational=True), ""])
    wait_shift = _history_mapping(awr_data.get("wait_shift_summary")) or _history_mapping(awr_data.get("wait_class_shift"))
    if wait_shift:
        wait_summary_rows = [
            {
                "previous_dominant_wait_class": wait_shift.get("previous_dominant_wait_class") or wait_shift.get("dominant_wait_class_previous") or "-",
                "current_dominant_wait_class": wait_shift.get("current_dominant_wait_class") or wait_shift.get("dominant_wait_class_current") or "-",
                "previous_top_event": wait_shift.get("previous_top_event") or "-",
                "current_top_event": wait_shift.get("current_top_event") or "-",
                "wait_class_shift_flag": wait_shift.get("wait_class_shift_flag"),
                "cpu_to_io_shift": wait_shift.get("cpu_to_io_shift"),
                "cpu_to_concurrency_shift": wait_shift.get("cpu_to_concurrency_shift"),
                "interpretation": wait_shift.get("interpretation") or "No material wait-class shift detected.",
            }
        ]
        if should_collapse_unavailable_awr_table(
            wait_summary_rows,
            ["previous_dominant_wait_class", "current_dominant_wait_class", "previous_top_event", "current_top_event"],
        ):
            if single_window_awr:
                lines.append("AWR wait-event details were unavailable for the mapped snapshot window.")
            else:
                lines.append("AWR wait-class shift details were unavailable for the mapped comparison window.")
        else:
            lines.append(_render_table(wait_summary_rows, list(wait_summary_rows[0].keys())))
    else:
        lines.append("Wait-class shift evidence unavailable.")

    lines.extend(["", _section_heading("SQL Activity Summary" if single_window_awr else "SQL Change Summary", informational=True), ""])
    sql_change = _history_mapping(awr_data.get("sql_change_summary")) or _history_mapping(awr_data.get("sql_change"))
    if sql_change:
        sql_summary_rows = [
            {
                "dominant_sql_id_previous": sql_change.get("dominant_sql_id_previous"),
                "dominant_sql_id_current": sql_change.get("dominant_sql_id_current"),
                "dominant_sql_schema_previous": sql_change.get("dominant_sql_schema_previous") or "-",
                "dominant_sql_schema_current": sql_change.get("dominant_sql_schema_current") or "-",
                "dominant_sql_module_previous": sql_change.get("dominant_sql_module_previous") or "-",
                "dominant_sql_module_current": sql_change.get("dominant_sql_module_current") or "-",
                "dominant_sql_class_previous": sql_change.get("dominant_sql_class_previous") or "-",
                "dominant_sql_class_current": sql_change.get("dominant_sql_class_current") or "-",
                "sql_regression_flag": sql_change.get("sql_regression_flag"),
                "sql_regression_severity": sql_change.get("sql_regression_severity") or "-",
                "plan_hash_changed_flag": sql_change.get("plan_hash_changed_flag"),
                "elapsed_per_exec_spike": sql_change.get("elapsed_per_exec_spike"),
                "cpu_per_exec_spike": sql_change.get("cpu_per_exec_spike"),
                "interpretation": sql_change.get("interpretation") or "-",
            }
        ]
        if should_collapse_unavailable_awr_table(
            sql_summary_rows,
            [
                "dominant_sql_id_previous",
                "dominant_sql_id_current",
                "dominant_sql_schema_previous",
                "dominant_sql_schema_current",
                "dominant_sql_module_previous",
                "dominant_sql_module_current",
            ],
        ):
            if single_window_awr:
                lines.append("AWR SQL details were unavailable for the mapped snapshot window.")
            else:
                lines.append("AWR SQL-change details were unavailable for the mapped comparison window.")
        else:
            lines.append(_render_table(sql_summary_rows, list(sql_summary_rows[0].keys())))
    else:
        if single_window_awr:
            lines.append("AWR SQL activity details were unavailable for this snapshot window.")
        else:
            lines.append("AWR SQL-change intelligence unavailable; SQL regression inferred from JSONL metric deltas when possible.")

    snapshot_mapping_summary = transition_data.get("snapshot_mapping_summary")
    lines.extend(["", _section_heading("AWR Snapshot Window", informational=True), ""])
    window_rows: list[dict[str, Any]] = []
    if previous_window.get("begin_snap_id") is not None:
        window_rows.append(
            {
                "window": "previous",
                "begin_snap": previous_window.get("begin_snap_id"),
                "end_snap": previous_window.get("end_snap_id"),
                "quality": previous_window.get("mapping_quality") or "-",
            }
        )
    if current_window.get("begin_snap_id") is not None:
        window_rows.append(
            {
                "window": "current",
                "begin_snap": current_window.get("begin_snap_id"),
                "end_snap": current_window.get("end_snap_id"),
                "quality": current_window.get("mapping_quality") or "-",
            }
        )
    if window_rows:
        lines.append(_render_table(window_rows, ["window", "begin_snap", "end_snap", "quality"]))
    else:
        lines.append("AWR snapshot window mapping was unavailable.")

    lines.extend(["", _section_heading("Load Profile Summary", informational=True), ""])
    if awr_report_text_summary.get("available") and isinstance(awr_report_text_summary.get("load_profile_summary"), list):
        load_items = [str(row) for row in awr_report_text_summary.get("load_profile_summary", [])[:8] if str(row).strip()]
        lines.extend(_render_awr_bullet_lines(load_items, empty="Load-profile highlights were not available for this snapshot window."))
    elif workload_metric_rows:
        concise = [
            row
            for row in awr_rows
            if row.get("previous") != "-" or row.get("current") != "-" or row.get("delta") != "-"
        ][:6]
        if concise:
            lines.append(_render_table(concise, ["metric", "previous", "current", "delta", "%delta", "significance"]))
        else:
            lines.append("Load-profile metrics were sparse in this mapped interval.")
    else:
        lines.append("Load-profile summary unavailable.")

    lines.extend(["", _section_heading("Main Bottlenecks", informational=True), ""])
    if awr_report_text_summary.get("available") and isinstance(awr_report_text_summary.get("main_bottlenecks"), list):
        bottlenecks = [str(item) for item in awr_report_text_summary.get("main_bottlenecks", []) if str(item).strip()]
        lines.extend(_render_awr_bullet_lines(bottlenecks[:5], empty="Main bottleneck details were not available for this snapshot window."))
    else:
        interpretation = wait_shift.get("interpretation") if isinstance(wait_shift, dict) else None
        if interpretation:
            lines.append(f"- {interpretation}")
        else:
            lines.append("- Main bottleneck evidence unavailable.")

    lines.extend(["", _section_heading("SQL Contributors", informational=True), ""])
    if awr_report_text_summary.get("available") and isinstance(awr_report_text_summary.get("sql_contributors"), list):
        sql_lines = [str(item) for item in awr_report_text_summary.get("sql_contributors", []) if str(item).strip()]
        lines.extend(
            _render_awr_bullet_lines(
                sql_lines[:5],
                empty="SQL contributor details were not available for this snapshot window.",
            )
        )
    elif sql_change:
        dom_prev = sql_change.get("dominant_sql_id_previous") or "-"
        dom_curr = sql_change.get("dominant_sql_id_current") or "-"
        if dom_prev == "-" and dom_curr == "-":
            lines.append("- SQL contributor details were not available for this snapshot window.")
        else:
            lines.append(f"- Dominant SQL previous/current: {dom_prev} -> {dom_curr}")
    else:
        lines.append("- SQL contributor evidence unavailable.")

    lines.extend(["", _section_heading("Recommended Follow-up", informational=True), ""])
    if awr_report_text_summary.get("available") and isinstance(awr_report_text_summary.get("recommended_follow_up"), list):
        follow_up = [str(item) for item in awr_report_text_summary.get("recommended_follow_up", []) if str(item).strip()]
        lines.extend(_render_awr_bullet_lines(follow_up[:6], empty="No AWR-specific follow-up suggestions were generated."))
    else:
        lines.append("- Capture a wider AWR interval with matching ASH window if mapped sections remain sparse.")

    lines.extend(["", _section_heading("AWR Interpretation Summary", informational=True), ""])
    interpretation_items = []
    if awr_report_text_summary.get("available") and isinstance(awr_report_text_summary.get("interpretation_summary"), list):
        interpretation_items = [str(item) for item in awr_report_text_summary.get("interpretation_summary", []) if str(item).strip()]
    if single_window_awr:
        interpretation_items.append("AWR trend context is limited because previous and current runs mapped to the same snapshot window.")
    lines.extend(
        _render_awr_bullet_lines(
            _dedupe_strings(interpretation_items)[:6],
            empty="AWR interpretation summary was unavailable for this snapshot window.",
        )
    )

    lines.extend(["", _section_heading("Event Timeline", informational=True), ""])
    timeline_entries = transition_data.get("event_timeline_entries")
    if isinstance(timeline_entries, list) and timeline_entries:
        for row in timeline_entries[:8]:
            notes = "; ".join((row.get("change_notes") or [])[:3])
            lines.append(f"- {row.get('at')}: {row.get('summary')} ({notes})")
    elif context is not None and context.recent_runs:
        lines.extend(f"- {run.completed_at}: {run.summary}" for run in context.recent_runs[:8])
    else:
        lines.append("- Event timeline unavailable.")

    lines.extend(["", _section_heading("Learning Features", informational=True), ""])
    if learning_data:
        learning_rows = [{"feature": friendly_label(str(key)), "value": value} for key, value in learning_data.items()]
        lines.append(_render_table(learning_rows, ["feature", "value"]))
    else:
        lines.append("Learning-feature vector unavailable.")

    lines.extend(["", _section_heading("Confidence + Coverage Notes", informational=True), ""])
    if historical_confidence:
        lines.append(f"- Confidence: {historical_confidence.get('confidence_level') or 'LOW'}")
        lines.append(f"- Coverage: {historical_confidence.get('coverage_quality') or 'LOW'}")
    else:
        snapshot_quality = _history_mapping(awr_data.get("snapshot_quality"))
        if snapshot_quality:
            lines.append(f"- Confidence: {snapshot_quality.get('confidence') or 'LOW'}")
            lines.append(f"- Coverage: {snapshot_quality.get('coverage_quality') or 'LOW'}")
    lines.append(
        "- AWR mode: "
        + (
            "Single-window interpretation (historical context applied)"
            if single_window_awr
            else "Run-pair comparison"
        )
    )
    if single_window_awr and previous_window.get("begin_snap_id") is not None:
        lines.append(f"- Snapshot window: SNAP {previous_window.get('begin_snap_id')}..{previous_window.get('end_snap_id')}")
    elif previous_window.get("begin_snap_id") is not None:
        lines.append(f"- Previous window: SNAP {previous_window.get('begin_snap_id')}..{previous_window.get('end_snap_id')}")
    if not single_window_awr and current_window.get("begin_snap_id") is not None:
        lines.append(f"- Current window: SNAP {current_window.get('begin_snap_id')}..{current_window.get('end_snap_id')}")
    if snapshot_mapping_summary and previous_window.get("begin_snap_id") is None and current_window.get("begin_snap_id") is None:
        lines.append(f"- Snapshot mapping: {snapshot_mapping_summary}")

    lines.extend(["", _section_heading("Recurring Patterns", status="WARNING" if context and context.recurring_findings else "OK"), ""])
    ranked_recurring = transition_data.get("recurring_patterns_ranked") or (context.recurring_findings if context else [])
    if ranked_recurring:
        lines.extend(f"- {finding}" for finding in ranked_recurring[:10])
    else:
        lines.append("- No recurring patterns were detected.")

    if series:
        keys = _history_series_columns(series)
        lines.extend(["", _section_heading("Historical Metric Points", informational=True), "", _render_table(series[-20:], keys)])

    if context is not None and context.trend_summaries:
        trend_rows = [
            {
                "Metric": trend.metric_name,
                "Direction": trend.direction,
                "Latest": trend.latest_value,
                "Previous": trend.previous_value,
                "Min": trend.min_value,
                "Max": trend.max_value,
                "Samples": trend.sample_count,
            }
            for trend in context.trend_summaries[:14]
        ]
        lines.extend(["", _section_heading("Metric Trends", informational=True), "", _render_table(trend_rows, ["Metric", "Direction", "Latest", "Previous", "Min", "Max", "Samples"])])
    return "\n".join(lines).strip()
```


## Source Files:

- `utils/formatter.py`

