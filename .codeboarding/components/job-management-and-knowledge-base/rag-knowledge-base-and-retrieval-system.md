---
component_id: 5.4
component_name: RAG Knowledge Base & Retrieval System
---

# RAG Knowledge Base & Retrieval System

## Component Description

Manages the long-term storage of diagnostic traces and implements semantic indexing/retrieval to allow agents to query past experiences and recurring issues.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/rag/indexer.py (lines 29-35)
```
def rebuild_history_index() -> dict[str, Any]:
    artifacts = rebuild_planner_memory_artifacts()
    return {
        "record_count": len(artifacts.get("history_indexing") or []),
        "trace_chunk_count": len(artifacts.get("trace_chunks") or []),
        "recurring_issue_count": len(artifacts.get("recurring_issue_index") or []),
    }
```

### /home/neha/projects/agents/odb_autodba/rag/trace_store.py (lines 87-161)
```
def append_health_run_trace(
    snapshot_summary: dict[str, Any] | None = None,
    *,
    snapshot: HealthSnapshot | None = None,
    report_markdown: str | None = None,
    history_context: HistoryContext | None = None,
    rebuild_artifacts: bool = True,
    db_key: str | None = None,
) -> TraceHealthRunRecord:
    """Persist a full Oracle health trace and append a compact JSONL summary.

    The first positional argument is kept for compatibility with the previous
    summary-only writer. New call sites should pass ``snapshot`` and
    ``report_markdown`` so each health run has a full JSON trace.
    """

    resolved_db_key = _resolve_db_key(db_key)
    assert resolved_db_key
    ensure_runtime_dirs(db_key=resolved_db_key)
    now = datetime.now(UTC)
    summary = dict(snapshot_summary or {})
    if snapshot is not None:
        summary = _summary_from_snapshot(snapshot, summary)

    database_name = str(summary.get("database_name") or _snapshot_database_name(snapshot) or "database")
    run_id = str(summary.get("run_id") or f"odb_autodba_{now.strftime('%Y%m%d_%H%M%S')}")
    completed_at = str(summary.get("completed_at") or (snapshot.generated_at if snapshot else now.isoformat()))
    overall_status = _overall_status(summary, snapshot)
    trace_file = health_run_trace_file_path(recorded_at=now, database_name=database_name, db_key=resolved_db_key)
    expected_trace_root = traces_root(db_key=resolved_db_key)
    assert trace_file is not None
    assert str(trace_file).startswith(str(expected_trace_root))
    LOGGER.info("trace_write db_key=%s trace_path=%s", resolved_db_key, trace_file)

    record = TraceHealthRunRecord(
        run_id=run_id,
        recorded_at=now.isoformat(),
        completed_at=completed_at,
        database_name=database_name,
        database_host=(snapshot.instance_info.host_name if snapshot else summary.get("database_host")),
        instance_name=(snapshot.instance_info.instance_name if snapshot else summary.get("instance_name")),
        db_unique_name=(snapshot.instance_info.db_unique_name if snapshot else summary.get("db_unique_name")),
        database_role=(snapshot.instance_info.database_role if snapshot else summary.get("database_role")),
        open_mode=(snapshot.instance_info.open_mode if snapshot else summary.get("open_mode")),
        trace_path=str(trace_file),
        overall_status=overall_status,
        summary=str(summary.get("summary") or f"Oracle health check completed with {len(summary.get('issues') or [])} issue(s)."),
        metrics=dict(summary.get("metrics") or {}),
        issues=_coerce_issues(summary.get("issues") or (snapshot.issues if snapshot else [])),
        actionable_items=list(snapshot.actionable_items if snapshot else []),
        health_sections=list(snapshot.health_sections if snapshot else []),
        snapshot=snapshot,
        report_markdown=report_markdown or "",
        history_context_summary=_history_context_summary(history_context),
    )

    _write_json(trace_file, record.model_dump(mode="json"))
    compact_path = health_run_trace_path(db_key=resolved_db_key)
    assert str(compact_path).startswith(str(expected_trace_root))
    _append_jsonl(compact_path, _compact_record(record))

    if rebuild_artifacts:
        try:
            from odb_autodba.rag.indexer import rebuild_planner_memory_artifacts

            rebuild_planner_memory_artifacts(database_name=database_name, db_key=resolved_db_key)
        except Exception as exc:
            LOGGER.warning(
                "history_index_rebuild_failed db_key=%s database_name=%s error_type=%s error=%s",
                resolved_db_key,
                database_name,
                type(exc).__name__,
                _sanitize_log_message(str(exc)),
            )
    return record
```

### /home/neha/projects/agents/odb_autodba/rag/investigation_trace_store.py (lines 78-160)
```
def hydrate_investigation_report_from_trace(trace_path: str) -> str:
    events = _load_trace_events(trace_path)
    if not events:
        return "# AI Investigation Result\n\nNo investigation trace events were available for hydration."

    question = _extract_question(events)
    steps = _extract_steps(events)
    done_payload = _extract_done_payload(events)

    sql_sections: list[str] = []
    result_sections: list[str] = []
    observations: list[str] = []
    for step in steps:
        step_number = step.get("step_number")
        goal = str(step.get("goal") or "").strip()
        label = f"Step {step_number}" if step_number is not None else "Step"
        if goal:
            label = f"{label} - {goal}"
        sql_text = str(step.get("sql") or "").strip()
        if sql_text:
            sql_sections.extend([f"### {label}", "```sql", sql_text, "```", ""])

        rows = step.get("result_rows")
        row_count = int(step.get("row_count") or 0)
        preview = str(step.get("result_preview") or "").strip()
        status = str(step.get("status") or "").strip() or "unknown"
        result_sections.append(f"### {label}")
        result_sections.append(f"Status: `{status}`")
        if preview:
            result_sections.append(preview)
        if isinstance(rows, list) and rows:
            rendered_rows = _render_result_rows(rows)
            if rendered_rows:
                result_sections.extend(["```json", rendered_rows, "```"])
        elif row_count == 0:
            result_sections.append("No rows returned.")
        result_sections.append("")

        if preview:
            observations.append(f"{label}: {preview}")
        if isinstance(rows, list) and rows:
            observations.append(f"{label}: captured {len(rows)} preview row(s).")

    likely_cause = _extract_likely_cause(events, done_payload)
    actions = _extract_actions(events, done_payload)
    confidence_line = _extract_confidence(done_payload, steps)
    conclusion_heading = _investigation_heading_for_question(question)

    lines: list[str] = ["# AI Investigation Result", "", "## Question", question or "Not provided.", ""]
    lines.append("## SQL Executed")
    if sql_sections:
        lines.extend(sql_sections)
    else:
        lines.append("No SQL statements were captured in the trace.")
    lines.append("")

    lines.append("## Result")
    if result_sections:
        lines.extend(result_sections)
    else:
        lines.append("No step results were captured in the trace.")
    lines.append("")

    lines.append("## Observation")
    if observations:
        lines.extend([f"- {item}" for item in _dedupe_lines(observations)])
    else:
        lines.append("- No observations captured.")
    lines.append("")

    lines.append(conclusion_heading)
    lines.append(likely_cause or "No likely cause/conclusion was captured.")
    lines.append("")

    if actions:
        lines.append("## Actions")
        lines.extend([f"- {item}" for item in actions])
        lines.append("")

    lines.append("## Confidence / Termination")
    lines.append(confidence_line)
    lines.append("")
    return "\n".join(lines).strip() + "\n"
```


## Source Files:

- `rag/indexer.py`
- `rag/investigation_trace_store.py`
- `rag/retriever.py`
- `rag/trace_store.py`

