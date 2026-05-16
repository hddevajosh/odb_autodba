---
component_id: 2
component_name: Communication & Service Layer
---

# Communication & Service Layer

## Component Description

Acts as the central nervous system of the platform, managing Model Context Protocol (MCP) communications and high-level business logic. It coordinates between the UI and specialized engines for database analysis and AI reasoning.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/mcp/server.py (lines 700-701)
```
def create_app() -> FastAPI:
    return app
```

### /home/neha/projects/agents/odb_autodba/services/autodba_service.py (lines 111-172)
```
def run_ai_investigation(query: str, db_key: str | None = None) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    prompt = (query or "").strip() or "Investigate Oracle performance issues"
    if detect_history_metric_question(prompt):
        return answer_history_metric_question(prompt, db_key=resolved_db_key)
    try:
        with db_key_context(resolved_db_key):
            report = InvestigationAgent(db_key=resolved_db_key).investigate(prompt, db_key=resolved_db_key)
        supporting = {
            "question": prompt,
            "problem_statement": report.problem_statement,
            "likely_cause": report.likely_cause,
            "evidence": list(report.evidence or []),
            "steps": [step.model_dump(mode="json") for step in (report.steps or [])],
            "trace_path": report.trace_path or "",
        }
        actions = list(report.recommended_next_actions or [])
        base_report = render_investigation_final_report(report)
        root_cause = infer_root_cause(
            mode="investigation",
            summary=report.summary,
            supporting_data=supporting,
            rendered_report=base_report,
        )
        heading = _investigation_heading_for_query(prompt=prompt, root_cause=root_cause)
        rendered = _append_root_cause_section(base_report, root_cause, heading=heading)
        result = {
            "ok": True,
            "db_key": resolved_db_key,
            "summary": report.summary,
            "rendered_report": rendered,
            "supporting_data": supporting,
            "root_cause": root_cause,
            "actions": actions,
            "trace_path": _extract_trace_path(supporting),
            "report_path": _extract_report_path(supporting),
        }
        return _attach_correlation(result, db_key=resolved_db_key, context=_context_from_question(prompt))
    except Exception as exc:
        return {
            "ok": False,
            "db_key": resolved_db_key,
            "summary": "Investigation failed.",
            "rendered_report": "",
            "supporting_data": {},
            "root_cause": {
                "category": "inconclusive",
                "confidence": "LOW",
                "evidence": ["Investigation agent raised an exception before evidence synthesis."],
                "primary_evidence": ["Investigation execution failed before deterministic synthesis."],
                "supporting_evidence": ["Review investigation logs and connectivity/privilege prerequisites."],
                "reasoning": "The investigation execution failed; root-cause attribution was not completed.",
                "impacted_components": ["investigation workflow"],
                "next_validation_step": "Retry investigation with validated DB connectivity and privileges for investigative SQL steps.",
            },
            "trace_path": "",
            "report_path": "",
            "error": _sanitize_error_message(str(exc)),
            "error_type": type(exc).__name__,
            "endpoint": "investigate",
            "actions": [],
        }
```

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


## Source Files:

- `mcp/client.py`
- `mcp/server.py`
- `services/autodba_service.py`
- `utils/formatter.py`
- `utils/severity.py`
- `utils/sql_analysis.py`

