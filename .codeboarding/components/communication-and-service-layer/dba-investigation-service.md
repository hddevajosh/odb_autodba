---
component_id: 2.2
component_name: DBA Investigation Service
---

# DBA Investigation Service

## Component Description

The core logic engine that orchestrates complex database analysis tasks. It performs natural language intent detection to determine if a user is asking about historical metrics or current health, then coordinates with AI agents to run deep investigations into database performance issues.

---

## Key References:

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

### /home/neha/projects/agents/odb_autodba/services/autodba_service.py (lines 29-54)
```
def run_health_check(db_key: str | None = None) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    with db_key_context(resolved_db_key):
        response = PlannerAgent(db_key=resolved_db_key).handle_message("Check health of my Oracle database", db_key=resolved_db_key)
    supporting = _coerce_supporting_data(response)
    trace_path = _extract_trace_path(supporting)
    report_path = _extract_report_path(supporting)
    base_report = render_planner_response(response)
    root_cause = infer_root_cause(
        mode="health",
        summary=response.summary,
        supporting_data=supporting,
        rendered_report=base_report,
    )
    rendered_report = _append_root_cause_section(base_report, root_cause)
    result = {
        "ok": True,
        "db_key": resolved_db_key,
        "summary": response.summary,
        "rendered_report": rendered_report,
        "supporting_data": supporting,
        "root_cause": root_cause,
        "trace_path": trace_path,
        "report_path": report_path,
    }
    return _attach_correlation(result, db_key=resolved_db_key, context="general")
```

### /home/neha/projects/agents/odb_autodba/utils/sql_analysis.py (lines 104-155)
```
def detect_history_metric_question(prompt: str) -> dict[str, Any] | None:
    lowered = " ".join((prompt or "").strip().lower().split())
    if not lowered:
        return None

    if "show historical trends" in lowered or "oracle historical trend analysis" in lowered:
        return None

    metric_family, requested_fields = _detect_metric_family(lowered)
    if metric_family is None:
        return None

    if _looks_like_live_now_query(lowered) and not _contains_explicit_history_scope(lowered):
        return None

    aggregation = _detect_aggregation(lowered)
    has_usage_hint = any(token in lowered for token in ("usage", "consumption", "overall"))
    has_history_scope = _contains_explicit_history_scope(lowered)
    has_question_shape = any(
        token in lowered
        for token in (
            "what is",
            "what has been",
            "were there any",
            "how many",
            "did ",
            "?",
        )
    )
    if aggregation is None and has_usage_hint:
        aggregation = "avg"
    if aggregation is None and not has_history_scope and not has_question_shape:
        return None
    if aggregation is None and metric_family == "active_sessions":
        # Avoid stealing normal live session prompts like "show active sessions".
        return None
    if aggregation is None:
        aggregation = "latest"

    time_window = _detect_time_window(lowered)
    entity_filter = _detect_entity_filter(lowered, metric_family)

    payload: dict[str, Any] = {
        "metric_family": metric_family,
        "requested_fields": requested_fields,
        "aggregation": aggregation,
        "time_window": time_window,
        "entity_filter": entity_filter,
        # Backward compatibility for older call sites/tests.
        "metric": metric_family,
    }
    return payload
```


## Source Files:

- `services/autodba_service.py`
- `utils/sql_analysis.py`

