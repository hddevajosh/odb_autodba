---
component_id: 1.1.3
component_name: Diagnostic Processor & Result Renderer
---

# Diagnostic Processor & Result Renderer

## Component Description

Encapsulates the Investigator logic and the transformation of raw agent outputs into human-readable dashboard elements. It handles the rendering of complex SQL results, remediation plans, and review summaries.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 132-133)
```
def _investigator() -> InvestigationAgent:
    return InvestigationAgent()
```

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 721-765)
```
def _render_mcp_result(job_payload: dict, *, fallback_title: str) -> str:
    result = job_payload.get("result") if isinstance(job_payload.get("result"), dict) else {}
    if isinstance(result.get("rendered_report"), str) and result.get("rendered_report").strip():
        return str(result.get("rendered_report"))
    summary_raw = result.get("summary") or job_payload.get("summary")
    summary = str(summary_raw).strip() if summary_raw is not None else ""
    if summary:
        lines = [f"# {fallback_title}", "", summary]
    else:
        trace_path = str(result.get("trace_path") or "").strip()
        is_investigation = fallback_title.strip().lower() == "oracle investigation"
        if is_investigation and trace_path:
            lines = [
                f"# {fallback_title}",
                "",
                "Investigation trace was captured, but a hydrated report was unavailable.",
                f"Trace path: `{trace_path}`",
            ]
        elif _debug_payloads_enabled():
            fallback_obj = result if result else job_payload
            compact_json = json.dumps(fallback_obj, ensure_ascii=True, indent=2, default=str)
            lines = [f"# {fallback_title}", "", "Debug payload:", "```json", compact_json, "```"]
        else:
            status = str(job_payload.get("status") or "unknown")
            error = _safe_error_message(str(job_payload.get("error") or result.get("error") or ""))
            lines = [
                f"# {fallback_title}",
                "",
                "No rendered report or summary was provided by the MCP job.",
                f"Status: `{status}`",
            ]
            if error:
                lines.append(f"Error: {error}")
    supporting = result.get("supporting_data")
    if isinstance(supporting, dict):
        history_sources = supporting.get("history_data_sources")
        if isinstance(history_sources, dict) and history_sources:
            lines.extend(
                [
                    "",
                    f"History source: {history_sources.get('history_source_used') or 'unknown'}",
                    f"Index status: {history_sources.get('history_index_status') or 'unknown'}",
                ]
            )
    return "\n".join(lines)
```

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 850-867)
```
def _execute_remediation(confirmed: bool, response_state: dict, selected_db_key: str | None = None):
    payload = (response_state or {}).get("response") or {}
    proposal_data = payload.get("remediation_proposal")
    if not proposal_data:
        return "No remediation proposal is available.", _action_history_markdown(selected_db_key)
    proposal = PlannerResponse.model_validate(payload).remediation_proposal
    review = review_remediation_proposal(proposal)
    review_text = _format_review_summary(review)
    if review.status != "approved":
        return f"Execution blocked by reviewer.\n{review_text}", _action_history_markdown(selected_db_key)
    decision = evaluate_action(proposal, ExecutionContext(confirmed=confirmed))
    if not decision.allowed:
        reasons = "; ".join(v.message for v in decision.violations)
        return f"{review_text}\nExecution blocked by guardrails: {reasons}", _action_history_markdown(selected_db_key)
    execution = execute_remediation_action(proposal)
    record = RemediationRecord(created_at=datetime.now(UTC).isoformat(), proposal=proposal, review=review, execution=execution)
    append_action_record(record, db_key=selected_db_key)
    return f"{review_text}\nExecution status: {execution.status}. {execution.message}", _action_history_markdown(selected_db_key)
```


## Source Files:

- `frontend/gradio_app.py`

