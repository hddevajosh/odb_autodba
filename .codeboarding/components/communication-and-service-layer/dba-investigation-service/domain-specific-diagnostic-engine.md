---
component_id: 2.2.2
component_name: Domain-Specific Diagnostic Engine
---

# Domain-Specific Diagnostic Engine

## Component Description

Contains the "expert" logic required to interpret complex Oracle database performance artifacts. It performs deep analysis on specific database states such as SQL execution plans, session locks, and workload repository snapshots.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/services/autodba_service.py (lines 670-694)
```
def analyze_awr(question: str | None = None, db_key: str | None = None) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    prompt = (question or "").strip() or "Analyze AWR from saved health runs."
    answer = HistoryService().answer_history_question(
        user_query=prompt,
        requested_domain="awr",
        db_key=resolved_db_key,
    )
    rendered_report = render_history_answer(answer)
    summary_lines = answer.get("summary_lines") if isinstance(answer.get("summary_lines"), list) else []
    summary = str(summary_lines[0]).strip() if summary_lines else "AWR analysis completed from saved traces."
    result = {
        "ok": True,
        "db_key": resolved_db_key,
        "summary": summary,
        "rendered_report": rendered_report,
        "supporting_data": answer,
        "trace_path": "",
        "report_path": _write_rendered_export(
            rendered_report=rendered_report,
            db_key=resolved_db_key,
            prefix="awr_analysis",
        ),
    }
    return _attach_correlation(result, db_key=resolved_db_key, context="sql")
```

### /home/neha/projects/agents/odb_autodba/services/autodba_service.py (lines 697-725)
```
def analyze_blocking_sessions(db_key: str | None = None) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    with db_key_context(resolved_db_key):
        active_rows = [row.model_dump(mode="json") for row in get_running_sessions_inventory()]
        blocking_rows = [row.model_dump(mode="json") for row in get_blocking_chains()]
        resource_rows = get_top_session_resource_candidates(limit=10)
    rendered_report = _render_blocking_report(
        active_rows=active_rows,
        blocking_rows=blocking_rows,
        resource_rows=resource_rows,
    )
    result = {
        "ok": True,
        "db_key": resolved_db_key,
        "summary": f"Blocking analysis completed ({len(blocking_rows)} blocking chain row(s)).",
        "rendered_report": rendered_report,
        "supporting_data": {
            "active_rows": active_rows,
            "blocking_rows": blocking_rows,
            "resource_rows": resource_rows,
        },
        "trace_path": "",
        "report_path": _write_rendered_export(
            rendered_report=rendered_report,
            db_key=resolved_db_key,
            prefix="blocking_analysis",
        ),
    }
    return _attach_correlation(result, db_key=resolved_db_key, context="blocking")
```

### /home/neha/projects/agents/odb_autodba/services/autodba_service.py (lines 175-198)
```
def analyze_sql_id(sql_id: str, db_key: str | None = None) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    normalized_sql_id = (sql_id or "").strip().lower()
    if not normalized_sql_id:
        raise ValueError("sql_id is required")
    with db_key_context(resolved_db_key):
        deep_dive = build_sql_id_deep_dive_report(normalized_sql_id)
    rendered_report = render_sql_id_deep_dive_report(deep_dive)
    supporting_data = deep_dive.model_dump(mode="json")
    result = {
        "ok": True,
        "db_key": resolved_db_key,
        "sql_id": normalized_sql_id,
        "summary": f"SQL_ID {normalized_sql_id} deep dive completed.",
        "rendered_report": rendered_report,
        "supporting_data": supporting_data,
        "trace_path": "",
        "report_path": _write_rendered_export(
            rendered_report=rendered_report,
            db_key=resolved_db_key,
            prefix=f"sql_id_{normalized_sql_id}",
        ),
    }
    return _attach_correlation(result, db_key=resolved_db_key, context="sql")
```


## Source Files:

- `services/autodba_service.py`

