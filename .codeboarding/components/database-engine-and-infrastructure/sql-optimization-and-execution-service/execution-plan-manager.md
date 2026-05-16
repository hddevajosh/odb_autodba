---
component_id: 4.3.2
component_name: Execution Plan Manager
---

# Execution Plan Manager

## Component Description

Responsible for the retrieval, parsing, and formatting of Oracle execution plans from various sources (AWR, Cursor Cache). It translates complex database operations into a format suitable for agentic reasoning and human review.

---

## Key References:

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

### /home/neha/projects/agents/odb_autodba/db/plan_checks.py (lines 14-45)
```
def collect_plan_history_for_sql_id(sql_id: str) -> PlanEvidence:
    rows = []
    queries = [
        """
        select distinct plan_hash_value
        from v$sql
        where sql_id = :sql_id and plan_hash_value is not null
        order by plan_hash_value
        """,
        """
        select distinct plan_hash_value
        from dba_hist_sqlstat
        where sql_id = :sql_id and plan_hash_value is not null
        order by plan_hash_value
        """,
    ]
    for sql in queries:
        try:
            rows = fetch_all(sql, {"sql_id": sql_id}, max_rows=20)
            if rows:
                break
        except Exception:
            continue
    plans = [int(r["plan_hash_value"]) for r in rows if r.get("plan_hash_value") is not None]
    return PlanEvidence(
        sql_id=sql_id,
        distinct_plan_hashes=plans,
        current_plan_hash=plans[0] if plans else None,
        plan_count=len(plans),
        churn_detected=len(plans) > 1,
        summary=(f"Observed {len(plans)} plan hash values for SQL_ID {sql_id}." if plans else f"No plan evidence found for SQL_ID {sql_id}."),
    )
```


## Source Files:

- `db/plan_checks.py`

