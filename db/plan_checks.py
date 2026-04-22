from __future__ import annotations

import re
from typing import Any

from odb_autodba.db.connection import fetch_all, fetch_one
from odb_autodba.models.schemas import FormattedPlanSection, PlanEvidence


DISPLAY_CURSOR_FORMAT = "ALLSTATS LAST +PREDICATE +PEEKED_BINDS +NOTE"
DISPLAY_AWR_FORMAT = "TYPICAL"


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


def collect_plan_evidence_for_top_sql(sql_ids: list[str]) -> list[PlanEvidence]:
    return [collect_plan_history_for_sql_id(sql_id) for sql_id in sql_ids[:5] if sql_id]


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


def _from_display_cursor(*, sql_id: str, preferred_child: int | None, notes: list[str]) -> FormattedPlanSection | None:
    children_to_try: list[int | None] = [preferred_child, None]
    for child in children_to_try:
        if child is None and children_to_try.count(None) > 1:
            continue
        try:
            rows = fetch_all(
                """
                select plan_table_output
                from table(dbms_xplan.display_cursor(:sql_id, :child_no, :fmt))
                """,
                {"sql_id": sql_id, "child_no": child, "fmt": DISPLAY_CURSOR_FORMAT},
                max_rows=500,
            )
            lines = _extract_plan_lines(rows)
            if not lines:
                continue
            return FormattedPlanSection(
                available=True,
                source_used="DBMS_XPLAN.DISPLAY_CURSOR",
                child_number=child,
                format_used=DISPLAY_CURSOR_FORMAT,
                lines=lines,
                notes=[],
            )
        except Exception as exc:
            notes.append(f"DISPLAY_CURSOR unavailable: {exc}")
    return None


def _from_display_awr(
    *,
    sql_id: str,
    preferred_plan_hash: int | None,
    awr_payload: dict[str, Any],
    notes: list[str],
) -> FormattedPlanSection | None:
    try:
        db_row = fetch_one("select dbid from v$database")
        dbid = _as_int((db_row or {}).get("dbid"))
    except Exception as exc:
        notes.append(f"DISPLAY_AWR skipped (dbid unavailable): {exc}")
        return None
    if dbid is None:
        notes.append("DISPLAY_AWR skipped because dbid could not be determined.")
        return None

    plan_hashes: list[int] = []
    if preferred_plan_hash is not None:
        plan_hashes.append(preferred_plan_hash)
    for row in awr_payload.get("plan_changes") or []:
        if not isinstance(row, dict):
            continue
        plan_hash = _as_int(row.get("plan_hash_value"))
        if plan_hash is not None and plan_hash not in plan_hashes:
            plan_hashes.append(plan_hash)
    if not plan_hashes:
        notes.append("DISPLAY_AWR skipped because no plan hash value was available.")
        return None

    for plan_hash in plan_hashes[:3]:
        try:
            rows = fetch_all(
                """
                select plan_table_output
                from table(dbms_xplan.display_awr(:sql_id, :plan_hash, :dbid, :fmt))
                """,
                {"sql_id": sql_id, "plan_hash": plan_hash, "dbid": dbid, "fmt": DISPLAY_AWR_FORMAT},
                max_rows=500,
            )
            lines = _extract_plan_lines(rows)
            if not lines:
                continue
            return FormattedPlanSection(
                available=True,
                source_used="DBMS_XPLAN.DISPLAY_AWR",
                plan_hash_value=plan_hash,
                format_used=DISPLAY_AWR_FORMAT,
                lines=lines,
                notes=[],
            )
        except Exception as exc:
            notes.append(f"DISPLAY_AWR unavailable for plan_hash={plan_hash}: {exc}")
    return None


def _fallback_plan_lines(rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return []
    out = [
        "Id  Parent  Operation                               Object                     Cost   Card",
        "--  ------  --------------------------------------  -------------------------  -----  -----",
    ]
    for row in rows[:250]:
        op = _op_text(row)
        obj = str(row.get("object_name") or row.get("object_owner") or "-")
        out.append(
            f"{str(row.get('id', '-')):>2}  "
            f"{str(row.get('parent_id', '-')):>6}  "
            f"{op[:38]:<38}  "
            f"{obj[:25]:<25}  "
            f"{str(row.get('cost', '-')):>5}  "
            f"{str(row.get('cardinality', '-')):>5}"
        )
    return out


def _interpret_plan(*, raw_plan_lines: list[dict[str, Any]], rendered_lines: list[str]) -> dict[str, Any]:
    join_types: set[str] = set()
    access_paths: set[str] = set()
    full_scans: set[str] = set()
    index_access: set[str] = set()

    for row in raw_plan_lines:
        op = str(row.get("operation") or "").upper()
        options = str(row.get("options") or "").upper()
        op_text = " ".join(part for part in [op, options] if part).strip()
        obj_name = str(row.get("object_name") or "-")
        if "JOIN" in op_text:
            join_types.add(op_text)
        if "TABLE ACCESS" in op_text or "INDEX" in op_text:
            access_paths.add(op_text)
        if "TABLE ACCESS" in op_text and "FULL" in op_text:
            full_scans.add(obj_name)
        if "INDEX" in op_text:
            index_access.add(obj_name)

    predicate_summary = _predicate_summary(rendered_lines)
    dynamic_sampling = any("dynamic sampling" in str(line).lower() for line in rendered_lines)

    statements: list[str] = []
    if join_types:
        statements.append(f"Join operations seen: {', '.join(sorted(join_types)[:4])}.")
    if full_scans:
        statements.append(f"Full scans observed on: {', '.join(sorted(full_scans)[:5])}.")
    if index_access:
        statements.append(f"Index access observed on: {', '.join(sorted(index_access)[:5])}.")
    if dynamic_sampling:
        statements.append("Dynamic sampling note detected in plan output.")
    if predicate_summary:
        statements.append("Predicate details were captured and should be reviewed for selectivity/cardinality mismatch.")
    if not statements:
        statements.append("No strong row-source pattern was inferred from available plan evidence.")

    return {
        "join_types": sorted(join_types),
        "access_paths": sorted(access_paths),
        "full_scan_objects": sorted(full_scans),
        "index_access_objects": sorted(index_access),
        "predicate_summary": predicate_summary,
        "interpretation": " ".join(statements).strip(),
    }


def _predicate_summary(lines: list[str]) -> list[str]:
    if not lines:
        return []
    out: list[str] = []
    in_predicate_block = False
    for raw in lines:
        line = str(raw).strip()
        if not line:
            if in_predicate_block and out:
                break
            continue
        if "predicate information" in line.lower():
            in_predicate_block = True
            continue
        if in_predicate_block:
            if line.startswith("Note") or re.match(r"^-{3,}$", line):
                continue
            out.append(line)
            if len(out) >= 8:
                break
    return out


def _extract_plan_lines(rows: list[dict[str, Any]]) -> list[str]:
    lines = []
    for row in rows:
        line = row.get("plan_table_output")
        if line is None:
            continue
        lines.append(str(line))
    return lines


def _op_text(row: dict[str, Any]) -> str:
    operation = str(row.get("operation") or "").strip()
    options = str(row.get("options") or "").strip()
    if options:
        return f"{operation} {options}".strip()
    return operation


def _first_non_null(rows: list[dict[str, Any]], key: str) -> Any:
    for row in rows:
        value = row.get(key)
        if value is not None:
            return value
    return None


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None
