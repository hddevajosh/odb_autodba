from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from odb_autodba.agents.investigation_agent import InvestigationAgent
from odb_autodba.agents.planner_agent import PlannerAgent
from odb_autodba.agents.correlation_engine import correlate_root_cause_from_traces, render_correlation_section
from odb_autodba.agents.root_cause_engine import infer_root_cause, render_root_cause_section
from odb_autodba.db.connection import db_key_context
from odb_autodba.db.query_deep_dive import build_sql_id_deep_dive_report
from odb_autodba.db.running_sessions import get_blocking_chains, get_running_sessions_inventory, get_top_session_resource_candidates
from odb_autodba.history.metric_catalog import metric_catalog_by_key, supported_metric_families
from odb_autodba.history.service import HistoryService
from odb_autodba.rag.trace_store import read_health_run_traces
from odb_autodba.runtime_paths import get_exports_dir
from odb_autodba.target_registry import get_oracle_target
from odb_autodba.utils.formatter import (
    format_dba_table,
    render_history_answer,
    render_investigation_final_report,
    render_planner_response,
    render_sql_id_deep_dive_report,
)
from odb_autodba.utils.sql_analysis import detect_history_metric_question, looks_like_history_request

LOGGER = logging.getLogger(__name__)


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
        "issues": [issue.model_dump(mode="json") for issue in (response.issues or [])],
        "remediation_proposal": response.remediation_proposal.model_dump(mode="json")
        if response.remediation_proposal is not None
        else None,
        "remediation_review": supporting.get("review") if isinstance(supporting.get("review"), dict) else None,
        "root_cause": root_cause,
        "trace_path": trace_path,
        "report_path": report_path,
    }
    return _attach_correlation(result, db_key=resolved_db_key, context="general")


def get_historical_trends(db_key: str | None = None) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    with db_key_context(resolved_db_key):
        response = PlannerAgent(db_key=resolved_db_key).handle_message("Show historical trends", db_key=resolved_db_key)
    supporting = _coerce_supporting_data(response)
    history_sources = supporting.get("history_data_sources") if isinstance(supporting.get("history_data_sources"), dict) else {}
    base_report = render_planner_response(response)
    root_cause = infer_root_cause(
        mode="history",
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
        "history_data_sources": history_sources,
        "trace_path": _extract_trace_path(supporting),
        "report_path": _extract_report_path(supporting),
    }
    return _attach_correlation(result, db_key=resolved_db_key, context="general")


def get_active_sessions(db_key: str | None = None) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    with db_key_context(resolved_db_key):
        response = PlannerAgent(db_key=resolved_db_key).handle_message("Show active sessions", db_key=resolved_db_key)
    supporting = _coerce_supporting_data(response)
    base_report = render_planner_response(response)
    root_cause = infer_root_cause(
        mode="sessions",
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
        "trace_path": _extract_trace_path(supporting),
        "report_path": _extract_report_path(supporting),
    }
    return _attach_correlation(result, db_key=resolved_db_key, context="blocking")


def run_ai_investigation(
    query: str,
    db_key: str | None = None,
    *,
    thread_id: str | None = None,
    continue_context: bool | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    prompt = (query or "").strip() or "Investigate Oracle performance issues"
    question_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16] if prompt else ""
    requested_thread_id = str(thread_id or "").strip()
    thread_context_requested = bool(requested_thread_id or continue_context)
    LOGGER.info(
        "investigation_request_received db_key=%s question_present=%s question_len=%s question_hash=%s thread_id=%s continue_context=%s thread_memory_enabled=false",
        resolved_db_key,
        str(bool(prompt)).lower(),
        len(prompt),
        question_hash,
        requested_thread_id,
        str(continue_context if continue_context is not None else ""),
    )
    if thread_context_requested:
        LOGGER.info(
            "investigation_thread_context_ignored=true db_key=%s thread_id=%s continue_context=%s thread_memory_enabled=false",
            resolved_db_key,
            requested_thread_id,
            str(continue_context if continue_context is not None else ""),
        )
    if looks_like_history_request(prompt) and detect_history_metric_question(prompt) and not _is_sql_id_metadata_investigation_prompt(prompt):
        return answer_history_metric_question(prompt, db_key=resolved_db_key)
    try:
        with db_key_context(resolved_db_key):
            report = InvestigationAgent(db_key=resolved_db_key).investigate(
                prompt,
                db_key=resolved_db_key,
            )
        if not str(report.problem_statement or "").strip():
            report.problem_statement = prompt
        diagnostic_mode = _should_include_investigation_rca(prompt=prompt, report=report)
        supporting = {
            "question": prompt,
            "problem_statement": report.problem_statement,
            "likely_cause": report.likely_cause,
            "evidence": list(report.evidence or []),
            "steps": [step.model_dump(mode="json") for step in (report.steps or [])],
            "trace_path": report.trace_path or "",
            "investigation_planner_requested": bool(report.planner_requested),
            "planner_provider": report.planner_provider,
            "planner_model": report.planner_model,
            "planner_elapsed_ms": report.planner_elapsed_ms,
            "planner_steps_count": report.planner_steps_count,
            "fallback_used": bool(report.fallback_used),
            "fallback_reason": report.fallback_reason,
            "plan_type": report.plan_type,
            "diagnostic_mode": diagnostic_mode,
            "thread_memory_enabled": False,
            "thread_context_ignored": bool(thread_context_requested),
            "thread_id_ignored": requested_thread_id,
            "termination_reason": report.termination_reason,
            "clarification_question": str(report.clarification_question or "").strip(),
        }
        investigation_status = "needs_clarification" if str(report.termination_reason or "").strip() == "clarification_required" else "complete"
        actions = list(report.recommended_next_actions or [])
        base_report = render_investigation_final_report(report)
        root_cause: dict[str, Any] = {}
        rendered = base_report
        if diagnostic_mode:
            root_cause = infer_root_cause(
                mode="investigation",
                summary=report.summary,
                supporting_data=supporting,
                rendered_report=base_report,
            )
            heading = _investigation_heading_for_query(prompt=prompt, root_cause=root_cause)
            rendered = _append_root_cause_section(base_report, root_cause, heading=heading)
        LOGGER.info(
            "investigation_planner_requested=%s planner_provider=%s planner_model=%s planner_elapsed_ms=%s planner_steps_count=%s fallback_used=%s fallback_reason=%s diagnostic_mode=%s",
            str(bool(report.planner_requested)).lower(),
            str(report.planner_provider or ""),
            str(report.planner_model or ""),
            int(report.planner_elapsed_ms or 0),
            int(report.planner_steps_count or 0),
            str(bool(report.fallback_used)).lower(),
            str(report.fallback_reason or ""),
            str(bool(diagnostic_mode)).lower(),
        )
        result = {
            "ok": True,
            "db_key": resolved_db_key,
            "problem_statement": prompt,
            "question": prompt,
            "summary": report.summary,
            "report_text": rendered,
            "rendered_report": rendered,
            "supporting_data": supporting,
            "root_cause": root_cause,
            "actions": actions,
            "trace_path": _extract_trace_path(supporting),
            "report_path": _extract_report_path(supporting),
            "thread_id": requested_thread_id,
            "thread_memory_enabled": False,
            "status": investigation_status,
        }
        if diagnostic_mode:
            return _attach_correlation(result, db_key=resolved_db_key, context=_context_from_question(prompt))
        return result
    except Exception as exc:
        return {
            "ok": False,
            "db_key": resolved_db_key,
            "problem_statement": prompt,
            "question": prompt,
            "summary": "Investigation failed.",
            "report_text": "",
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
            "thread_id": requested_thread_id,
            "thread_memory_enabled": False,
        }


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


def answer_history_metric_question(question: str, db_key: str | None = None) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    prompt = (question or "").strip()
    if not prompt:
        raise ValueError("question is required")
    jsonl = HistoryService().jsonl
    metric_request = detect_history_metric_question(prompt)
    index_answer = jsonl.answer_history_question_from_index(
        user_query=prompt,
        requested_domain=str((metric_request or {}).get("metric_family") or ""),
        db_key=resolved_db_key,
    )
    if index_answer and index_answer.get("confident"):
        rendered_report = str(index_answer.get("rendered_report") or "")
        summary = str(index_answer.get("summary") or "Historical metric answer generated from index.")
        supporting = index_answer.get("supporting_data") if isinstance(index_answer.get("supporting_data"), dict) else {}
        supporting["source"] = "index"
        supporting["route"] = index_answer.get("route")
    else:
        traces = read_health_run_traces(limit=1000, db_key=resolved_db_key)
        rendered_report, summary, supporting = _render_general_history_metric_summary(
            question=prompt,
            metric_request=metric_request,
            traces=traces,
            db_key=resolved_db_key,
        )
        supporting["source"] = "jsonl_fallback"

    result = {
        "ok": True,
        "db_key": resolved_db_key,
        "summary": summary,
        "rendered_report": rendered_report,
        "supporting_data": supporting,
        "source": str(supporting.get("source") or "jsonl_fallback"),
        "trace_path": "",
        "report_path": _write_rendered_export(
            rendered_report=rendered_report,
            db_key=resolved_db_key,
            prefix="history_metric",
        ),
    }
    metric_family = str((supporting.get("metric_family") if isinstance(supporting, dict) else "") or "")
    return _attach_correlation(result, db_key=resolved_db_key, context=_context_from_metric_family(metric_family))


def _render_general_history_metric_summary(
    *,
    question: str,
    metric_request: dict[str, Any] | None,
    traces: list[Any],
    db_key: str,
) -> tuple[str, str, dict[str, Any]]:
    catalog = metric_catalog_by_key()
    if not metric_request:
        supported = ", ".join(supported_metric_families())
        message = (
            "I could not map that question to a supported historical metric family. "
            f"Supported families: {supported}."
        )
        return (
            "# Historical Metric Analysis\n\n"
            f"{message}\n",
            message,
            {
                "question_type": "history_metric",
                "history_available": bool(traces),
                "fallback_used": True,
                "supported_metric_families": supported_metric_families(),
                "metric_request": {},
            },
        )

    metric_family = str(metric_request.get("metric_family") or metric_request.get("metric") or "").strip().lower()
    aggregation = str(metric_request.get("aggregation") or "latest").strip().lower()
    time_window = metric_request.get("time_window") if isinstance(metric_request.get("time_window"), dict) else {"label": "all"}
    requested_fields = metric_request.get("requested_fields")
    if not isinstance(requested_fields, list):
        requested_fields = []
    if not requested_fields and metric_family in catalog:
        requested_fields = list(catalog[metric_family].fields)

    if metric_family not in catalog:
        supported = ", ".join(supported_metric_families())
        message = f"Unsupported historical metric family '{metric_family}'. Supported families: {supported}."
        return (
            "# Historical Metric Analysis\n\n" + message + "\n",
            message,
            {
                "question_type": "history_metric",
                "metric_family": metric_family,
                "aggregation": aggregation,
                "time_window": time_window,
                "runs_scanned": len(traces),
                "matched_runs": 0,
                "fields": requested_fields,
                "fallback_used": True,
                "supported_metric_families": supported_metric_families(),
            },
        )

    traces_in_window = _filter_traces_by_time_window(traces=traces, time_window=time_window)
    if not traces_in_window:
        window_label = str(time_window.get("label") or "all")
        no_runs_message = f"No saved health reports found for time window '{window_label}'. Showing current snapshot instead."
        title = f"# Historical {catalog[metric_family].title}"
        rendered = (
            f"{title}\n\n"
            f"Question: {question}\n"
            f"Target database: {db_key}\n"
            f"Time window: {window_label}\n\n"
            f"Answer:\n{no_runs_message}\n"
        )
        return rendered, no_runs_message, {
            "question_type": "history_metric",
            "metric_family": metric_family,
            "aggregation": aggregation,
            "time_window": time_window,
            "runs_scanned": len(traces),
            "matched_runs": 0,
            "fields": requested_fields,
            "fallback_used": True,
        }

    evidence = _collect_metric_evidence(
        traces=traces_in_window,
        fields=requested_fields,
        entity_filter=str(metric_request.get("entity_filter") or "").strip() or None,
    )
    if evidence["sample_count"] == 0:
        title = f"# Historical {catalog[metric_family].title}"
        rendered = (
            f"{title}\n\n"
            f"Question: {question}\n"
            f"Time window: {time_window.get('label', 'all')}\n\n"
            "Answer:\nNo saved health reports in this window contained the requested metric values.\n"
        )
        return rendered, "No saved health reports contained the requested metric values.", {
            "question_type": "history_metric",
            "metric_family": metric_family,
            "aggregation": aggregation,
            "time_window": time_window,
            "runs_scanned": len(traces),
            "matched_runs": len(traces_in_window),
            "fields": requested_fields,
            "fallback_used": True,
        }

    rendered, summary = _render_focused_history_metric_report(
        question=question,
        metric_family=metric_family,
        metric_title=catalog[metric_family].title,
        aggregation=aggregation,
        time_window_label=str(time_window.get("label") or "all"),
        evidence=evidence,
        runs_scanned=len(traces),
        runs_matched=len(traces_in_window),
    )
    return rendered, summary, {
        "question_type": "history_metric",
        "metric_family": metric_family,
        "aggregation": aggregation,
        "time_window": time_window,
        "runs_scanned": len(traces),
        "matched_runs": len(traces_in_window),
        "fields": requested_fields,
        "sample_count": evidence.get("sample_count"),
        "field_summaries": _fallback_field_summaries(evidence=evidence),
        "fallback_used": False,
    }


def _filter_traces_by_time_window(*, traces: list[Any], time_window: dict[str, Any]) -> list[Any]:
    label = str(time_window.get("label") or "all").strip().lower()
    if label in {"all", ""}:
        return list(traces)

    now = datetime.now(UTC)
    today_start = datetime(now.year, now.month, now.day, tzinfo=UTC)
    start: datetime | None = None
    end: datetime | None = now

    if label == "today":
        start = today_start
    elif label == "yesterday":
        start = today_start - timedelta(days=1)
        end = today_start
    elif label == "last_24_hours":
        start = now - timedelta(hours=24)
    elif label == "last_n_hours":
        start = now - timedelta(hours=max(int(time_window.get("hours") or 1), 1))
    elif label == "last_n_days":
        start = now - timedelta(days=max(int(time_window.get("days") or 1), 1))
    elif label == "this_week":
        start = today_start - timedelta(days=today_start.weekday())
    elif label == "last_week":
        this_week_start = today_start - timedelta(days=today_start.weekday())
        start = this_week_start - timedelta(days=7)
        end = this_week_start

    filtered: list[Any] = []
    for trace in traces:
        completed_at = _trace_completed_at(trace)
        if completed_at is None:
            continue
        if start and completed_at < start:
            continue
        if end and completed_at >= end:
            continue
        filtered.append(trace)
    return filtered


def _trace_completed_at(trace: Any) -> datetime | None:
    raw = None
    if hasattr(trace, "completed_at"):
        raw = getattr(trace, "completed_at", None)
    if raw is None and hasattr(trace, "recorded_at"):
        raw = getattr(trace, "recorded_at", None)
    if raw is None and isinstance(trace, dict):
        raw = trace.get("completed_at") or trace.get("recorded_at")
    if isinstance(raw, datetime):
        return raw.astimezone(UTC)
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return parsed.astimezone(UTC)
    except Exception:
        return None


def _collect_metric_evidence(*, traces: list[Any], fields: list[str], entity_filter: str | None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for trace in reversed(traces):
        metrics = trace.metrics if hasattr(trace, "metrics") and isinstance(trace.metrics, dict) else {}
        if not isinstance(metrics, dict):
            continue
        timestamp = _trace_completed_at(trace)
        ts_text = timestamp.isoformat() if isinstance(timestamp, datetime) else ""
        row: dict[str, Any] = {"timestamp": ts_text}
        for field in fields:
            for key in _candidate_metric_keys(field):
                if key not in metrics:
                    continue
                row[field] = metrics.get(key)
                break
        if entity_filter:
            table_name = str(metrics.get("hottest_tablespace") or "").upper()
            row["entity_match"] = table_name == entity_filter.upper()
            if not row["entity_match"]:
                continue
        rows.append(row)

    numeric_samples: dict[str, list[float]] = {field: [] for field in fields}
    event_timestamps: list[str] = []
    matched_runs = 0
    for row in rows:
        has_any = False
        for field in fields:
            value = _to_float(row.get(field))
            if value is None:
                continue
            numeric_samples[field].append(value)
            has_any = True
            if value > 0:
                event_timestamps.append(str(row.get("timestamp") or ""))
        if has_any:
            matched_runs += 1

    return {
        "rows": rows,
        "numeric_samples": numeric_samples,
        "sample_count": sum(len(values) for values in numeric_samples.values()),
        "matched_runs": matched_runs,
        "event_timestamps": [stamp for stamp in event_timestamps if stamp][:10],
    }


def _candidate_metric_keys(field: str) -> tuple[str, ...]:
    aliases: dict[str, tuple[str, ...]] = {
        "highest_tablespace_pct": ("highest_tablespace_pct", "hottest_tablespace_pct"),
        "highest_tablespace_name": ("highest_tablespace_name", "hottest_tablespace"),
        "alert_ora_tns_count": ("alert_ora_tns_count", "alert_log_count"),
        "top_sql_cpu_seconds": ("top_sql_cpu_seconds", "top_cpu_sql_cpu_s"),
        "top_sql_elapsed_seconds": ("top_sql_elapsed_seconds", "top_elapsed_sql_elapsed_s"),
        "redo_switches": ("redo_switches", "redo_switch_count"),
        "fra_used_pct": ("fra_used_pct", "fra_pct"),
        "incident_driver_sql": ("incident_driver_sql", "top_cpu_sql_id", "top_elapsed_sql_id"),
        "blocking_sessions": ("blocking_sessions", "blocking_count"),
    }
    return aliases.get(field, (field,))


def _to_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _render_focused_history_metric_report(
    *,
    question: str,
    metric_family: str,
    metric_title: str,
    aggregation: str,
    time_window_label: str,
    evidence: dict[str, Any],
    runs_scanned: int,
    runs_matched: int,
) -> tuple[str, str]:
    numeric_samples = evidence.get("numeric_samples") if isinstance(evidence.get("numeric_samples"), dict) else {}
    sample_lines: list[str] = []
    grouped_values: dict[str, list[float]] = {}
    per_field_values: dict[str, list[float]] = {}
    for field, values in numeric_samples.items():
        if not isinstance(values, list) or not values:
            continue
        vals = [float(v) for v in values]
        per_field_values[field] = vals
        semantic = _metric_semantic_category(field)
        grouped_values.setdefault(semantic, []).extend(vals)
        avg_val = sum(vals) / len(vals)
        field_label = _field_label(field)
        unit = _unit_suffix(semantic)
        sample_lines.append(
            f"- {field_label}: avg={avg_val:.2f}{unit}, min={min(vals):.2f}{unit}, max={max(vals):.2f}{unit}, latest={vals[-1]:.2f}{unit}"
        )

    if not grouped_values:
        return (
            f"# Historical {metric_title}\n\nQuestion: {question}\nTime window: {time_window_label}\n\nAnswer:\nNo numeric values found for requested metric.\n",
            "No numeric values found for requested historical metric.",
        )

    answer_lines: list[str] = []
    for field, values in per_field_values.items():
        semantic = _metric_semantic_category(field)
        unit = _unit_suffix(semantic)
        label = _field_label(field)
        if aggregation == "avg":
            answer_lines.append(f"Average {label}: {sum(values)/len(values):.2f}{unit}")
        elif aggregation == "min":
            answer_lines.append(f"Minimum {label}: {min(values):.2f}{unit}")
        elif aggregation == "max":
            answer_lines.append(f"Maximum {label}: {max(values):.2f}{unit}")
        elif aggregation == "trend":
            earliest = values[0]
            latest = values[-1]
            direction = "increased" if latest > earliest else "decreased" if latest < earliest else "remained stable"
            answer_lines.append(f"{label} trend: {direction} (earliest={earliest:.2f}{unit}, latest={latest:.2f}{unit})")
        elif aggregation == "latest":
            answer_lines.append(f"Latest {label}: {values[-1]:.2f}{unit}")

    category_order = [
        "cpu_percent",
        "memory_percent",
        "sql_cpu_time",
        "sql_elapsed_time",
        "counts",
        "ratios",
        "other",
    ]

    for category in category_order:
        values = grouped_values.get(category) or []
        if not values:
            continue
        label = _category_label(category)
        unit = _unit_suffix(category)
        if aggregation == "avg":
            value = sum(values) / len(values)
            answer_lines.append(f"Average {label}: {value:.2f}{unit}")
        elif aggregation == "min":
            answer_lines.append(f"Minimum {label}: {min(values):.2f}{unit}")
        elif aggregation == "max":
            answer_lines.append(f"Maximum {label}: {max(values):.2f}{unit}")
        elif aggregation == "count":
            count = sum(1 for value in values if value > 0)
            answer_lines.append(f"{label} occurrences (>0): {count}")
        elif aggregation == "any":
            any_hit = any(value > 0 for value in values)
            answer_lines.append(f"{label} present: {'Yes' if any_hit else 'No'}")
        elif aggregation == "trend":
            earliest = values[0]
            latest = values[-1]
            direction = "increased" if latest > earliest else "decreased" if latest < earliest else "remained stable"
            answer_lines.append(f"{label} trend: {direction} (earliest={earliest:.2f}{unit}, latest={latest:.2f}{unit})")
        else:
            answer_lines.append(f"Latest {label}: {values[-1]:.2f}{unit}")

    if metric_family == "blocking":
        answer_lines.extend(_blocking_history_summary(evidence=evidence, runs_matched=runs_matched))

    summary = (
        f"Historical {metric_title.lower()} summary generated across {runs_matched} matched run(s) "
        f"with {len(grouped_values)} metric category group(s)."
    )

    evidence_lines = [
        f"- Health reports scanned: {runs_scanned}",
        f"- Health reports matched in time window: {runs_matched}",
        f"- Numeric observations: {sum(len(vals) for vals in grouped_values.values())}",
        f"- Metric category groups: {', '.join([_category_label(key) for key in grouped_values.keys()])}",
    ]
    event_timestamps = evidence.get("event_timestamps") if isinstance(evidence.get("event_timestamps"), list) else []
    if event_timestamps:
        evidence_lines.append(f"- Event timestamps (up to 10): {', '.join(event_timestamps)}")

    rendered = "\n".join(
        [
            f"# Historical {metric_title}",
            "",
            f"Question: {question}",
            f"Time window: {time_window_label}",
            "",
            "Answer:",
            *(answer_lines or ["No grouped metric summary available."]),
            "",
            "Evidence:",
            *evidence_lines,
            "",
            "Field summaries:",
            *(sample_lines or ["- No field-level numeric summary available."]),
        ]
    )
    return rendered, summary


def _fallback_field_summaries(*, evidence: dict[str, Any]) -> list[dict[str, Any]]:
    numeric_samples = evidence.get("numeric_samples") if isinstance(evidence.get("numeric_samples"), dict) else {}
    summaries: list[dict[str, Any]] = []
    for field, raw_values in numeric_samples.items():
        if not isinstance(raw_values, list) or not raw_values:
            continue
        values = [float(value) for value in raw_values]
        recent_values = values[-3:] if len(values) >= 3 else values
        average = sum(values) / len(values)
        recent_average = sum(recent_values) / len(recent_values)
        latest = values[-1]
        minimum = min(values)
        maximum = max(values)
        summaries.append(
            {
                "field": str(field),
                "sample_count": len(values),
                "latest": round(latest, 3),
                "current": round(latest, 3),
                "average_normal": round(average, 3),
                "recent_average": round(recent_average, 3),
                "min": round(minimum, 3),
                "max": round(maximum, 3),
                "range": round(maximum - minimum, 3),
                "state": _fallback_metric_state(field=str(field), latest=latest, average=average),
            }
        )
    return summaries


def _fallback_metric_state(*, field: str, latest: float, average: float) -> str:
    threshold = 85.0 if field.endswith("_pct") else 1.0 if field.endswith("_count") else 120.0 if field.endswith(("_cpu_s", "_elapsed_s")) else None
    if threshold is not None and latest >= threshold:
        return "pressured"
    if average and latest >= average * 1.2:
        return "elevated"
    return "normal"


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


def _resolve_db_key(db_key: str | None) -> str:
    target = get_oracle_target(db_key)
    return target.db_key


def _coerce_supporting_data(response: Any) -> dict[str, Any]:
    payload = getattr(response, "supporting_data", None)
    if isinstance(payload, dict):
        return payload
    return {}


def _extract_trace_path(supporting_data: dict[str, Any]) -> str:
    trace_path = supporting_data.get("trace_path")
    if isinstance(trace_path, str):
        return trace_path
    return ""


def _extract_report_path(supporting_data: dict[str, Any]) -> str:
    for key in ("report_path", "dashboard_path", "html_report_path", "export_path"):
        value = supporting_data.get(key)
        if isinstance(value, str):
            return value
    return ""


def _append_root_cause_section(
    rendered_report: str,
    root_cause: dict[str, Any],
    *,
    heading: str = "## 🔴 Root Cause Analysis",
) -> str:
    base = (rendered_report or "").rstrip()
    section = render_root_cause_section(root_cause, heading=heading).strip()
    if not base:
        return section
    if "## 🔴 Root Cause Analysis" in base or "## 🔵 Investigation Conclusion" in base:
        return base
    return f"{base}\n\n{section}\n"


def _append_correlation_section(rendered_report: str, correlation: dict[str, Any]) -> str:
    base = (rendered_report or "").rstrip()
    section = render_correlation_section(correlation).strip()
    if not base:
        return section
    if "## 🔴 Root Cause Correlation" in base:
        return base
    return f"{base}\n\n{section}\n"


def _attach_correlation(result: dict[str, Any], *, db_key: str, context: str = "general") -> dict[str, Any]:
    payload = dict(result)
    supporting = payload.get("supporting_data") if isinstance(payload.get("supporting_data"), dict) else {}
    try:
        correlation = correlate_root_cause_from_traces(db_key=db_key, context=context)
        payload["correlation"] = correlation
        payload["rendered_report"] = _append_correlation_section(str(payload.get("rendered_report") or ""), correlation)
        if supporting:
            supporting = dict(supporting)
        else:
            supporting = {}
        supporting["correlation_sources_used"] = correlation.get("sources_used")
        supporting["correlation_context"] = context
        payload["supporting_data"] = supporting
    except Exception as exc:
        if supporting:
            supporting = dict(supporting)
        else:
            supporting = {}
        warnings = supporting.get("warnings") if isinstance(supporting.get("warnings"), list) else []
        warnings.append(f"Correlation engine warning: {_sanitize_error_message(str(exc))}")
        supporting["warnings"] = warnings
        payload["supporting_data"] = supporting
    return payload


def _field_label(field: str) -> str:
    labels = {
        "host_cpu_pct": "Host CPU",
        "container_cpu_pct": "Oracle CPU",
        "top_cpu_sql_cpu_s": "Top SQL CPU",
        "top_elapsed_sql_elapsed_s": "Top SQL Elapsed",
        "host_memory_pct": "Host Memory",
        "container_memory_pct": "Oracle Memory",
        "blocking_count": "Blocking Sessions",
    }
    return labels.get(field, field.replace("_", " ").title())


def _metric_semantic_category(field: str) -> str:
    name = str(field or "").strip().lower()
    if name.endswith("_cpu_pct"):
        return "cpu_percent"
    if name.endswith("_memory_pct"):
        return "memory_percent"
    if name.endswith("_cpu_s"):
        return "sql_cpu_time"
    if name.endswith("_elapsed_s"):
        return "sql_elapsed_time"
    if name.endswith("_count"):
        return "counts"
    if name.endswith("_pct") or name.endswith("_ratio"):
        return "ratios"
    return "other"


def _category_label(category: str) -> str:
    labels = {
        "cpu_percent": "CPU",
        "memory_percent": "Memory",
        "sql_cpu_time": "Top SQL CPU",
        "sql_elapsed_time": "Top SQL Elapsed",
        "counts": "Count",
        "ratios": "Ratio",
        "other": "Metric",
    }
    return labels.get(category, "Metric")


def _unit_suffix(category: str) -> str:
    if category in {"cpu_percent", "memory_percent", "ratios"}:
        return "%"
    if category in {"sql_cpu_time", "sql_elapsed_time"}:
        return " sec"
    return ""


def _blocking_history_summary(*, evidence: dict[str, Any], runs_matched: int) -> list[str]:
    rows = evidence.get("rows") if isinstance(evidence.get("rows"), list) else []
    blocking_values: list[float] = []
    last_occurrence: datetime | None = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = _to_float(row.get("blocking_sessions"))
        if value is None:
            value = _to_float(row.get("blocking_count"))
        if value is None:
            continue
        blocking_values.append(value)
        if value > 0:
            stamp = _parse_iso_utc(row.get("timestamp"))
            if stamp and (last_occurrence is None or stamp > last_occurrence):
                last_occurrence = stamp
    if not blocking_values:
        return []
    occurrences = sum(1 for value in blocking_values if value > 0)
    max_blocking = max(blocking_values) if blocking_values else 0.0
    affected_pct = (occurrences / max(runs_matched, 1)) * 100.0
    lines = [f"Blocking detected in {occurrences}/{runs_matched} runs ({affected_pct:.1f}%)"]
    lines.append(f"Max blocking sessions: {int(max_blocking)}")
    if last_occurrence:
        lines.append(f"Last occurrence: {last_occurrence.strftime('%Y-%m-%d %H:%M UTC')}")
    return lines


def _parse_iso_utc(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except Exception:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _context_from_metric_family(metric_family: str) -> str:
    key = str(metric_family or "").strip().lower()
    if key == "cpu":
        return "cpu"
    if key == "blocking":
        return "blocking"
    if key in {"sql_workload", "plan_stats"}:
        return "sql"
    if key == "memory":
        return "memory"
    return "general"


def _context_from_question(question: str) -> str:
    text = str(question or "").strip().lower()
    if any(token in text for token in ("blocking", "lock", "blocked session")):
        return "blocking"
    if any(token in text for token in ("cpu", "host cpu")):
        return "cpu"
    if any(token in text for token in ("memory", "pga", "sga", "temp")):
        return "memory"
    if any(token in text for token in ("sql", "plan hash", "sql_id")):
        return "sql"
    return "general"


def _is_sql_id_metadata_investigation_prompt(prompt: str) -> bool:
    text = str(prompt or "").strip().lower()
    if "sql_id" not in text and "sql id" not in text:
        return False
    metadata_tokens = (
        "memory or awr history",
        "exists in memory or awr history",
        "exists in memory",
        "awr history",
        "tables involved",
        "indexes used",
        "stats were last analyzed",
        "stale or missing",
        "plan objects",
        "sql text",
    )
    return any(token in text for token in metadata_tokens)


def _should_include_investigation_rca(*, prompt: str, report: Any) -> bool:
    plan_type = str(getattr(report, "plan_type", "") or "").strip().lower()
    if plan_type in {"inventory_read_only_lookup", "current_state", "list", "lookup", "read_only_lookup"}:
        return False
    if plan_type in {"diagnostic", "root_cause", "performance_diagnostic"}:
        return True
    text = str(prompt or "").strip().lower()
    diagnostic_tokens = (
        "root cause",
        "diagnose",
        "why",
        "slow",
        "bottleneck",
        "regression",
        "tune",
        "high wait",
        "latency",
        "high cpu",
        "performance issue",
        "sql_id performance",
        "blocking root cause",
    )
    return any(token in text for token in diagnostic_tokens)


def _investigation_heading_for_query(*, prompt: str, root_cause: dict[str, Any]) -> str:
    text = (prompt or "").strip().lower()
    diagnostic_tokens = (
        "why",
        "caused",
        "cause",
        "slow",
        "blocking",
        "lock contention",
        "cpu high",
        "memory high",
        "ora-",
        "error",
        "failed",
        "failure",
    )
    inventory_tokens = (
        "size of the database",
        "database size",
        "list tablespaces",
        "show active sessions",
        "what parameters",
        "which tables exist",
        "show grants",
        "invalid objects",
        "list invalid objects",
        "which tables are prone to blocking locks",
        "prone to blocking locks",
    )
    category = str(root_cause.get("category") or "")
    if "prone to blocking locks" in text or "tables are prone to blocking" in text:
        if category == "blocking_lock":
            return "## 🔴 Root Cause Analysis"
        return "## 🔵 Investigation Conclusion"
    if any(token in text for token in diagnostic_tokens):
        return "## 🔴 Root Cause Analysis"
    if any(token in text for token in inventory_tokens):
        return "## 🔵 Investigation Conclusion"
    if any(token in text for token in ("list ", "show ", "what is ", "which ")):
        return "## 🔵 Investigation Conclusion"
    return "## 🔴 Root Cause Analysis"


def _sanitize_error_message(message: str) -> str:
    text = message or ""
    key_value_patterns = [
        r"(?i)(password\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(pass\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(token\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(secret\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(wallet[_\s-]*password\s*[:=]\s*)([^,\s;]+)",
    ]
    for pattern in key_value_patterns:
        text = re.sub(pattern, r"\1***REDACTED***", text)
    text = re.sub(r"(?i)([A-Za-z0-9_.-]+)/([^@\s/]+)@", r"\1/***REDACTED***@", text)
    text = re.sub(r"(?i)(//[^:/@\s]+:)([^@\s]+)@", r"\1***REDACTED***@", text)
    return text


def _render_blocking_report(*, active_rows: list[dict[str, Any]], blocking_rows: list[dict[str, Any]], resource_rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Blocking Lock Analysis",
        "",
        f"- Active sessions: {len(active_rows)}",
        f"- Blocking chain rows: {len(blocking_rows)}",
        f"- High-resource session candidates: {len(resource_rows)}",
        "",
        "## Blocking Chains",
        _render_rows_table(blocking_rows[:20]) if blocking_rows else "No blocking chains were found.",
        "",
        "## Active Sessions Snapshot",
        _render_rows_table(active_rows[:20]) if active_rows else "No active user sessions were found.",
        "",
        "## Top Session Resource Candidates",
        _render_rows_table(resource_rows[:20]) if resource_rows else "No high-resource session candidates were found.",
    ]
    return "\n".join(lines)


def _render_rows_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""
    keys: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key, value in row.items():
            if key not in keys and value not in (None, "", []):
                keys.append(key)
            if len(keys) >= 8:
                break
        if len(keys) >= 8:
            break
    specs = [{"header": key, "width": 18, "key": key} for key in keys]
    return "```text\n" + format_dba_table(rows, specs) + "\n```"


def _write_rendered_export(*, rendered_report: str, db_key: str, prefix: str) -> str:
    safe_prefix = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(prefix or "report")).strip("_") or "report"
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = get_exports_dir(db_key=db_key) / f"{safe_prefix}_{stamp}.md"
    path.write_text(str(rendered_report or ""), encoding="utf-8")
    return str(path)
