from __future__ import annotations

import ast
import html
import textwrap
from typing import Any

from odb_autodba.agents.root_cause_engine import rank_root_causes
from odb_autodba.models.schemas import HealthSnapshot, HistoryContext, InvestigationReport, PlannerResponse, RemediationProposal, RemediationRecord, RemediationReview, SqlIdDeepDive
from odb_autodba.utils.severity import severity_icon, severity_rank


STATUS_BADGES = {
    "OK": "🟢 OK",
    "WARNING": "🟠 WARNING",
    "CRITICAL": "🔴 CRITICAL",
    "INFO": "🔵 INFO",
}

STATUS_ICONS = {
    "OK": "🟢",
    "WARNING": "🟠",
    "CRITICAL": "🔴",
    "INFO": "🔵",
}

SECTION_COLUMNS = {
    "Database Status": ["db_name", "open_mode", "database_role", "log_mode", "instance_name", "instance_status"],
    "Alert Log Errors": ["source", "window_hours", "filter", "rows_found", "status", "ts", "severity", "code", "message"],
    "Tablespace Usage": ["tablespace_name", "used_pct", "used_mb", "free_mb", "total_mb"],
    "Temp Usage": ["sid", "serial_num", "username", "program", "module", "sql_id", "gb_used"],
    "Locks And Blocking": ["waiter_sid", "waiter_user", "waiter_sql_id", "seconds_in_wait", "blocker_sid", "blocker_user", "blocker_sql_id", "blocker_program"],
    "Objects And Validity": ["owner", "object_name", "object_type"],
    "Redo And Archiving": ["redo_switches", "redo_per_hour", "log_mode", "archive_dest"],
    "Backup And Recovery": ["session_key", "input_type", "status", "completed"],
    "Scheduler Jobs": ["owner", "job_name", "status", "error", "started"],
    "Performance Overview": ["sql_id", "plan_hash_value", "executions", "elapsed_s", "cpu_s", "ela_per_exec_s", "buffer_gets", "disk_reads"],
    "Current Wait Profile": ["event", "wait_class", "time_waited_s", "total_waits", "avg_wait_ms"],
    "AWR Wait Events": ["event_name", "ms_per_occ"],
    "Cache Ratios": ["buffer_hit_pct", "library_hit_pct", "dictionary_hit_pct"],
    "Transactions And Undo": ["sid", "serial_num", "username", "minutes", "sql_id", "tablespace_name", "used_pct"],
    "Memory And Configuration": ["sid", "serial_num", "username", "sql_id", "spid", "pga_used_mb", "pga_alloc_mb", "temp_used_mb", "module", "program", "machine"],
    "Init Parameters": ["name", "value"],
    "CPU Hotspots": [
        "row_type",
        "os_pid",
        "spid",
        "process_group",
        "cpu_pct",
        "memory_pct",
        "rss_mb",
        "inst_id",
        "sid",
        "serial_num",
        "username",
        "sql_id",
        "parsing_schema_name",
        "module",
        "program",
        "event",
        "wait_class",
        "status",
        "sql_classification",
        "workload_interpretation",
        "source_metric",
        "source",
        "pga_used_mb",
        "pga_alloc_mb",
    ],
    "Memory Hotspots": [
        "row_type",
        "os_pid",
        "spid",
        "process_group",
        "memory_pct",
        "rss_mb",
        "swap_mb",
        "inst_id",
        "sid",
        "serial_num",
        "username",
        "sql_id",
        "parsing_schema_name",
        "module",
        "program",
        "event",
        "wait_class",
        "status",
        "sql_classification",
        "workload_interpretation",
        "source_metric",
        "source",
        "pga_used_mb",
        "pga_alloc_mb",
        "temp_used_mb",
    ],
}

SECTION_COMPACT_COLUMNS = {
    "Tablespace Usage": ["tablespace_name", "used_pct", "used", "free", "total"],
    "Temp Usage": ["sid", "username", "sql_id", "segtype", "temp_used", "tablespace"],
    "Memory And Configuration": ["sid", "serial_num", "username", "sql_id", "pga_used", "pga_alloc", "temp_used", "module", "program"],
    "CPU Hotspots": ["row_type", "os_pid", "process_group", "cpu_pct", "memory_pct", "sid", "username", "sql_id", "module", "program", "source"],
    "Memory Hotspots": ["row_type", "os_pid", "process_group", "memory_pct", "rss", "sid", "username", "sql_id", "pga_used", "pga_alloc", "temp_used", "module", "program", "source"],
}

NARRATIVE_SECTION_NAMES = {
    "Alert Log Errors",
}

FRIENDLY_LABEL_MAP = {
    "state_persisted_but_worsened_flag": "State persisted but worsened",
    "sql_amplified_by_blocking_flag": "SQL amplified by blocking",
    "transition_confidence_reason": "Transition confidence reason",
    "persistent_issue_with_higher_impact_flag": "Persistent issue with higher impact",
    "previous_dominant_wait_class": "Previous dominant wait class",
    "current_dominant_wait_class": "Current dominant wait class",
    "previous_top_event": "Previous top event",
    "current_top_event": "Current top event",
    "wait_class_shift_flag": "Shift detected",
    "cpu_to_io_shift": "CPU to I/O shift",
    "cpu_to_concurrency_shift": "CPU to concurrency shift",
    "dominant_sql_id_previous": "Previous dominant SQL_ID",
    "dominant_sql_id_current": "Current dominant SQL_ID",
    "dominant_sql_schema_previous": "Previous dominant SQL schema",
    "dominant_sql_schema_current": "Current dominant SQL schema",
    "dominant_sql_module_previous": "Previous dominant SQL module",
    "dominant_sql_module_current": "Current dominant SQL module",
    "dominant_sql_class_previous": "Previous dominant SQL class",
    "dominant_sql_class_current": "Current dominant SQL class",
    "sql_regression_flag": "SQL regression detected",
    "sql_regression_severity": "SQL regression severity",
    "plan_hash_changed_flag": "Plan hash changed",
    "elapsed_per_exec_spike": "Elapsed per exec spike",
    "cpu_per_exec_spike": "CPU per exec spike",
}

INTERPRETIVE_NOTE_HINTS = (
    "likely",
    "indicating",
    "suggesting",
    "suggests",
    "implies",
    "pressure",
    "contention",
    "instability",
    "anomaly",
    "contradiction",
    "despite",
    "no active blocker",
    "lock-related waits",
    "allocation failure",
    "overall tablespace usage is low",
    "root cause",
)

FACTUAL_NOTE_HINTS = (
    "source view",
    "fallback view",
    "fallback query",
    "collector",
    "collection",
    "sampled",
    "snapshot",
    "source used",
    "rows captured",
    "window",
)


def _heading_icon(status: str | None = None, *, informational: bool = False) -> str:
    normalized = (status or "").upper()
    if normalized in STATUS_ICONS:
        return STATUS_ICONS[normalized]
    return "🔵" if informational else "🟢"


def _section_heading(title: str, *, level: int = 2, status: str | None = None, informational: bool = False) -> str:
    hashes = "#" * max(level, 1)
    return f"{hashes} {_heading_icon(status, informational=informational)} {title}"


def _status_rank(status: str) -> int:
    normalized = (status or "INFO").upper()
    if normalized == "INFO":
        return 0
    if normalized in {"OK", "WARNING", "CRITICAL"}:
        return severity_rank(normalized)
    return 0


def _worst_status(statuses: list[str], *, default: str = "OK") -> str:
    clean = [str(status or "INFO").upper() for status in statuses if status]
    return max(clean or [default], key=_status_rank)


def _overall_snapshot_status(snapshot: HealthSnapshot) -> str:
    statuses = [issue.severity for issue in snapshot.issues]
    statuses.extend(item.severity for item in snapshot.actionable_items)
    statuses.extend(str(section.status) for section in snapshot.health_sections if str(section.status) != "INFO")
    return _worst_status(statuses)


def _findings_status(snapshot: HealthSnapshot) -> str:
    return _worst_status([item.severity for item in snapshot.actionable_items], default="OK")


def _sanitize_fixed_cell(value: Any, width: int) -> str:
    text = _format_value(value, max_length=max(width, 8))
    if len(text) > width:
        return f"{text[: max(width - 1, 1)]}…"
    return text


def format_dba_table(rows: list[dict[str, Any]], columns: list[dict[str, Any]]) -> str:
    if not rows:
        return "None"
    widths = [int(column.get("width", 12)) for column in columns]
    headers = [str(column.get("header") or column.get("key") or "") for column in columns]
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        "  ".join("-" * widths[index] for index in range(len(widths))),
    ]
    for row in rows:
        parts = []
        for index, column in enumerate(columns):
            key = column.get("key") or column.get("header")
            getter = column.get("getter")
            value = getter(row) if callable(getter) else row.get(key)
            parts.append(_sanitize_fixed_cell(value, widths[index]).ljust(widths[index]))
        lines.append("  ".join(parts).rstrip())
    return "\n".join(lines)


def _render_scroll_pre(text: str) -> str:
    escaped = html.escape(text or "None")
    return f'<div style="overflow-x:auto;"><pre>{escaped}</pre></div>'


def _render_dba_code_table(rows: list[dict[str, Any]], columns: list[dict[str, Any]]) -> str:
    return _render_scroll_pre(format_dba_table(rows, columns))


def _render_markdown_kv_table(rows: list[tuple[str, Any]]) -> str:
    return _render_dba_code_table(
        [{"metric": label, "value": value} for label, value in rows],
        [
            {"header": "metric", "width": 28, "key": "metric"},
            {"header": "value", "width": 70, "key": "value"},
        ],
    )


def _render_horizontal_kv_block(rows: list[tuple[str, Any]], *, columns: int = 2) -> list[str]:
    formatted = [(str(label), _format_value(value, max_length=80)) for label, value in rows]
    if not formatted:
        return [_render_scroll_pre("None")]
    effective_columns = max(1, columns)
    label_widths = [0] * effective_columns
    value_widths = [0] * effective_columns
    for index, (label, value) in enumerate(formatted):
        column_index = index % effective_columns
        label_widths[column_index] = max(label_widths[column_index], len(label))
        value_widths[column_index] = max(value_widths[column_index], len(value))
    lines: list[str] = []
    for index in range(0, len(formatted), effective_columns):
        chunk = formatted[index : index + effective_columns]
        parts = []
        for offset, (label, value) in enumerate(chunk):
            parts.append(f"{label:<{label_widths[offset]}} : {value:<{value_widths[offset]}}")
        lines.append("   ".join(parts).rstrip())
    return [_render_scroll_pre("\n".join(lines))]


def friendly_label(key: str) -> str:
    text = str(key or "").strip()
    if not text:
        return "Value"
    if text in FRIENDLY_LABEL_MAP:
        return FRIENDLY_LABEL_MAP[text]
    normalized = text.replace("%", " pct ").replace("/", " ").replace("-", " ").replace("_", " ")
    words = [word for word in normalized.split() if word]
    output: list[str] = []
    for word in words:
        upper = word.upper()
        if upper in {"SQL", "SQLID", "ID", "AWR", "CPU", "IO", "PGA", "SGA", "TX", "SID", "OS"}:
            output.append(upper if upper != "SQLID" else "SQL_ID")
            continue
        if word.lower() == "pct":
            output.append("%")
            continue
        output.append(word.capitalize())
    return " ".join(output) if output else text


def _wrap_text(value: Any, *, width: int = 100) -> list[str]:
    text = _format_value(value, max_length=1200)
    if text in {"", "-"}:
        return ["-"]
    wrapped = textwrap.wrap(text, width=width, break_long_words=False, break_on_hyphens=False)
    return wrapped or [text]


def format_storage_value(value_mb: Any, *, source_unit: str = "mb") -> str:
    number = _to_float(value_mb)
    if number is None:
        return _format_value(value_mb)
    unit = str(source_unit or "mb").strip().lower()
    if unit == "kb":
        number = number / 1024.0
    elif unit == "bytes":
        number = number / (1024.0 * 1024.0)
    abs_number = abs(number)
    if abs_number >= 1024.0 * 1024.0:
        return f"{number / (1024.0 * 1024.0):.2f} TB"
    if abs_number >= 1024.0:
        return f"{number / 1024.0:.2f} GB"
    return f"{number:.2f} MB"


def format_storage_triplet(*, used_mb: Any, free_mb: Any, total_mb: Any) -> str:
    return (
        f"{format_storage_value(used_mb)} used / "
        f"{format_storage_value(free_mb)} free / "
        f"{format_storage_value(total_mb)} total"
    )


def _format_pct(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return _format_value(value)
    return f"{number:.2f}%"


def render_key_value_block(rows: list[tuple[str, Any]]) -> str:
    if not rows:
        return "- None"
    lines: list[str] = []
    for label, value in rows:
        wrapped = _wrap_text(value)
        lines.append(f"- {label}: {wrapped[0]}")
        for continuation in wrapped[1:]:
            lines.append(f"  {continuation}")
    return "\n".join(lines)


def render_bullet_group(items: list[str]) -> str:
    if not items:
        return "- None"
    lines: list[str] = []
    for item in items:
        wrapped = _wrap_text(item)
        lines.append(f"- {wrapped[0]}")
        for continuation in wrapped[1:]:
            lines.append(f"  {continuation}")
    return "\n".join(lines)


def choose_section_render_mode(section_name: str, rows: list[dict[str, Any]]) -> str:
    if section_name in {"Host And OS"}:
        return "key_value"
    if section_name in NARRATIVE_SECTION_NAMES:
        if _rows_have_long_text(rows):
            return "bullets"
        return "table_compact"
    if section_name in {
        "Tablespace Usage",
        "Temp Usage",
        "Locks And Blocking",
        "Current Wait Profile",
        "AWR Wait Events",
        "CPU Hotspots",
        "Memory Hotspots",
        "Memory And Configuration",
        "Transactions And Undo",
        "Performance Overview",
    }:
        return "table_compact"
    if section_name in {"Database Status", "Init Parameters", "Scheduler Jobs", "Redo And Archiving", "Backup And Recovery"}:
        return "table_numeric"
    if not rows:
        return "note"
    if _rows_have_long_text(rows):
        return "bullets"
    numeric_ratio = _numeric_value_ratio(rows)
    if len(rows) == 1 and numeric_ratio < 0.4:
        return "key_value"
    return "table_compact" if numeric_ratio >= 0.45 else "bullets"


def _numeric_value_ratio(rows: list[dict[str, Any]]) -> float:
    total = 0
    numeric = 0
    for row in rows[:20]:
        for value in row.values():
            if not _has_value(value):
                continue
            total += 1
            if isinstance(value, (int, float, bool)):
                numeric += 1
                continue
            if _to_float(value) is not None:
                numeric += 1
    if total == 0:
        return 0.0
    return float(numeric) / float(total)


def _rows_have_long_text(rows: list[dict[str, Any]], *, threshold: int = 90) -> bool:
    for row in rows[:20]:
        for value in row.values():
            if not _has_value(value):
                continue
            if isinstance(value, str) and len(value) > threshold:
                return True
    return False


def render_planner_response(response: PlannerResponse) -> str:
    return response.body_markdown


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


def render_history_answer(answer: dict[str, Any]) -> str:
    context: HistoryContext | None = answer.get("context")
    series = answer.get("series") or []
    summary_lines = answer.get("summary_lines") or []
    domain = answer.get("domain")
    time_scope = answer.get("time_scope") or {}
    transition = answer.get("state_transition") or (context.state_transition if context else None)
    awr_state_diff = answer.get("awr_state_diff") or (transition.awr_state_diff if transition else None)
    history_source = answer.get("history_source_summary") or answer.get("history_source_note") or (
        f"History source: {answer.get('history_source_used') or (context.history_source_used if context else 'raw JSONL only')}."
    )
    awr_source_summary = answer.get("awr_source_summary") or (transition.awr_source_summary if transition else None)
    fallback_summary = answer.get("fallback_summary") or (transition.fallback_summary if transition else None)
    transition_data = _history_mapping(transition)
    awr_data = _history_mapping(awr_state_diff)
    learning_data = _history_mapping(answer.get("learning_features") or (transition.learning_features if transition else None))
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

    lines.extend(["", _section_heading("AWR Workload Changes", informational=True), ""])
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
    if workload_metric_rows:
        awr_rows = []
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
    else:
        fallback_reason = fallback_info.get("awr_user_message") or historical_confidence.get("fallback_reason") or "AWR workload comparison unavailable; JSONL fallback used."
        lines.append(f"AWR workload comparison fallback: {fallback_reason}")

    lines.extend(["", _section_heading("Wait Class Shift", informational=True), ""])
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
            lines.append("AWR wait-class shift details were unavailable for the mapped comparison window.")
        else:
            lines.append(_render_table(wait_summary_rows, list(wait_summary_rows[0].keys())))
    else:
        lines.append("Wait-class shift evidence unavailable.")

    lines.extend(["", _section_heading("SQL Change Summary", informational=True), ""])
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
            lines.append("AWR SQL-change details were unavailable for the mapped comparison window.")
        else:
            lines.append(_render_table(sql_summary_rows, list(sql_summary_rows[0].keys())))
    else:
        lines.append("AWR SQL-change intelligence unavailable; SQL regression inferred from JSONL metric deltas when possible.")

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
    coverage_notes = transition_data.get("coverage_notes") if isinstance(transition_data.get("coverage_notes"), list) else []
    snapshot_mapping_summary = transition_data.get("snapshot_mapping_summary")
    window_mapping = _history_mapping(awr_data.get("window_mapping"))
    previous_window = _history_mapping(window_mapping.get("previous"))
    current_window = _history_mapping(window_mapping.get("current"))
    if historical_confidence:
        history_source_note = str(transition_data.get("history_source_summary") or historical_confidence.get("history_source_used") or "-")
        awr_source_note = str(transition_data.get("awr_source_summary") or "-")
        history_source_note = _strip_prefixed_label(history_source_note, "History source")
        awr_source_note = _strip_prefixed_label(awr_source_note, "AWR source")
        lines.append(f"- Confidence: {historical_confidence.get('confidence_level') or 'LOW'}")
        lines.append(f"- Coverage: {historical_confidence.get('coverage_quality') or 'LOW'}")
        lines.append(f"- History source: {history_source_note}")
        lines.append(f"- AWR source: {awr_source_note}")
        confidence_reason = str(historical_confidence.get("confidence_reason") or "").strip()
        fallback_reason = str(historical_confidence.get("fallback_reason") or "").strip()
        if confidence_reason:
            lines.append(f"- Confidence reason: {confidence_reason}")
        elif fallback_reason:
            lines.append(f"- Fallback: {fallback_reason}")
    else:
        snapshot_quality = _history_mapping(awr_data.get("snapshot_quality"))
        if snapshot_quality:
            lines.append(
                "- "
                + (
                    f"AWR coverage={snapshot_quality.get('coverage_quality')}, "
                    f"comparability={snapshot_quality.get('comparability_score')}, "
                    f"confidence={snapshot_quality.get('confidence')}."
                )
            )
    if previous_window.get("begin_snap_id") is not None:
        lines.append(f"- Previous window: SNAP {previous_window.get('begin_snap_id')}..{previous_window.get('end_snap_id')}")
    if current_window.get("begin_snap_id") is not None:
        lines.append(f"- Current window: SNAP {current_window.get('begin_snap_id')}..{current_window.get('end_snap_id')}")
    if snapshot_mapping_summary and previous_window.get("begin_snap_id") is None and current_window.get("begin_snap_id") is None:
        lines.append(f"- Snapshot mapping: {snapshot_mapping_summary}")
    if coverage_notes:
        deduped = _dedupe_strings(coverage_notes)
        lines.extend(f"- {note}" for note in deduped[:1])

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


def _render_execution_plan_block(lines: list[Any]) -> str:
    if not lines:
        return "No execution plan lines were captured."
    text = "\n".join(str(line) for line in lines[:500])
    return f"```text\n{text}\n```"


def _render_sql_metric_table(payload: Any, *, default_text: str) -> str:
    mapping = _deep_dive_mapping(payload)
    if not mapping:
        return default_text
    rows = [{"metric": key, "value": value} for key, value in mapping.items()]
    return _render_dba_code_table(
        rows,
        [
            {"header": "metric", "width": 34, "key": "metric"},
            {"header": "value", "width": 78, "key": "value"},
        ],
    )


def _render_sql_rows(rows: list[dict[str, Any]], *, default_text: str) -> str:
    if not rows:
        return default_text
    return _render_table(rows, _infer_columns(rows, limit=8))


def _deep_dive_mapping(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    if hasattr(payload, "model_dump"):
        try:
            out = payload.model_dump(mode="json")
            return out if isinstance(out, dict) else {}
        except Exception:
            return {}
    return {}


def _history_mapping(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    if hasattr(payload, "model_dump"):
        try:
            dumped = payload.model_dump(mode="json")
            return dumped if isinstance(dumped, dict) else {}
        except Exception:
            return {}
    return {}


def _primary_driver_title_for_outcome(outcome: str) -> str:
    if outcome in {"recovered", "improved", "persisted_but_improved"}:
        return "Recovery Drivers"
    if outcome in {"worsened", "persisted_but_worsened"}:
        return "Incident Drivers"
    return "Persistent Drivers"


def _secondary_driver_title_for_outcome(outcome: str) -> str:
    if outcome in {"recovered", "improved", "persisted_but_improved"}:
        return "Residual Warning Drivers"
    if outcome in {"worsened", "persisted_but_worsened"}:
        return "Persistent Background Risks"
    return "Worsening Signals"


def _primary_driver_empty_text(title: str) -> str:
    if "Recovery" in title:
        return "No material recovery drivers identified."
    if "Incident" in title or "Risk" in title:
        return "No material incident drivers identified."
    return "No material persistent drivers identified."


def _secondary_driver_empty_text(title: str) -> str:
    if "Residual" in title:
        return "No residual warning drivers identified."
    if "Risk" in title:
        return "No persistent background risks identified."
    return "No worsening signals identified."


def _format_metric_number(value: Any) -> str:
    if value is None or value == "":
        return "-"
    try:
        number = float(value)
    except Exception:
        return str(value)
    if abs(number) >= 1000:
        return f"{number:,.1f}"
    if abs(number) >= 100:
        return f"{number:.1f}"
    return f"{number:.2f}"


def _format_signed_metric_number(value: Any) -> str:
    if value is None or value == "":
        return "-"
    try:
        number = float(value)
    except Exception:
        return str(value)
    if number > 0:
        return f"+{_format_metric_number(number)}"
    return _format_metric_number(number)


def _format_percent_delta(value: Any) -> str:
    if value is None or value == "":
        return "-"
    try:
        number = float(value)
    except Exception:
        return str(value)
    sign = "+" if number > 0 else ""
    return f"{sign}{number:.2f}%"


def _module_program(module: Any, program: Any) -> str:
    module_text = _format_value(module, max_length=60)
    program_text = _format_value(program, max_length=60)
    if module_text == "-" and program_text == "-":
        return "-"
    if module_text == "-":
        return program_text
    if program_text == "-":
        return module_text
    return f"{module_text} / {program_text}"


def _format_bool(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y"}:
        return "Yes"
    if text in {"0", "false", "no", "n"}:
        return "No"
    return _format_value(value)


def _has_meaningful_awr_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        text = value.strip()
        return bool(text and text != "-")
    return True


def should_collapse_unavailable_awr_table(rows: list[dict[str, Any]], required_fields: list[str]) -> bool:
    if not rows:
        return True
    return all(all(not _has_meaningful_awr_value(row.get(field)) for field in required_fields) for row in rows)


def render_compact_awr_unavailable_note(title: str, rows: list[dict[str, Any]], *, metric_key: str | None = None) -> str:
    metric_names: list[str] = []
    if metric_key:
        for row in rows[:6]:
            metric = str(row.get(metric_key) or "").strip()
            if metric:
                metric_names.append(metric)
    representative = ", ".join(metric_names[:3])
    suffix = f" Representative metrics: {representative}." if representative else ""
    return f"{title}{suffix}"


def _strip_prefixed_label(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    prefix = f"{label}:"
    if text.lower().startswith(prefix.lower()):
        return text[len(prefix) :].strip()
    return text


def _dedupe_strings(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _render_executive_summary(snapshot: HealthSnapshot) -> str:
    rows = []
    if snapshot.health_sections:
        for section in snapshot.health_sections:
            rows.append(
                {
                    "Check": section.name,
                    "Status": _status_badge(str(section.status)),
                    "Summary": section.summary,
                }
            )
    else:
        rows = [
            {"Check": "Active Sessions", "Status": _status_badge("INFO"), "Summary": f"{snapshot.session_summary.active_sessions} active session(s)."},
            {"Check": "Blocking Chains", "Status": _status_badge("CRITICAL" if snapshot.blocking_chains else "OK"), "Summary": f"{len(snapshot.blocking_chains)} blocking chain(s)."},
            {"Check": "Tablespace Usage", "Status": _status_badge("INFO"), "Summary": _highest_tablespace(snapshot)},
        ]
    return _render_table(rows, ["Check", "Status", "Summary"])


def _render_key_signals(snapshot: HealthSnapshot) -> str:
    critical_count = sum(1 for item in snapshot.actionable_items if item.severity == "CRITICAL")
    warning_count = sum(1 for item in snapshot.actionable_items if item.severity == "WARNING")
    return "\n".join(
        _render_horizontal_kv_block(
            [
                ("Active sessions", snapshot.session_summary.active_sessions),
                ("Blocking chains", len(snapshot.blocking_chains)),
                ("ORA/TNS rows", len(snapshot.raw_evidence.get("alert_log") or [])),
                ("Highest tablespace", _highest_tablespace(snapshot)),
                ("Actionable findings", f"{len(snapshot.actionable_items)} ({critical_count} critical, {warning_count} warning)"),
                ("Host checks", "Included" if snapshot.host_snapshot else "Disabled"),
            ],
            columns=2,
        )
    )


def _render_actionable_items(snapshot: HealthSnapshot) -> str:
    if not snapshot.actionable_items:
        return f"{_status_badge('OK')} No critical or warning action items were generated by the rules."
    sorted_items = sorted(snapshot.actionable_items, key=lambda item: 0 if item.severity == "CRITICAL" else 1)
    summary_rows = [
        {
            "Status": _status_badge(item.severity),
            "Finding": item.title,
            "Detail": item.detail,
            "Recommended Next Step": item.recommendation,
        }
        for item in sorted_items
    ]
    return _render_table(summary_rows, ["Status", "Finding", "Detail", "Recommended Next Step"])


def _render_likely_causes(snapshot: HealthSnapshot) -> str:
    causes = rank_root_causes(snapshot) or ["No dominant root cause identified from the current evidence."]
    return render_bullet_group([str(cause) for cause in causes])


def _render_issue_evidence(snapshot: HealthSnapshot) -> str:
    if not snapshot.issues:
        return f"{_status_badge('OK')} No issues generated from the current evidence."
    rows = [
        {
            "Status": _status_badge(issue.severity),
            "Issue": issue.title,
            "Evidence": issue.description,
            "Recommendation": issue.recommendation,
        }
        for issue in snapshot.issues[:12]
    ]
    return _render_table(rows, ["Status", "Issue", "Evidence", "Recommendation"])


def _render_supporting_evidence(snapshot: HealthSnapshot) -> str:
    blocks: list[str] = []
    if snapshot.issues:
        issue_block = _render_issue_evidence(snapshot)
        if issue_block:
            blocks.append(issue_block)

    sorted_items = sorted(snapshot.actionable_items, key=lambda item: 0 if item.severity == "CRITICAL" else 1)
    evidence_blocks: list[str] = []
    for item in sorted_items:
        evidence_rows = [_coerce_mapping(row) for row in item.evidence[:5]]
        evidence_rows = [row for row in evidence_rows if row]
        if not evidence_rows and not item.evidence:
            continue
        block = [
            f"### Evidence: {item.title}",
            "",
            f"**Status:** {_status_badge(item.severity)}",
        ]
        if evidence_rows:
            block.extend(["", _render_compact_evidence(evidence_rows)])
        else:
            block.extend([""])
            block.extend(f"- {_format_value(row)}" for row in item.evidence[:5])
        evidence_blocks.append("\n".join(block))
    if evidence_blocks:
        blocks.append("#### Finding Evidence\n\n" + "\n\n".join(evidence_blocks))

    if not blocks:
        return f"{_status_badge('OK')} No supporting evidence rows were captured."
    return "\n\n".join(blocks)


def _partition_section_notes(section_name: str, notes: list[str]) -> tuple[list[str], list[str]]:
    inline_notes: list[str] = []
    moved_interpretive: list[str] = []
    for raw_note in notes or []:
        note = str(raw_note or "").strip()
        if not note:
            continue
        if _is_interpretive_note(note):
            moved_interpretive.append(note)
            continue
        if _is_factual_collection_note(note) or len(note) <= 140:
            inline_notes.append(note)
            continue
        moved_interpretive.append(note)
    return _dedupe_text_lines(inline_notes), _dedupe_text_lines(moved_interpretive)


def _is_interpretive_note(note: str) -> bool:
    text = str(note or "").strip().lower()
    if not text:
        return False
    return any(hint in text for hint in INTERPRETIVE_NOTE_HINTS)


def _is_factual_collection_note(note: str) -> bool:
    text = str(note or "").strip().lower()
    if not text:
        return False
    return any(hint in text for hint in FACTUAL_NOTE_HINTS)


def _dedupe_text_lines(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for line in lines:
        normalized = " ".join(str(line or "").lower().split())
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(str(line).strip())
    return output


def _remove_overlapping_lines(candidates: list[str], references: list[str]) -> list[str]:
    if not references:
        return candidates
    normalized_references = {" ".join(str(item or "").lower().split()) for item in references if str(item or "").strip()}
    output: list[str] = []
    for candidate in candidates:
        normalized = " ".join(str(candidate or "").lower().split())
        if not normalized:
            continue
        if normalized in normalized_references:
            continue
        output.append(candidate)
    return output


def _remove_redundant_lines(candidates: list[str], references: list[str]) -> list[str]:
    if not references:
        return candidates
    normalized_references = [" ".join(str(item or "").lower().split()) for item in references if str(item or "").strip()]
    output: list[str] = []
    for candidate in candidates:
        normalized = " ".join(str(candidate or "").lower().split())
        if not normalized:
            continue
        if any(normalized in ref or ref in normalized for ref in normalized_references):
            continue
        output.append(candidate)
    return output


def _render_ai_investigation_summary(snapshot: HealthSnapshot, moved_interpretive_notes: list[str]) -> str:
    causes = (rank_root_causes(snapshot) or ["No dominant root cause identified from the current evidence."])[:4]
    summary_points = _dedupe_text_lines(_ai_summary_points(snapshot))
    summary_points = _remove_overlapping_lines(summary_points, causes)
    summary_points = summary_points[:3]
    cross_signal = _dedupe_text_lines(_cross_signal_interpretations(snapshot, moved_interpretive_notes))
    cross_signal = _remove_overlapping_lines(cross_signal, causes + summary_points)
    cross_signal = _remove_redundant_lines(cross_signal, causes + summary_points)
    cross_signal = cross_signal[:3]
    recommendations = _dedupe_text_lines(_recommended_follow_up(snapshot))[:4]

    blocks: list[str] = [
        "### Deterministic vs AI Boundary",
        "",
        "- Deterministic sections above contain observed evidence and collected metrics.",
        "- AI interpretation below consolidates inferred relationships and contradiction resolution.",
        "",
        "### Summary",
        "",
        render_bullet_group(summary_points or ["Current evidence was stable and did not produce a strong AI interpretation."]),
        "",
        "### Likely Causes",
        "",
        render_bullet_group(causes),
    ]
    if cross_signal:
        blocks.extend(["", "### Cross-signal Interpretation", "", render_bullet_group(cross_signal)])
    blocks.extend(
        [
            "",
            "### Recommended Follow-up",
            "",
            render_bullet_group(recommendations or ["Continue periodic health checks and review changes in Top SQL and alert-log trends."]),
        ]
    )
    return "\n".join(blocks)


def _ai_summary_points(snapshot: HealthSnapshot) -> list[str]:
    points: list[str] = []
    overall = _overall_snapshot_status(snapshot)
    points.append(f"Current state is {overall.lower()}.")

    anomaly = snapshot.raw_evidence.get("tablespace_allocation_anomaly") or {}
    if isinstance(anomaly, dict) and anomaly.get("tablespace_allocation_failure_with_low_pct"):
        ts_name = anomaly.get("tablespace_name") or _highest_tablespace_name(snapshot) or "the affected tablespace"
        points.append(
            f"ORA-01653 allocation failures remain a storage anomaly on {ts_name} despite low overall usage percentage."
        )

    blocking = snapshot.raw_evidence.get("blocking_interpretation") or {}
    if isinstance(blocking, dict) and blocking.get("lock_wait_observed") and not blocking.get("active_blocker_present"):
        points.append(
            "Lock-related waits were observed, but no active blocker existed at collection time, indicating transient contention."
        )

    top_cpu = snapshot.top_sql_by_cpu[:3]
    if top_cpu:
        labels: list[str] = []
        for row in top_cpu:
            classification = row.sql_classification or "unclassified"
            labels.append(f"{row.sql_id} ({classification})")
        points.append("Top CPU SQL contributors include " + ", ".join(labels) + ".")

    return points


def _cross_signal_interpretations(snapshot: HealthSnapshot, moved_interpretive_notes: list[str]) -> list[str]:
    notes = list(moved_interpretive_notes or [])
    host = snapshot.host_snapshot
    if host and host.cpu_hotspot.triggered:
        if (host.cpu_hotspot.container_cpu_pct or 0) >= 85 and (host.cpu_hotspot.host_cpu_pct or 0) < 70:
            notes.append(
                "Container CPU is critically high despite moderate host CPU, suggesting localized DB/container pressure rather than host-wide saturation."
            )
        if host.cpu_hotspot.correlation_confidence in {"low", "none"} and snapshot.top_sql_by_cpu:
            notes.append(
                "OS hotspot sampling was incomplete for Oracle process mapping, but DB-side Top SQL still indicates Oracle CPU pressure."
            )
    if snapshot.raw_evidence.get("alert_log"):
        notes.append("Recent ORA/TNS alert-log errors align with observed performance and stability findings.")
    return notes


def _recommended_follow_up(snapshot: HealthSnapshot) -> list[str]:
    actions: list[str] = []
    for item in snapshot.actionable_items:
        recommendation = str(item.recommendation or "").strip()
        if recommendation:
            actions.append(recommendation)

    anomaly = snapshot.raw_evidence.get("tablespace_allocation_anomaly") or {}
    if isinstance(anomaly, dict) and anomaly.get("tablespace_allocation_failure_with_low_pct"):
        ts_name = anomaly.get("tablespace_name") or _highest_tablespace_name(snapshot) or "affected tablespace"
        actions.append(
            f"Validate autoextend/maxsize, free extents, and quota for {ts_name} to address ORA-01653 allocation failures."
        )

    blocking = snapshot.raw_evidence.get("blocking_interpretation") or {}
    if isinstance(blocking, dict) and blocking.get("lock_wait_observed") and not blocking.get("active_blocker_present"):
        actions.append("Capture blocker chains during peak load windows to validate transient row-lock contention sources.")

    if snapshot.host_snapshot and snapshot.host_snapshot.cpu_hotspot.triggered:
        actions.append("During the next CPU spike, capture OS PID -> GV$SESSION mappings to improve hotspot correlation confidence.")

    return actions


def _highest_tablespace_name(snapshot: HealthSnapshot) -> str | None:
    if snapshot.tablespaces:
        top = snapshot.tablespaces[0]
        if top.tablespace_name:
            return str(top.tablespace_name)
    return None


def _render_top_cpu_sql(snapshot: HealthSnapshot) -> str:
    if not snapshot.top_sql_by_cpu:
        return "No top SQL by CPU rows were captured."
    rows = [
        {
            "SQL_ID": row.sql_id,
            "Schema/User": row.parsing_schema_name or row.username,
            "Module/Program": _module_program(row.module, row.program),
            "CPU(s)": row.cpu_s,
            "CPU/Exec(s)": row.cpu_per_exec_s,
            "Ela/Exec(s)": row.ela_per_exec_s,
            "Elapsed(s)": row.elapsed_s,
            "Execs": row.executions,
            "Class": row.sql_classification,
            "Workload": row.workload_interpretation,
        }
        for row in snapshot.top_sql_by_cpu[:5]
    ]
    return _render_top_sql_table(rows)


def _render_top_elapsed_sql(snapshot: HealthSnapshot) -> str:
    if not snapshot.top_sql_by_elapsed:
        return "No top SQL by elapsed time rows were captured."
    rows = [
        {
            "SQL_ID": row.sql_id,
            "Schema/User": row.parsing_schema_name or row.username,
            "Module/Program": _module_program(row.module, row.program),
            "Ela/Exec(s)": row.ela_per_exec_s,
            "CPU/Exec(s)": row.cpu_per_exec_s,
            "Elapsed(s)": row.elapsed_s,
            "CPU(s)": row.cpu_s,
            "Execs": row.executions,
            "Class": row.sql_classification,
            "Workload": row.workload_interpretation,
        }
        for row in snapshot.top_sql_by_elapsed[:5]
    ]
    return _render_top_sql_table(rows)


def _top_sql_overlap_note(snapshot: HealthSnapshot) -> str:
    cpu_ids = [row.sql_id for row in (snapshot.top_sql_by_cpu or [])[:5] if row.sql_id]
    elapsed_ids = [row.sql_id for row in (snapshot.top_sql_by_elapsed or [])[:5] if row.sql_id]
    if not cpu_ids or not elapsed_ids:
        return "Top SQL overlap note unavailable."
    overlap = sorted(set(cpu_ids) & set(elapsed_ids))
    if not overlap:
        return "Top elapsed and top CPU SQL sets do not overlap materially in this snapshot."
    overlap_ratio = len(overlap) / float(max(min(len(cpu_ids), len(elapsed_ids)), 1))
    if overlap_ratio >= 0.6:
        return f"Top elapsed and top CPU SQL sets largely overlap: {', '.join(overlap[:5])}."
    return f"Top elapsed and top CPU SQL sets partially overlap: {', '.join(overlap[:5])}."


def _render_top_sql_table(rows: list[dict[str, Any]]) -> str:
    return _render_dba_code_table(
        rows,
        [
            {"header": "sql_id", "width": 13, "key": "SQL_ID"},
            {"header": "schema_user", "width": 16, "key": "Schema/User"},
            {"header": "module_prog", "width": 36, "key": "Module/Program"},
            {"header": "elapsed_s", "width": 10, "key": "Elapsed(s)"},
            {"header": "ela_exec_s", "width": 10, "key": "Ela/Exec(s)"},
            {"header": "cpu_exec_s", "width": 10, "key": "CPU/Exec(s)"},
            {"header": "cpu_s", "width": 10, "key": "CPU(s)"},
            {"header": "execs", "width": 8, "key": "Execs"},
            {"header": "class", "width": 14, "key": "Class"},
            {"header": "workload", "width": 44, "key": "Workload"},
        ],
    )


def _render_health_section(section, *, notes_override: list[str] | None = None) -> list[str]:
    prepared_rows = _prepare_rows_for_section(section.name, section.rows[:12] if section.rows else [])
    section_notes = notes_override if notes_override is not None else section.notes
    lines = [
        _section_heading(section.name, level=3, status=str(section.status), informational=str(section.status) == "INFO"),
        "",
        f"**Status:** {_status_badge(str(section.status))}",
        "",
        section.summary or "Evidence captured.",
    ]
    if section_notes:
        lines.extend(["", "**Notes:**"])
        lines.extend(f"- {_format_value(note, max_length=800)}" for note in section_notes[:5])
    if prepared_rows:
        lines.extend(["", _render_section_rows(section.name, prepared_rows)])
    return lines + [""]


def _render_section_rows(section_name: str, rows: list[dict[str, Any]]) -> str:
    if section_name == "Host And OS":
        return _render_host_rows(rows)
    columns = SECTION_COLUMNS.get(section_name) or _infer_columns(rows)
    return _render_table(rows, columns)


def _render_host_rows(rows: list[dict[str, Any]]) -> str:
    host_rows = [row for row in rows if row.get("scope") in {"host", "oracle_container"}]
    hotspot_rows = [row for row in rows if row.get("scope") == "hotspot_analysis"]
    fs_rows = [row for row in rows if row.get("scope") == "filesystem"]
    parts = []
    if host_rows:
        parts.append(_render_table(host_rows, ["scope", "container", "cpu_pct", "memory_pct", "swap_pct", "memory_usage", "load_average"]))
    if hotspot_rows:
        parts.extend(
            [
                "",
                "**Hotspot Analysis:**",
                "",
                _render_table(
                    hotspot_rows,
                    [
                        "cpu_hotspot_triggered",
                        "memory_hotspot_triggered",
                        "cpu_hotspot_correlation_success",
                        "memory_hotspot_correlation_success",
                        "cpu_correlation_success",
                        "memory_correlation_success",
                        "cpu_correlation_confidence",
                        "memory_correlation_confidence",
                        "cpu_candidate_sql_ids",
                        "memory_candidate_sql_ids",
                        "top_oracle_fg_cpu",
                        "top_oracle_bg_cpu",
                        "top_non_oracle_cpu",
                        "top_oracle_fg_mem",
                        "top_oracle_bg_mem",
                        "top_non_oracle_mem",
                    ],
                ),
            ]
        )
    if fs_rows:
        parts.extend(["", "**Filesystems:**", "", _render_table(fs_rows, ["filesystem", "size", "used", "avail", "use_pct", "mount"])])
    return "\n".join(parts) if parts else _render_table(rows, _infer_columns(rows))


def _render_compact_evidence(rows: list[dict[str, Any]]) -> str:
    columns = _infer_columns(rows, limit=5)
    return _render_table(rows, columns)


def _prepare_rows_for_section(section_name: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = [dict(row) for row in rows]
    if section_name == "Tablespace Usage":
        for row in prepared:
            row["used_pct"] = _format_pct(row.get("used_pct"))
            row["used_mb"] = format_storage_value(row.get("used_mb"), source_unit="kb")
            row["free_mb"] = format_storage_value(row.get("free_mb"), source_unit="kb")
            row["total_mb"] = format_storage_value(row.get("total_mb"), source_unit="kb")
        return prepared
    if section_name == "Temp Usage":
        for row in prepared:
            mb_used = row.get("mb_used")
            gb_used = row.get("gb_used")
            if _has_value(mb_used):
                row["gb_used"] = format_storage_value(mb_used, source_unit="mb")
            elif _has_value(gb_used):
                row["gb_used"] = f"{_format_value(gb_used)} GB"
        return prepared
    if section_name == "Memory And Configuration":
        for row in prepared:
            row["pga_used_mb"] = format_storage_value(row.get("pga_used_mb"))
            row["pga_alloc_mb"] = format_storage_value(row.get("pga_alloc_mb"))
            if "temp_used_mb" in row:
                row["temp_used_mb"] = format_storage_value(row.get("temp_used_mb"))
        return prepared
    if section_name in {"CPU Hotspots", "Memory Hotspots"}:
        for row in prepared:
            if "rss_mb" in row:
                row["rss_mb"] = format_storage_value(row.get("rss_mb"))
            if "pga_used_mb" in row:
                row["pga_used_mb"] = format_storage_value(row.get("pga_used_mb"))
            if "pga_alloc_mb" in row:
                row["pga_alloc_mb"] = format_storage_value(row.get("pga_alloc_mb"))
            if "temp_used_mb" in row:
                row["temp_used_mb"] = format_storage_value(row.get("temp_used_mb"))
        return prepared
    return prepared


def _render_section_bullets(section_name: str, rows: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    if section_name == "Alert Log Errors":
        for row in rows[:12]:
            lines.append(
                f"{row.get('ts') or '-'} {row.get('severity') or 'INFO'} {row.get('code') or '-'}: {row.get('message') or '-'}"
            )
        return render_bullet_group(lines)
    for row in rows[:12]:
        kv_pairs = [f"{friendly_label(str(key))}: {_format_value(value, max_length=800)}" for key, value in row.items() if _has_value(value)]
        if not kv_pairs:
            continue
        lines.append("; ".join(kv_pairs[:6]))
    return render_bullet_group(lines)


def _render_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return ""
    useful_columns = [column for column in columns if any(_has_value(row.get(column)) for row in rows)]
    if not useful_columns:
        useful_columns = columns[:3]
    table_columns = [_text_column_spec(column, rows) for column in useful_columns]
    return _render_dba_code_table(rows, table_columns)


def _infer_columns(rows: list[dict[str, Any]], limit: int = 8) -> list[str]:
    columns: list[str] = []
    for row in rows:
        for key, value in row.items():
            if key not in columns and _has_value(value):
                columns.append(key)
            if len(columns) >= limit:
                return columns
    return columns or list(rows[0].keys())[:limit]


def _text_header(column: str) -> str:
    normalized = str(column).strip()
    replacements = {
        "SQL_ID": "sql_id",
        "CPU(s)": "cpu_s",
        "Elapsed(s)": "elapsed_s",
        "Recommended Next Step": "next_step",
        "Completed At": "completed_at",
    }
    if normalized in replacements:
        return replacements[normalized]
    normalized = normalized.replace("%", "pct")
    normalized = normalized.replace("(", "_").replace(")", "")
    normalized = normalized.replace("/", "_").replace("-", "_")
    normalized = normalized.replace(" ", "_")
    normalized = normalized.lower()
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized.strip("_") or "value"


def _text_column_spec(column: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    header = _text_header(column)
    values = [_format_value(row.get(column), max_length=200) for row in rows]
    max_value_width = max([len(header), *(len(value) for value in values)], default=len(header))
    wide_identifier_tokens = {"sql_id", "module", "program", "driver", "object_name", "object", "schema_user"}
    wide_narrative_headers = {
        "summary",
        "detail",
        "recommendation",
        "next_step",
        "trace",
        "message",
        "interpretation",
        "workload",
        "workload_interpretation",
        "follow_up",
    }
    if any(token in header for token in wide_identifier_tokens):
        width = min(max(max_value_width, 18), 100)
    elif header in wide_narrative_headers:
        width = min(max(max_value_width, 32), 100)
    elif header in {"finding", "issue", "check", "event", "archive_dest", "driver_name"}:
        width = min(max(max_value_width, 20), 80)
    elif header in {"status", "severity"}:
        width = min(max(max_value_width, 10), 14)
    elif header in {"completed_at", "generated_at", "last_analyzed", "completed"}:
        width = min(max(max_value_width, 19), 32)
    else:
        width = min(max(max_value_width, len(header), 8), 40)
    return {"header": header, "width": width, "key": column}


def _history_series_columns(rows: list[dict[str, Any]]) -> list[str]:
    preferred = [
        "completed_at",
        "overall_status",
        "host_cpu_pct",
        "host_memory_pct",
        "container_cpu_pct",
        "container_memory_pct",
        "active_sessions",
        "blocking_count",
        "alert_log_count",
        "hottest_tablespace_pct",
        "top_cpu_sql_cpu_s",
    ]
    selected = [key for key in preferred if any(_has_value(row.get(key)) for row in rows)]
    if len(selected) >= 8:
        return selected[:8]
    for row in rows:
        for key in row:
            if key == "trace_path":
                continue
            if key not in selected and _has_value(row.get(key)):
                selected.append(key)
            if len(selected) >= 8:
                return selected
    return selected or _infer_columns(rows)


def _status_badge(status: str) -> str:
    return STATUS_BADGES.get(status.upper(), f"🔵 **{status or 'INFO'}**")


def _highest_tablespace(snapshot: HealthSnapshot) -> str:
    if not snapshot.tablespaces:
        return "n/a"
    top = snapshot.tablespaces[0]
    return f"{top.tablespace_name} {top.used_pct:.1f}%"


def _coerce_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            parsed = ast.literal_eval(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _to_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _table_cell(value: Any) -> str:
    return _escape_cell(_format_value(value, max_length=140))


def _format_value(value: Any, max_length: int = 400) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return f"{value:.2f}".rstrip("0").rstrip(".")
    if isinstance(value, dict):
        text = ", ".join(f"{friendly_label(str(key))}={_format_value(val, max_length=120)}" for key, val in value.items() if _has_value(val))
    elif isinstance(value, list):
        text = ", ".join(_format_value(item, max_length=80) for item in value[:5])
    else:
        text = str(value)
    text = " ".join(text.split())
    if len(text) > max_length:
        return text[: max_length - 1] + "…"
    return text


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _header(name: str) -> str:
    return str(name).replace("_", " ").title()


def _has_value(value: Any) -> bool:
    return value is not None and value != "" and value != []


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


def _render_investigation_step_output(step: InvestigationStep) -> list[str]:
    if step.status != "success":
        return []
    if not step.result_rows:
        return ["No row output returned.", ""]
    keys = _investigation_output_columns(step)
    columns = [{"header": key, "width": 18, "key": key} for key in keys]
    lines = [
        "**SQL Output:**",
        "",
        _render_scroll_pre(format_dba_table(step.result_rows, columns)),
    ]
    if step.result_truncated:
        lines.append(f"Displayed first {len(step.result_rows)} row(s).")
    lines.append("")
    return lines


def _investigation_output_columns(step: InvestigationStep) -> list[str]:
    keys: list[str] = []
    preferred = [str(col) for col in (step.result_columns or []) if col]
    for key in preferred:
        if key not in keys:
            keys.append(key)
        if len(keys) >= 8:
            return keys
    for row in step.result_rows:
        if not isinstance(row, dict):
            continue
        for key in row:
            if key not in keys:
                keys.append(str(key))
            if len(keys) >= 8:
                return keys
    return keys[:8]


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


def _remediation_why_line(proposal: RemediationProposal) -> str:
    if proposal.action_type not in {"clear_blocking_lock", "kill_session"}:
        return proposal.reason_for_action or proposal.rationale or proposal.description
    target = proposal.target or {}
    sid = _coerce_int(target.get("sid"))
    sid_label = str(sid) if sid is not None else "unknown"
    username = str(target.get("username") or "-")
    classification = str(target.get("blocker_classification") or "unknown")
    idle_in_tx = bool(target.get("blocker_idle_in_transaction")) or classification == "idle_in_transaction_blocker"
    reason = "idle in transaction" if idle_in_tx else "a blocking session"
    blocked_count = _coerce_int(target.get("blocked_session_count"))
    blocked_label = str(blocked_count) if blocked_count is not None else "unknown"
    session_label = "session" if blocked_count == 1 else "sessions"
    max_wait_s = _coerce_int(target.get("max_blocked_wait_seconds"))
    wait_label = str(max_wait_s) if max_wait_s is not None else "unknown"
    object_name = str(target.get("object_name") or "").strip()
    object_owner = str(target.get("object_owner") or "").strip()
    object_label = f"{object_owner}.{object_name}" if object_owner and object_name else object_name
    object_fragment = f" on {object_label}" if object_label else ""
    return (
        f"SID {sid_label} (user {username}) is {reason} and blocking {blocked_label} {session_label} "
        f"for {wait_label} seconds{object_fragment}."
    )


def _reviewer_decision_line(proposal: RemediationProposal, review: RemediationReview | None) -> str:
    if review is None:
        return "Pending - reviewer decision not available."
    status = str(review.status or "pending").lower()
    if status == "approved":
        if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
            target = proposal.target or {}
            classification = str(target.get("blocker_classification") or "unknown")
            blocked_count = _coerce_int(target.get("blocked_session_count")) or 0
            max_wait_s = _coerce_int(target.get("max_blocked_wait_seconds")) or 0
            sustained_impact = blocked_count >= 2 or max_wait_s >= 300
            if classification in {"application_session", "idle_in_transaction_blocker"} and sustained_impact:
                return "Approved - guardrail checks passed for a foreground user blocker with sustained wait impact."
        return "Approved - guardrail checks passed for the proposed remediation."
    if status == "rejected":
        failed = {str(item) for item in review.guardrail_checks_failed}
        protected_failures = {
            "target_not_protected_user",
            "target_not_background_process",
            "target_not_protected_maintenance_session",
            "blocker_not_internal_or_background",
            "protected_user",
            "background_process",
            "protected_maintenance_session",
            "protected_blocker_class",
        }
        if failed & protected_failures:
            return "Denied - target session is protected by guardrails."
        return "Denied - guardrail checks failed for this remediation action."
    if status == "not_needed":
        return "Not needed - no reviewer action required."
    return "Pending - reviewer decision in progress."


def _compact_risk_line(proposal: RemediationProposal) -> str | None:
    if proposal.action_type in {"clear_blocking_lock", "kill_session"} and proposal.risks:
        return "Risk: killing the session may roll back the active transaction; validate ownership first."
    return None


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None


def _render_remediation_evidence_lines(proposal: RemediationProposal) -> list[str]:
    target = proposal.target or {}
    lines: list[str] = []
    blocker = (
        f"Blocker: SID {target.get('sid')}, SERIAL# {target.get('serial#')}, INST {target.get('inst_id')}, "
        f"user={target.get('username') or '-'}, status={target.get('status') or '-'}, "
        f"class={target.get('blocker_classification') or 'unknown'}."
    )
    lines.append(f"- {blocker}")
    lines.append(
        "- "
        + (
            f"Context: program={target.get('program') or '-'}, module={target.get('module') or '-'}, "
            f"machine={target.get('machine') or '-'}."
        )
    )
    blocked_count = target.get("blocked_session_count")
    max_wait = target.get("max_blocked_wait_seconds")
    lines.append(
        f"- Impact: blocked_session_count={blocked_count if blocked_count is not None else 'unknown'}, "
        f"max_wait_s={max_wait if max_wait is not None else 'unknown'}."
    )
    if target.get("blocker_idle_in_transaction") is not None:
        lines.append(
            f"- Transaction state: has_transaction={target.get('blocker_has_transaction')}, "
            f"idle_in_transaction={target.get('blocker_idle_in_transaction')}."
        )
    object_owner = target.get("object_owner")
    object_name = target.get("object_name")
    object_type = target.get("object_type")
    if object_name:
        lines.append(f"- Object: {object_owner}.{object_name} ({object_type or 'unknown type'}).")
    else:
        lines.append("- Object: unavailable from current lock evidence.")
    blocked_sessions = target.get("blocked_session_details")
    if isinstance(blocked_sessions, list) and blocked_sessions:
        first = blocked_sessions[0]
        lines.append(
            "- Blocked sample: "
            f"SID {first.get('sid')}, user={first.get('username')}, sql_id={first.get('sql_id')}, "
            f"event={first.get('event')}, wait_s={first.get('seconds_in_wait')}."
        )
    else:
        lines.append("- Blocked sample: unavailable.")
    lines.append(f"- Evidence completeness: {target.get('evidence_complete')}.")
    return lines


def render_action_history_markdown(records: list[RemediationRecord]) -> str:
    if not records:
        return "No remediation actions have been executed yet."
    lines = []
    for record in records[-10:][::-1]:
        icon = severity_icon("WARNING" if record.execution.status == "succeeded" else "CRITICAL")
        review_icon = "🟢" if record.review.status == "approved" else "🔴" if record.review.status == "rejected" else "🔵"
        rationale = record.review.rationale or "No reviewer rationale provided."
        notes = "; ".join(record.review.reviewer_notes[:2]) if record.review.reviewer_notes else "No reviewer notes."
        lines.append(
            f"- {icon} {record.created_at} — {record.proposal.title} — "
            f"review={review_icon} {record.review.status} ({rationale}; {notes}) — execution={record.execution.status}"
        )
    return "\n".join(lines)
