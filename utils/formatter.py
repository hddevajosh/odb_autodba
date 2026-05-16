from __future__ import annotations

import ast
import html
import re
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

INVESTIGATION_RENDER_ROW_LIMIT = 50

SECTION_COLUMNS = {
    "Database Status": ["db_name", "open_mode", "database_role", "log_mode", "instance_name", "instance_status"],
    "Alert Log Errors": ["source", "window_hours", "filter", "rows_found", "status", "ts", "severity", "code", "message"],
    "Tablespace Usage": [
        "tablespace_name",
        "pct_used",
        "pct_free",
    ],
    "Tablespace Allocation Details": ["tablespace_name", "allocated_gb", "used_allocated_gb", "free_allocated_gb", "max_gb", "allocated_used_pct", "max_used_pct", "autoextensible", "allocation_anomaly"],
    "Temp Tablespace Capacity": ["tablespace_name", "temp_allocated_gb", "temp_current_allocated_gb", "temp_free_gb", "temp_used_gb", "temp_used_pct"],
    "Temp Session Consumers": ["inst_id", "sid", "serial_num", "username", "sql_id", "module", "tablespace", "temp_used_mb"],
    "Locks And Blocking": ["waiter_inst_id", "waiter_sid", "waiter_user", "waiter_sql_id", "waiter_wait_class", "seconds_in_wait", "blocker_inst_id", "blocker_sid", "blocker_user", "blocker_sql_id", "blocker_classification", "blocking_severity", "blocking_reason"],
    "Objects And Validity": ["owner", "object_name", "object_type"],
    "Redo And Archiving": ["thread#", "switches_24h", "switches_per_hour", "event", "avg_wait_ms", "log_mode", "archive_dest"],
    "Services And Routing": ["inst_id", "service_name", "network_name", "con_id", "container_name", "status", "finding"],
    "Database Role Mode": ["role", "open_mode", "standby_health_mode", "primary_style_checks_skipped"],
    "Standby Role / Open Mode": ["db_name", "database_role", "open_mode", "protection_mode", "protection_level", "switchover_status", "log_mode"],
    "Managed Recovery Process": ["inst_id", "process", "status", "client_process", "thread#", "sequence#", "block#", "blocks"],
    "Data Guard Lag": ["name", "value", "unit", "time_computed", "datum_time", "parsed_seconds", "severity"],
    "Archive Gap": ["thread#", "low_sequence#", "high_sequence#"],
    "Archive Destination Status": [
        "dest_id",
        "status",
        "type",
        "database_mode",
        "recovery_mode",
        "protection_mode",
        "destination",
        "error",
        "archived_thread#",
        "archived_seq#",
        "applied_thread#",
        "applied_seq#",
    ],
    "Data Guard Status Messages": ["timestamp", "severity", "facility", "error_code", "message"],
    "Standby Alert Log Signals": ["originating_timestamp", "component_id", "message_type", "message_level", "severity", "message_text"],
    "Listener / Connectivity Log Signals": ["source", "severity", "message"],
    "Standby Active Services": ["inst_id", "service_name", "network_name", "con_id", "container_name", "status", "finding"],
    "DBA Trust Checks": ["check", "value"],
    "Backup And Recovery": ["session_key", "input_type", "status", "completed"],
    "Scheduler Jobs": ["owner", "job_name", "status", "error", "started"],
    "Performance Overview": ["sql_id", "plan_hash_value", "executions", "elapsed_s", "cpu_s", "ela_per_exec_s", "buffer_gets", "disk_reads"],
    "Current Wait Profile": ["event", "wait_class", "time_waited_s", "total_waits", "avg_wait_ms"],
    "Session Wait Correlation": ["inst_id", "event", "wait_class", "sql_id", "module", "username", "session_count", "max_seconds_in_wait"],
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
    "Tablespace Usage": [
        "tablespace_name",
        "pct_used",
        "pct_free",
    ],
    "Temp Tablespace Capacity": ["tablespace_name", "temp_used_pct", "temp_used_gb", "temp_free_gb"],
    "Temp Session Consumers": ["inst_id", "sid", "username", "sql_id", "tablespace", "temp_used_mb"],
    "Managed Recovery Process": ["inst_id", "process", "status", "client_process", "thread#", "sequence#"],
    "Data Guard Lag": ["name", "value", "parsed_seconds", "severity"],
    "Archive Gap": ["thread#", "low_sequence#", "high_sequence#"],
    "Archive Destination Status": ["dest_id", "status", "error", "archived_seq#", "applied_seq#"],
    "Data Guard Status Messages": ["timestamp", "severity", "error_code", "message"],
    "Standby Alert Log Signals": ["originating_timestamp", "severity", "message_text"],
    "Listener / Connectivity Log Signals": ["severity", "message"],
    "Standby Active Services": ["inst_id", "service_name", "status", "finding"],
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


def _format_gb_from_mb(value_mb: Any) -> str:
    number = _to_float(value_mb)
    if number is None:
        return _format_value(value_mb)
    return f"{number / 1024.0:.2f}"


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
        "Managed Recovery Process",
        "Data Guard Lag",
        "Archive Gap",
        "Archive Destination Status",
        "Data Guard Status Messages",
        "Standby Alert Log Signals",
        "Listener / Connectivity Log Signals",
        "Standby Active Services",
    }:
        return "table_compact"
    if section_name in {"Database Status", "Database Role Mode", "Standby Role / Open Mode", "Init Parameters", "Scheduler Jobs", "Redo And Archiving", "Backup And Recovery"}:
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
        if str(section.name or "").strip() == "DBA Trust Checks":
            continue
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

    historical_confidence = _history_mapping(transition_data.get("historical_confidence"))
    structured_awr = _history_mapping(awr_data.get("structured_sections"))
    unavailable_reasons = structured_awr.get("unavailable_reasons") if isinstance(structured_awr.get("unavailable_reasons"), list) else []
    unavailable_reason_text = ", ".join(str(item) for item in unavailable_reasons if str(item).strip())
    snapshot_quality = _history_mapping(awr_data.get("snapshot_quality"))

    lines.extend(["", _section_heading("AWR Snapshot Chain Diagnostic", informational=True), ""])
    chain_rows = structured_awr.get("snapshot_chain_diagnostic") if isinstance(structured_awr.get("snapshot_chain_diagnostic"), list) else snapshot_quality.get("diagnostic_rows")
    if isinstance(chain_rows, list) and chain_rows:
        lines.append(_render_table(chain_rows, ["DBID", "Instance", "Startup Time", "Snap Min", "Snap Max", "Begin Time", "End Time", "Rows", "Selected"]))
        if sum(1 for row in chain_rows if str(row.get("Selected") or "").lower() == "no") > 0:
            lines.append(
                "Multiple AWR snapshot chains exist for this time range. AutoDBA selected snapshots matching current DBID/instance/startup chain. Other chains were ignored."
            )
    else:
        lines.append("AWR snapshot chain diagnostic rows were unavailable.")

    lines.extend(["", _section_heading("AWR Snapshot Quality", informational=True), ""])
    window_rows = structured_awr.get("snapshot_windows") if isinstance(structured_awr.get("snapshot_windows"), list) else snapshot_quality.get("window_rows")
    if isinstance(window_rows, list) and window_rows:
        lines.append(_render_table(window_rows, ["Window", "DBID", "Instance", "Startup Time", "Begin Snap", "End Snap", "Begin Time", "End Time", "Duration Min", "Quality", "Use"]))
    else:
        lines.append("AWR snapshot window rows were unavailable.")
    quality_summary_rows = [
        {
            "Window quality": snapshot_quality.get("window_quality") or "LOW",
            "Usage": snapshot_quality.get("usage") or "context_only",
            "Reason": snapshot_quality.get("reason") or "AWR snapshot quality was not available.",
        }
    ]
    lines.append(_render_table(quality_summary_rows, ["Window quality", "Usage", "Reason"]))
    if str(snapshot_quality.get("window_quality") or "").upper() == "LOW":
        lines.append("AWR current window is low quality; AWR findings are context only and cannot drive CRITICAL RCA alone.")

    lines.extend(["", _section_heading("AWR Workload Delta", informational=True), ""])
    workload_rows = structured_awr.get("workload_delta") if isinstance(structured_awr.get("workload_delta"), list) else []
    if workload_rows:
        lines.append(_render_table(workload_rows, ["Metric", "Previous", "Current", "Delta", "Per Min", "Interpretation"]))
    else:
        lines.append(
            "AWR workload delta rows were unavailable."
            + (f" Reason: {unavailable_reason_text}." if unavailable_reason_text else "")
        )

    lines.extend(["", _section_heading("AWR Wait Class Shift", informational=True), ""])
    wait_shift_rows = structured_awr.get("wait_class_shift") if isinstance(structured_awr.get("wait_class_shift"), list) else []
    if wait_shift_rows:
        lines.append(_render_table(wait_shift_rows, ["Wait Class", "Previous Wait s", "Current Wait s", "Delta s", "Current % DB Time", "Interpretation"]))
    else:
        lines.append(
            "AWR wait class shift rows were unavailable."
            + (f" Reason: {unavailable_reason_text}." if unavailable_reason_text else "")
        )

    lines.extend(["", _section_heading("AWR Top Wait Events", informational=True), ""])
    top_wait_rows = structured_awr.get("top_wait_events") if isinstance(structured_awr.get("top_wait_events"), list) else []
    if top_wait_rows:
        lines.append(_render_table(top_wait_rows, ["Event", "Wait Class", "Prev Wait s", "Curr Wait s", "Delta s", "Waits", "Avg Latency", "Impact", "DBA Interpretation"]))
    else:
        lines.append(
            "AWR top wait-event rows were unavailable."
            + (f" Reason: {unavailable_reason_text}." if unavailable_reason_text else "")
        )

    lines.extend(["", _section_heading("AWR SQL Delta", informational=True), ""])
    sql_delta_rows = structured_awr.get("sql_delta") if isinstance(structured_awr.get("sql_delta"), list) else []
    if sql_delta_rows:
        lines.append(
            _render_table(
                sql_delta_rows,
                [
                    "SQL_ID",
                    "Plan",
                    "Schema",
                    "Module",
                    "Execs",
                    "Elapsed s",
                    "Elapsed/Exec s",
                    "CPU s",
                    "I/O Wait s",
                    "App Wait s",
                    "Conc Wait s",
                    "Gets/Exec",
                    "Reads/Exec",
                    "DB Time %",
                    "Classification",
                    "sql_text_sample",
                    "Interpretation",
                ],
            )
        )
    else:
        lines.append(
            "AWR SQL delta rows were unavailable."
            + (f" Reason: {unavailable_reason_text}." if unavailable_reason_text else "")
        )

    lines.extend(["", _section_heading("AWR Plan Stability", informational=True), ""])
    plan_rows = structured_awr.get("plan_stability") if isinstance(structured_awr.get("plan_stability"), list) else []
    if plan_rows:
        lines.append(_render_table(plan_rows, ["SQL_ID", "Plans", "Previous Plan", "Current Plan", "Plan Changed", "Prev Elapsed/Exec", "Curr Elapsed/Exec", "Regression Evidence"]))
    else:
        lines.append("AWR plan-stability rows were unavailable.")

    lines.extend(["", _section_heading("AWR Blocking / ASH Concurrency", informational=True), ""])
    ash_rows = structured_awr.get("ash_blocking") if isinstance(structured_awr.get("ash_blocking"), list) else []
    if ash_rows:
        lines.append(_render_table(ash_rows, ["Event", "Wait Class", "Samples", "Distinct Waiters", "Blocking Inst", "Blocking SID", "Top SQL_ID", "Object", "Interpretation"]))
    else:
        lines.append("ASH concurrency rows were unavailable.")

    lines.extend(["", _section_heading("AWR Object Hotspots", informational=True), ""])
    object_rows = structured_awr.get("object_hotspots") if isinstance(structured_awr.get("object_hotspots"), list) else []
    if object_rows:
        lines.append(_render_table(object_rows, ["Object", "Object Type", "Event", "Wait Class", "Samples", "Top SQL_ID", "Interpretation"]))
    else:
        lines.append("AWR object hotspot rows were unavailable.")

    lines.extend(["", _section_heading("AWR Redo / Commit Profile", informational=True), ""])
    redo_rows = structured_awr.get("redo_commit_profile") if isinstance(structured_awr.get("redo_commit_profile"), list) else []
    if redo_rows:
        lines.append(_render_table(redo_rows, ["Metric", "Previous", "Current", "Delta", "Interpretation"]))
    else:
        lines.append("AWR redo/commit profile rows were unavailable.")

    lines.extend(["", _section_heading("AWR Current Evidence Correlation", informational=True), ""])
    current_metrics = {}
    if context is not None and context.latest_run is not None and isinstance(context.latest_run.metrics, dict):
        current_metrics = context.latest_run.metrics
    blocking_count = current_metrics.get("blocking_count")
    correlation_rows: list[dict[str, Any]] = []
    if any("enq: tx" in str(row.get("Event") or "").lower() for row in ash_rows):
        if (blocking_count or 0) > 0:
            correlation_rows.append(
                {
                    "AWR Signal": "TX row lock contention",
                    "Current Health Evidence": f"blocking_count={blocking_count}",
                    "Correlation": "confirmed",
                    "Decision": "active driver",
                }
            )
        else:
            correlation_rows.append(
                {
                    "AWR Signal": "TX row lock contention",
                    "Current Health Evidence": f"blocking_count={blocking_count or 0} in latest health run",
                    "Correlation": "historical/transient",
                    "Decision": "AWR confirms row-lock contention occurred in previous AWR window, but it is not active now.",
                }
            )
    if correlation_rows:
        lines.append(_render_table(correlation_rows, ["AWR Signal", "Current Health Evidence", "Correlation", "Decision"]))
    else:
        lines.append("No strong AWR-to-current correlation rows were available.")

    lines.extend(["", _section_heading("AWR DBA Recommendations", informational=True), ""])
    rec_rows = structured_awr.get("dba_recommendations") if isinstance(structured_awr.get("dba_recommendations"), list) else []
    if rec_rows:
        lines.append(_render_table(rec_rows, ["Priority", "Recommendation", "Reason"]))
    else:
        lines.append("No AWR-specific recommendations were generated.")

    lines.extend(["", _section_heading("AWR Confidence / Coverage Notes", informational=True), ""])
    confidence_rows = structured_awr.get("confidence_coverage") if isinstance(structured_awr.get("confidence_coverage"), list) else []
    if confidence_rows:
        lines.append(_render_table(confidence_rows, ["Item", "Value"]))
    else:
        confidence_fallback = [
            {"Item": "AWR mode", "Value": "structured DBA_HIST comparison"},
            {"Item": "Current window quality", "Value": snapshot_quality.get("window_quality") or "LOW"},
            {"Item": "Confidence", "Value": historical_confidence.get("confidence_level") or snapshot_quality.get("confidence") or "LOW"},
        ]
        lines.append(_render_table(confidence_fallback, ["Item", "Value"]))

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
    recommended_plan_decision = (
        plan_analysis.get("recommended_plan_decision") if isinstance(plan_analysis.get("recommended_plan_decision"), dict) else {}
    )

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
        _render_sql_metric_table(
            {k: v for k, v in plan_analysis.items() if k != "recommended_plan_decision"},
            default_text="Plan stability evidence was unavailable.",
        ),
        "",
        "## Recommended Plan Decision",
        _render_recommended_plan_decision(recommended_plan_decision, deep_dive.sql_id),
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


def _render_recommended_plan_decision(payload: dict[str, Any], sql_id: str) -> str:
    if not payload:
        return "No plan recommendation possible from AWR for this SQL_ID/lookback window."
    why_items = payload.get("why") if isinstance(payload.get("why"), list) else []
    why_lines = [f"- {str(item).strip()}" for item in why_items if str(item).strip()]
    return "\n".join(
        [
            _render_sql_metric_table(
                {
                    "SQL_ID": payload.get("sql_id") or sql_id,
                    "Recommended plan": payload.get("recommended_plan"),
                    "Current live plan": payload.get("current_live_plan"),
                    "Dominant historical plan": payload.get("dominant_historical_plan"),
                    "Baseline/fastest eligible plan": payload.get("baseline_fastest_eligible_plan"),
                    "Decision": payload.get("decision"),
                    "Confidence": payload.get("confidence"),
                },
                default_text="No recommendation details were generated.",
            ),
            "",
            "Why:",
            "\n".join(why_lines) if why_lines else "- No specific rationale lines were captured.",
            "",
            "DBA recommendation:",
            str(payload.get("dba_recommendation") or "No DBA recommendation was captured."),
        ]
    )


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


def _infer_awr_mode(previous_window: dict[str, Any], current_window: dict[str, Any]) -> str:
    if (
        previous_window.get("begin_snap_id") is not None
        and previous_window.get("end_snap_id") is not None
        and previous_window.get("begin_snap_id") == current_window.get("begin_snap_id")
        and previous_window.get("end_snap_id") == current_window.get("end_snap_id")
    ):
        return "single_window_interpretation"
    return "comparison"


def _render_awr_bullet_lines(items: list[str], *, empty: str) -> list[str]:
    if not items:
        return [f"- {empty}"]
    lines: list[str] = []
    for item in items:
        parts = [part.rstrip() for part in str(item).splitlines() if part.strip()]
        if not parts:
            continue
        lines.append(f"- {parts[0].strip()}")
        for part in parts[1:]:
            lines.append(f"  {part.strip()}")
    return lines or [f"- {empty}"]


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
    host_check = _host_check_payload(snapshot)
    return "\n".join(
        _render_horizontal_kv_block(
            [
                ("Active sessions", snapshot.session_summary.active_sessions),
                ("Blocking chains", len(snapshot.blocking_chains)),
                ("ORA/TNS rows", len(snapshot.raw_evidence.get("alert_log") or [])),
                ("Highest tablespace", _highest_tablespace(snapshot)),
                ("Actionable findings", f"{len(snapshot.actionable_items)} ({critical_count} critical, {warning_count} warning)"),
                ("Host checks", _host_checks_summary_value(host_check)),
            ],
            columns=2,
        )
    )


def _host_checks_summary_value(host_check: dict[str, Any]) -> str:
    scope = str(host_check.get("host_check_scope") or "").strip().lower()
    if scope == "disabled":
        return "Disabled"
    if scope == "local_app_host":
        return "Local AutoDBA app host"
    if scope == "remote_db_host_ssh":
        return "Remote Oracle DB host via SSH"
    if scope == "unavailable":
        return "Unavailable"
    return "Included"


def _host_check_payload(snapshot: HealthSnapshot) -> dict[str, Any]:
    raw = snapshot.raw_evidence.get("host_check") if isinstance(snapshot.raw_evidence.get("host_check"), dict) else {}
    if raw:
        return dict(raw)
    host = snapshot.host_snapshot
    if host is None:
        return {
            "host_check_mode": "disabled",
            "host_check_scope": "disabled",
            "host_check_label": "Host checks disabled",
            "host_check_warning": "Host OS metrics disabled; database health is based on Oracle-side signals only.",
            "host_check_target": "",
        }
    return {
        "host_check_mode": host.host_check_mode,
        "host_check_scope": host.host_check_scope,
        "host_check_label": host.host_check_label,
        "host_check_warning": host.host_check_warning or "",
        "host_check_target": host.host_check_target or "",
    }


def _render_host_check_scope_section(snapshot: HealthSnapshot) -> str:
    host_check = _host_check_payload(snapshot)
    mode = str(host_check.get("host_check_mode") or "local_app_host")
    scope = str(host_check.get("host_check_scope") or "").strip().lower()
    label = str(host_check.get("host_check_label") or "Host metrics unavailable")
    if mode == "ssh_remote":
        label = "Remote Oracle DB host via SSH"
    elif mode == "local_app_host":
        label = "Local AutoDBA app host"
    elif mode == "disabled":
        label = "Host checks disabled"
    warning = str(host_check.get("host_check_warning") or "").strip()
    target = str(host_check.get("host_check_target") or "").strip()
    lines = [
        f"- Mode: {mode}",
        f"- Scope: {label}",
    ]
    if mode == "ssh_remote" and scope == "unavailable":
        lines.append("- Availability: unavailable")
    if target:
        lines.append(f"- Host: {target}")
    if warning:
        lines.append(f"- Note: {warning}")
    elif mode == "disabled":
        lines.append("- Note: Oracle-side health checks only.")
    return "\n".join(lines)


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
            pct_used = _to_float(row.get("pct_used"))
            if pct_used is None:
                pct_used = _to_float(row.get("used_pct"))
            pct_free = _to_float(row.get("pct_free"))
            row["pct_used"] = _format_pct(pct_used)
            row["pct_free"] = _format_pct(pct_free)
            row["used_pct"] = _format_pct(pct_used)
        return prepared
    if section_name == "Tablespace Allocation Details":
        for row in prepared:
            row["allocated_gb"] = _format_value(_to_float(row.get("allocated_gb")))
            row["used_allocated_gb"] = _format_value(_to_float(row.get("used_allocated_gb")))
            row["free_allocated_gb"] = _format_value(_to_float(row.get("free_allocated_gb")))
            row["max_gb"] = _format_value(_to_float(row.get("max_gb")))
            row["allocated_used_pct"] = _format_pct(_to_float(row.get("allocated_used_pct")))
            row["max_used_pct"] = _format_pct(_to_float(row.get("max_used_pct")))
        return prepared
    if section_name == "Temp Tablespace Capacity":
        for row in prepared:
            row["temp_used_pct"] = _format_pct(_to_float(row.get("temp_used_pct")))
        return prepared
    if section_name == "Temp Session Consumers":
        for row in prepared:
            if "temp_used_mb" in row:
                row["temp_used_mb"] = format_storage_value(row.get("temp_used_mb"), source_unit="mb")
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
    pct = top.pct_used if top.pct_used is not None else top.used_pct
    return f"{top.tablespace_name} {float(pct or 0.0):.1f}%"


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
    summary_line = str(report.summary or "").strip() or f"Ran {len(report.steps or [])} read-only SQL step(s)."
    question_text = _coerce_problem_statement_for_render(report)
    success_steps = [step for step in (report.steps or []) if str(step.status or "").lower() == "success"]
    latest_step = report.steps[-1] if report.steps else None

    sections = [
        "# AI Investigation Result",
        "",
        "## Question",
        "",
        question_text or "Not provided.",
        "",
        "## Summary",
        "",
        summary_line,
        "",
        "## Result",
        "",
        "See SQL Evidence Collected below.",
        "",
        "## SQL Evidence Collected",
        "",
    ]
    if bool(report.thread_continued) and str(report.thread_id or "").strip():
        known_sql_ids = ", ".join((report.thread_context_summary or {}).get("known_sql_ids") or []) or "none"
        known_tables = ", ".join((report.thread_context_summary or {}).get("known_tables") or []) or "none"
        sections[10:10] = [
            "Continuing previous investigation context:",
            f"- thread_id: {report.thread_id}",
            f"- known SQL_IDs: {known_sql_ids}",
            f"- known tables: {known_tables}",
            "",
        ]

    if success_steps:
        for step in success_steps:
            sections.extend(_render_sql_evidence_step(step))
            sections.append("")
    elif latest_step is not None:
        sections.extend(["No successful SQL result was produced.", "", latest_step.result_preview or "Investigation step failed.", ""])
    else:
        sections.extend(["No SQL steps were executed.", ""])

    correction_blocks: list[str] = []
    for step in report.steps or []:
        correction_lines = _render_correction_attempts(step)
        if correction_lines:
            correction_blocks.extend(correction_lines + [""])
    if correction_blocks:
        sections.extend(["## Correction Attempts", ""])
        sections.extend(correction_blocks)

    observations: list[str] = []
    for step in report.steps or []:
        observations.append(
            f"Step {step.step_number} ({step.goal}): status={step.status}, rows={int(step.row_count or 0)}, result={step.result_preview}"
        )
        if str(step.finding or "").strip():
            observations.append(step.finding.strip())
    observations = _dedupe_strings(observations)
    sections.extend(["## Observation", ""])
    if observations:
        sections.extend(f"- {item}" for item in observations[:12])
    else:
        sections.append("- No observations captured.")

    sections.extend(["", "## DBA Inference", ""])
    inference = str(report.likely_cause or "").strip()
    sections.append(inference or "No DBA inference was produced.")

    sections.extend(["", "## Evidence Source", ""])
    sections.append(f"- Source: {str(report.evidence_source or 'SQL')}")
    sections.append(f"- Historical context used: {str(bool(report.historical_context_used)).lower()}")
    if isinstance(report.required_evidence_status, dict) and report.required_evidence_status:
        completed = sum(1 for value in report.required_evidence_status.values() if bool(value))
        total = len(report.required_evidence_status)
        sections.append(f"- Required evidence satisfied: {completed}/{total}")

    sections.extend(["", "## Confidence / Termination", ""])
    sections.append(f"- confidence: {str(report.confidence or 'MEDIUM')}")
    sections.append(f"- inference_confidence: {str(report.inference_confidence or report.confidence or 'MEDIUM')}")
    sections.append(f"- termination_reason: {str(report.termination_reason or 'completed')}")
    if int(report.sql_execution_cap or 0) > 0:
        sections.append(f"- sql_execution_budget: {int(report.sql_execution_count or 0)}/{int(report.sql_execution_cap or 0)}")
    if str(report.clarification_question or "").strip():
        sections.append(f"- clarification: {report.clarification_question.strip()}")

    notes = _normalize_notes_list(report.planner_notes)
    if report.fallback_used:
        notes.append("AI stepwise planner unavailable; fallback SQL path was used.")
    notes = _dedupe_strings(notes)
    if notes:
        sections.extend(["", "## Planner Notes", ""])
        sections.extend(f"- {line}" for line in notes)

    return "\n".join(sections)


def _coerce_problem_statement_for_render(report: InvestigationReport) -> str:
    primary = str(getattr(report, "problem_statement", "") or "").strip()
    if primary:
        return primary
    for key in ("question", "prompt", "user_question"):
        value = getattr(report, key, "")
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _render_correction_attempts(step: InvestigationStep) -> list[str]:
    failed_attempts = _investigation_failed_attempts(step)
    if not failed_attempts:
        return []
    attempts = _investigation_attempt_records(step)
    lines: list[str] = [f"Step {step.step_number}: {step.goal}", ""]
    for failed in failed_attempts:
        attempt_no = int(failed.get("attempt_no") or failed.get("attempt") or 0)
        sql = str(failed.get("sql") or "").strip()
        error = str(failed.get("error") or "").strip()
        repair_reason = str(failed.get("repair_reason") or "").strip()
        repaired_sql = ""
        for entry in attempts:
            entry_no = int(entry.get("attempt_no") or entry.get("attempt") or 0)
            entry_status = str(entry.get("execution_status") or entry.get("status") or "").strip().lower()
            entry_sql = str(entry.get("sql") or "").strip()
            if entry_no > attempt_no and entry_status == "success" and entry_sql:
                repaired_sql = entry_sql
                break
        lines.append(f"Attempt {attempt_no} failed:")
        if sql:
            lines.extend(["SQL:", "```sql", sql, "```"])
        if error:
            lines.extend([f"- Error: {error}"])
        if repair_reason:
            lines.extend([f"- Repair reason: {repair_reason}"])
        if repaired_sql:
            lines.extend(["Final repaired SQL:", "```sql", repaired_sql, "```"])
        lines.append("")
    return lines


def _render_sql_evidence_step(step: InvestigationStep) -> list[str]:
    status_label = _investigation_status_label(step)
    row_count = int(step.row_count or 0)
    columns = [str(col) for col in (step.result_columns or []) if str(col).strip()]
    if not columns and step.result_rows:
        columns = [str(key) for key in list(step.result_rows[0].keys())[:8] if str(key).strip()]
    lines: list[str] = [
        f"### Step {step.step_number} — {step.goal or 'Investigation step'}",
        f"Status: {status_label}",
        f"Rows: {row_count}",
        f"Columns: {', '.join(columns) if columns else 'none'}",
        f"Repaired from failed attempt: {'yes' if _investigation_repair_used(step) else 'no'}",
        "",
        "SQL:",
        "```sql",
        str(step.sql or "").strip() or "-- SQL unavailable --",
        "```",
        "",
        "Output:",
    ]
    lines.extend(_render_investigation_step_output(step))
    return lines


def _normalize_notes_list(notes: Any) -> list[str]:
    if notes is None:
        return []
    if isinstance(notes, str):
        text = notes.strip()
        return [text] if text else []
    if isinstance(notes, list):
        return [str(item).strip() for item in notes if str(item).strip()]
    try:
        return [str(item).strip() for item in list(notes) if str(item).strip()]
    except Exception:
        text = str(notes).strip()
        return [text] if text else []


def _render_investigation_step_output(step: InvestigationStep) -> list[str]:
    if step.status != "success":
        return []
    rows = _sanitize_investigation_rows(step.result_rows or [])
    if not rows:
        return ["Returned 0 rows.", ""]
    clipped = rows[:INVESTIGATION_RENDER_ROW_LIMIT]
    keys = _investigation_output_columns(step=step, rows=clipped)
    columns = _investigation_output_column_specs(rows=clipped, keys=keys)
    lines = [
        _render_scroll_pre(format_dba_table(clipped, columns)),
    ]
    if step.result_truncated or int(step.row_count or 0) > len(clipped):
        lines.append(f"Displayed first {len(clipped)} row(s); output truncated.")
    lines.append("")
    return lines


def _investigation_output_columns(*, step: InvestigationStep, rows: list[dict[str, Any]]) -> list[str]:
    keys: list[str] = []
    preferred = [str(col) for col in (step.result_columns or []) if col]
    for key in preferred:
        if key not in keys:
            keys.append(key)
        if len(keys) >= 8:
            return keys
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in row:
            if key not in keys:
                keys.append(str(key))
            if len(keys) >= 8:
                return keys
    return keys[:8]


def _investigation_output_column_specs(*, rows: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for key in keys:
        header_len = len(str(key))
        sample_values = [str((row.get(key) if isinstance(row, dict) else "") or "") for row in rows[:20]]
        max_value_len = max([0] + [len(value) for value in sample_values])
        width = max(10, header_len + 2, min(40, max_value_len + 2))
        specs.append({"header": key, "width": width, "key": key})
    return specs


def _investigation_attempt_records(step: InvestigationStep) -> list[dict[str, Any]]:
    attempts = step.correction_attempts if isinstance(step.correction_attempts, list) else []
    records: list[dict[str, Any]] = []
    for entry in attempts:
        if hasattr(entry, "model_dump"):
            record = entry.model_dump(mode="json")
        elif isinstance(entry, dict):
            record = dict(entry)
        else:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _investigation_failed_attempts(step: InvestigationStep) -> list[dict[str, Any]]:
    failed: list[dict[str, Any]] = []
    for record in _investigation_attempt_records(step):
        status = str(record.get("execution_status") or record.get("status") or "").strip().lower()
        if status and status != "success":
            failed.append(record)
    return failed


def _investigation_repair_used(step: InvestigationStep) -> bool:
    return bool(_investigation_failed_attempts(step))


def _investigation_status_label(step: InvestigationStep) -> str:
    if str(step.status or "").lower() != "success":
        return str(step.status or "unknown")
    if _investigation_repair_used(step):
        return "success after repair"
    return "success"


def _sanitize_investigation_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cleaned: dict[str, Any] = {}
        for raw_key, raw_value in row.items():
            key = str(raw_key)
            value = raw_value
            if any(token in key.lower() for token in ("password", "passwd", "token", "secret", "api_key", "apikey", "private_key", "credential")):
                cleaned[key] = "***REDACTED***"
                continue
            text = str(value or "")
            text = re.sub(r"(?i)(password\s*[:=]\s*)([^,\s;]+)", r"\1***REDACTED***", text)
            text = re.sub(r"(?i)(token\s*[:=]\s*)([^,\s;]+)", r"\1***REDACTED***", text)
            text = re.sub(r"(?i)(secret\s*[:=]\s*)([^,\s;]+)", r"\1***REDACTED***", text)
            cleaned[key] = text if isinstance(value, str) else value
        sanitized.append(cleaned)
    return sanitized


def render_remediation_card_markdown(proposal: RemediationProposal | None, review: RemediationReview | dict[str, Any] | None = None) -> str:
    if proposal is None:
        return "No remediation proposed for the current analysis."
    review_data = _review_to_dict(review)
    sql = _normalized_sql_command(proposal.execution_sql or proposal.sql)
    safety_level = _proposal_safety_level(proposal)
    severity = _proposal_severity(proposal)
    approval = "required" if safety_level == "high_risk" else "not_required"
    failed_rows, passed_rows = _guardrail_detail_rows_from_review(review_data)
    decision_status = _guardrail_decision_status(review_data, failed_rows)
    decision_icon = "🟢" if decision_status == "approved" else "🔴"
    evidence_rows = _render_evidence_rows(proposal)
    why_line = _remediation_why_line(proposal)
    lines = [
        "## Proposed Remediation",
        "",
        *_markdown_table(("Field", "Value"), [
            ("title", proposal.title),
            ("action_type", proposal.action_type),
            ("safety_level", safety_level),
            ("severity", severity),
            ("guardrail_decision", f"{decision_icon} {decision_status}"),
            ("approval", approval),
        ]),
        "",
        "## Why suggested",
        "",
        why_line,
        "",
        "## Guardrails",
        "",
        *_markdown_table(("Result", "Count"), [
            ("Passed", str(len(passed_rows))),
            ("Failed", str(len(failed_rows))),
        ]),
        "",
        "## Failed Checks",
        "",
    ]
    if failed_rows:
        lines.extend(_markdown_table(("Guardrail", "Reason"), failed_rows))
    else:
        lines.append("No failed guardrails.")
    lines.extend([
        "",
        "## Key Evidence",
        "",
        *_markdown_table(("Field", "Value"), evidence_rows),
        "",
        "## Suggested Command",
        "```sql",
        sql or "-- No executable SQL generated for this proposal.",
        "```",
    ])
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        lines.extend(
            [
                "",
                "## Safety Warning",
                "Killing the session may roll back the blocker transaction and affect application users. Validate blocker ownership before execution.",
            ]
        )
    return "\n".join(lines)


def _markdown_table(headers: tuple[str, str], rows: list[tuple[str, str]]) -> list[str]:
    h1, h2 = headers
    lines: list[str] = []
    lines.append(f"| {h1} | {h2} |")
    lines.append("|---|---|")
    for left, right in rows:
        lines.append(f"| {_table_escape(left)} | {_table_escape(right)} |")
    return lines


def _table_escape(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _guardrail_decision_status(review_data: dict[str, Any], failed_rows: list[tuple[str, str]]) -> str:
    status = str(review_data.get("status") or "").strip().lower()
    if status in {"approved", "rejected"}:
        return status
    return "rejected" if failed_rows else "approved"


def _reviewer_decision_rows(
    *,
    reviewer_state: dict[str, Any],
    source_label: str,
    reason_value: str,
    decision_value: str,
    reviewer_name: str,
    reviewer_model: str,
) -> list[tuple[str, str]]:
    primary_status = str(reviewer_state.get("primary_reviewer_status") or reviewer_state.get("reviewer_status") or "").strip().lower()
    fallback_used = _display_fallback_used(reviewer_state)
    fallback_status = str(reviewer_state.get("fallback_reviewer_status") or reviewer_state.get("reviewer_status") or "").strip().lower()
    if fallback_used:
        normalized_primary_status = primary_status if primary_status in {"unavailable", "timeout", "error", "failed"} else "unavailable"
        normalized_fallback_status = fallback_status if fallback_status in {"approved", "rejected"} else "rejected"
        fallback_icon = "🟢" if normalized_fallback_status == "approved" else "🔴"
        return [
            ("decision", f"{fallback_icon} fallback {normalized_fallback_status}"),
            ("primary_reviewer", reviewer_name),
            ("primary_status", normalized_primary_status),
            ("fallback_reviewer", str(reviewer_state.get("fallback_reviewer_provider") or "Deterministic Guardrail Reviewer")),
            ("fallback_decision", f"{fallback_icon} {normalized_fallback_status}"),
            ("fallback_reason", reason_value or str(reviewer_state.get("fallback_reason") or "openai_error")),
            ("source", source_label),
        ]
    rows: list[tuple[str, str]] = [
        ("decision", decision_value),
        ("reviewer", reviewer_name),
        ("reviewer_model", reviewer_model or "deterministic"),
        ("source", source_label),
    ]
    if reason_value:
        rows.append(("reason", reason_value))
    return rows


def _review_source_label(state: dict[str, Any]) -> str:
    fallback_used = _display_fallback_used(state)
    primary_provider = str(state.get("primary_reviewer_provider") or "")
    if "Deterministic Guardrail Reviewer" in primary_provider and not fallback_used:
        return "existing_guardrails_policy_engine"
    if fallback_used:
        return "existing_guardrails_policy_engine + deterministic_fallback"
    return "existing_guardrails_policy_engine + openai_reviewer"


def _display_fallback_used(state: dict[str, Any]) -> bool:
    if not bool(state.get("fallback_used")):
        return False
    primary_provider = str(state.get("primary_reviewer_provider") or "").strip().lower()
    selected_reviewer = str(state.get("selected_reviewer") or "").strip().lower()
    fallback_reason = str(state.get("fallback_reason") or "").strip().lower()
    primary_status = str(state.get("primary_reviewer_status") or "").strip().lower()
    if "deterministic guardrail reviewer" in primary_provider and fallback_reason.startswith("guardrail_precheck_"):
        return False
    if "chatgpt" in primary_provider or "openai" in primary_provider:
        return True
    if "chatgpt" in selected_reviewer or "openai" in selected_reviewer:
        return True
    return primary_status in {"timeout", "error", "failed", "unavailable"}


def _guardrail_detail_rows_from_review(review_data: dict[str, Any]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    notes: list[str] = []
    for source_key in ("reviewer_notes", "notes"):
        source = review_data.get(source_key)
        if isinstance(source, list):
            notes.extend(str(item or "").strip() for item in source if str(item or "").strip())
    passed_rows: list[tuple[str, str]] = []
    failed_rows: list[tuple[str, str]] = []
    for note in notes:
        if note.startswith("guardrail_passed="):
            raw = note.split("=", 1)[1]
            check, sep, message = raw.partition("|")
            passed_rows.append((check.strip() or "-", message.strip() or "-"))
        elif note.startswith("guardrail_failed="):
            raw = note.split("=", 1)[1]
            check, sep, message = raw.partition("|")
            failed_rows.append((check.strip() or "-", message.strip() or "-"))
    if not passed_rows:
        passed_rows = [(str(name), "-") for name in review_data.get("guardrail_checks_passed") or []]
    if not failed_rows:
        failed_rows = [(str(name), "-") for name in review_data.get("guardrail_checks_failed") or []]
    return _dedupe_guardrail_rows(failed_rows), _dedupe_guardrail_rows(passed_rows)


def _dedupe_guardrail_rows(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    deduped: dict[str, str] = {}
    ordered: list[str] = []
    for check, reason in rows:
        name = str(check or "-").strip() or "-"
        message = str(reason or "-").strip() or "-"
        if name not in deduped:
            deduped[name] = message
            ordered.append(name)
            continue
        if deduped[name] in {"", "-", "unknown"} and message not in {"", "-", "unknown"}:
            deduped[name] = message
    return [(name, deduped[name]) for name in ordered]


def _remediation_why_line(proposal: RemediationProposal) -> str:
    if proposal.action_type not in {"clear_blocking_lock", "kill_session"}:
        return proposal.reason_for_action or proposal.rationale or proposal.description
    target = proposal.target or {}
    sid = _coerce_int(target.get("sid"))
    sid_label = str(sid) if sid is not None else "unknown"
    blocked_count = _coerce_int(target.get("blocked_session_count"))
    blocked_label = str(blocked_count) if blocked_count is not None else "unknown"
    session_label = "session" if blocked_count == 1 else "sessions"
    max_wait_s = _coerce_int(target.get("max_blocked_wait_seconds"))
    wait_label = str(max_wait_s) if max_wait_s is not None else "unknown"
    object_name = str(target.get("object_name") or "").strip()
    object_owner = str(target.get("object_owner") or "").strip()
    object_label = f"{object_owner}.{object_name}" if object_owner and object_name else object_name
    object_fragment = f" on {object_label}" if object_label else ""
    return f"SID {sid_label} is blocking {blocked_label} {session_label} for {wait_label} seconds{object_fragment}."


def reviewer_display_name(provider: str | None, model: str | None = None) -> str:
    provider_text = str(provider or "").strip()
    model_text = str(model or "").strip()
    combined = f"{provider_text} {model_text}".lower()
    if "chatgpt" in combined or "openai" in combined or combined.startswith("gpt-"):
        return "ChatGPT Action Reviewer"
    if "gemini" in combined and "flash" in combined:
        return "Gemini 2.5 Flash Agent"
    if "deterministic" in combined:
        return "Deterministic Guardrail Reviewer"
    if provider_text:
        return provider_text
    return "Unknown Reviewer"


def reviewer_decision_icon(status: str | None, approved: bool | None = None) -> str:
    if approved is True:
        return "🟢"
    if approved is False:
        return "🔴"
    normalized = str(status or "").strip().lower()
    if normalized in {"approved", "allow", "allowed", "pass", "passed", "accepted"}:
        return "🟢"
    if normalized in {"rejected", "denied", "blocked", "failed", "error"}:
        return "🔴"
    if normalized in {"pending", "running", "awaiting_review", "awaiting-review"}:
        return "🟡"
    if normalized in {"skipped", "unavailable", "disabled", "not_needed", "not-needed"}:
        return "⚪"
    return "⚪"


def reviewer_state_fields(review: RemediationReview | dict[str, Any] | None) -> dict[str, Any]:
    data = _review_to_dict(review)
    provider_raw, model_raw = _review_provider_model_raw(data)
    status_raw = str(data.get("reviewer_status") or data.get("status") or "pending").strip().lower()
    selection_meta = _review_selection_meta(data)
    approved_raw = data.get("reviewer_approved")
    if approved_raw is None and "approved" in data and isinstance(data.get("approved"), bool):
        approved_raw = data.get("approved")
    approved = approved_raw if isinstance(approved_raw, bool) else _approved_from_status(status_raw)
    normalized_status = _normalized_reviewer_status(status_raw, approved)
    icon = reviewer_decision_icon(normalized_status, approved)
    reason = str(data.get("reviewer_reason") or data.get("rationale") or "").strip()
    passed_checks = [str(item) for item in data.get("guardrail_checks_passed") or [] if str(item).strip()]
    failed_checks = [str(item) for item in data.get("guardrail_checks_failed") or [] if str(item).strip()]
    guardrail_summary = str(data.get("guardrail_summary") or "").strip() or f"passed={len(passed_checks)}, failed={len(failed_checks)}"
    fallback_reason = str(selection_meta["fallback_reason"] or "").strip()
    fallback_used = selection_meta["fallback_used"]
    if fallback_used is None and fallback_reason:
        fallback_used = True
    return {
        "reviewer_provider_raw": provider_raw,
        "reviewer_model_raw": model_raw,
        "reviewer_display_name": reviewer_display_name(provider_raw, model_raw),
        "reviewer_status": normalized_status,
        "reviewer_approved": approved,
        "reviewer_icon": icon,
        "reviewer_reason": reason,
        "guardrail_summary": guardrail_summary,
        "reviewer_decision_label": _reviewer_decision_label(normalized_status, approved),
        "reviewer_decision_word": _reviewer_decision_word(normalized_status, approved),
        "reviewer_selection_requested": selection_meta["reviewer_selection_requested"],
        "openai_api_key_present": selection_meta["openai_api_key_present"],
        "selected_reviewer": selection_meta["selected_reviewer"],
        "fallback_used": fallback_used,
        "fallback_reason": fallback_reason,
        "primary_reviewer_provider": selection_meta["primary_reviewer_provider"],
        "primary_reviewer_model": selection_meta["primary_reviewer_model"],
        "primary_reviewer_status": selection_meta["primary_reviewer_status"],
        "fallback_reviewer_provider": selection_meta["fallback_reviewer_provider"],
        "fallback_reviewer_status": selection_meta["fallback_reviewer_status"],
        "effective_reviewer_provider": selection_meta["effective_reviewer_provider"],
        "effective_reviewer_status": selection_meta["effective_reviewer_status"],
        "openai_elapsed_ms": selection_meta["openai_elapsed_ms"],
        "openai_timeout_sec": selection_meta["openai_timeout_sec"],
        "guardrails_passed_count": len(passed_checks),
        "guardrails_failed_count": len(failed_checks),
    }


def _review_to_dict(review: RemediationReview | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(review, RemediationReview):
        return review.model_dump(mode="json")
    if isinstance(review, dict):
        return dict(review)
    return {}


def _review_provider_model_raw(data: dict[str, Any]) -> tuple[str | None, str | None]:
    provider = str(data.get("reviewer_provider_raw") or data.get("reviewer_provider") or "").strip() or None
    model = str(data.get("reviewer_model_raw") or data.get("reviewer_model") or "").strip() or None
    notes: list[str] = []
    for source_key in ("reviewer_notes", "notes"):
        source = data.get(source_key)
        if isinstance(source, list):
            notes.extend(str(item or "").strip() for item in source if str(item or "").strip())
    for note in notes:
        lower = note.lower()
        if lower.startswith("reviewer provider="):
            value = note.split("=", 1)[1].strip()
            if value:
                provider = value
        elif "reviewer provider is deterministic" in lower:
            provider = "deterministic"
        if lower.startswith("gemini model=") or lower.startswith("openai_model="):
            value = note.split("=", 1)[1].strip()
            if value:
                model = value
    return provider, model


def _review_selection_meta(data: dict[str, Any]) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "reviewer_selection_requested": None,
        "openai_api_key_present": None,
        "selected_reviewer": "",
        "fallback_used": None,
        "fallback_reason": "",
        "openai_model": "",
        "openai_timeout_sec": None,
        "primary_reviewer_provider": "",
        "primary_reviewer_model": "",
        "primary_reviewer_status": "",
        "fallback_reviewer_provider": "",
        "fallback_reviewer_status": "",
        "effective_reviewer_provider": "",
        "effective_reviewer_status": "",
        "openai_elapsed_ms": None,
    }
    notes: list[str] = []
    for source_key in ("reviewer_notes", "notes"):
        source = data.get(source_key)
        if isinstance(source, list):
            notes.extend(str(item or "").strip() for item in source if str(item or "").strip())
    for note in notes:
        lower = note.lower()
        if lower.startswith("reviewer_selection_requested="):
            meta["reviewer_selection_requested"] = _to_optional_bool(note.split("=", 1)[1].strip())
        elif lower.startswith("openai_api_key_present="):
            meta["openai_api_key_present"] = _to_optional_bool(note.split("=", 1)[1].strip())
        elif lower.startswith("google_api_key_present=") and meta["openai_api_key_present"] is None:
            meta["openai_api_key_present"] = _to_optional_bool(note.split("=", 1)[1].strip())
        elif lower.startswith("selected_reviewer="):
            meta["selected_reviewer"] = note.split("=", 1)[1].strip()
        elif lower.startswith("openai_model="):
            meta["openai_model"] = note.split("=", 1)[1].strip()
        elif lower.startswith("openai_timeout_sec="):
            meta["openai_timeout_sec"] = _to_optional_float(note.split("=", 1)[1].strip())
        elif lower.startswith("fallback_used="):
            meta["fallback_used"] = _to_optional_bool(note.split("=", 1)[1].strip())
        elif lower.startswith("fallback_reason="):
            meta["fallback_reason"] = note.split("=", 1)[1].strip()
        elif lower.startswith("primary_reviewer_provider="):
            meta["primary_reviewer_provider"] = note.split("=", 1)[1].strip()
        elif lower.startswith("primary_reviewer_model="):
            meta["primary_reviewer_model"] = note.split("=", 1)[1].strip()
        elif lower.startswith("primary_reviewer_status="):
            meta["primary_reviewer_status"] = note.split("=", 1)[1].strip().lower()
        elif lower.startswith("fallback_reviewer_provider="):
            meta["fallback_reviewer_provider"] = note.split("=", 1)[1].strip()
        elif lower.startswith("fallback_reviewer_status="):
            meta["fallback_reviewer_status"] = note.split("=", 1)[1].strip().lower()
        elif lower.startswith("effective_reviewer_provider="):
            meta["effective_reviewer_provider"] = note.split("=", 1)[1].strip()
        elif lower.startswith("effective_reviewer_status="):
            meta["effective_reviewer_status"] = note.split("=", 1)[1].strip().lower()
        elif lower.startswith("openai_elapsed_ms="):
            meta["openai_elapsed_ms"] = _to_optional_int(note.split("=", 1)[1].strip())
        elif lower.startswith("gemini_elapsed_ms=") and meta["openai_elapsed_ms"] is None:
            meta["openai_elapsed_ms"] = _to_optional_int(note.split("=", 1)[1].strip())
        elif lower.startswith("gemini_timeout_sec=") and meta["openai_timeout_sec"] is None:
            meta["openai_timeout_sec"] = _to_optional_float(note.split("=", 1)[1].strip())
    return meta


def _to_optional_bool(raw: str) -> bool | None:
    normalized = str(raw or "").strip().lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    return None


def _to_optional_int(raw: str) -> int | None:
    try:
        return int(float(str(raw or "").strip()))
    except Exception:
        return None


def _to_optional_float(raw: str) -> float | None:
    try:
        return float(str(raw or "").strip())
    except Exception:
        return None


def _approved_from_status(status: str) -> bool | None:
    normalized = str(status or "").strip().lower()
    if normalized in {"approved", "allow", "allowed", "pass", "passed", "accepted"}:
        return True
    if normalized in {"rejected", "denied", "blocked", "failed", "error"}:
        return False
    return None


def _normalized_reviewer_status(status: str, approved: bool | None) -> str:
    if approved is True:
        return "approved"
    if approved is False and str(status or "").strip().lower() not in {"error", "failed"}:
        return "rejected"
    normalized = str(status or "").strip().lower()
    if normalized:
        return normalized
    return "unknown"


def _reviewer_decision_label(status: str, approved: bool | None) -> str:
    if approved is True:
        return "Approved"
    if approved is False:
        if status in {"error", "failed"}:
            return "Reviewer error"
        return "Rejected"
    if status in {"pending", "running", "awaiting_review", "awaiting-review"}:
        return "Pending"
    if status in {"skipped", "unavailable", "disabled", "not_needed", "not-needed"}:
        return "Skipped"
    if status in {"error", "failed"}:
        return "Reviewer error"
    if status in {"approved", "allow", "allowed", "pass", "passed", "accepted"}:
        return "Approved"
    if status in {"rejected", "denied", "blocked"}:
        return "Rejected"
    return "Unknown"


def _reviewer_decision_word(status: str, approved: bool | None) -> str:
    label = _reviewer_decision_label(status, approved).lower()
    return "reviewer error" if label == "reviewer error" else label


def _proposal_action_id(proposal: RemediationProposal) -> str:
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        return f"{proposal.action_type}:{target.get('inst_id')}:{target.get('sid')}:{target.get('serial#')}"
    if proposal.action_type == "extend_tablespace":
        return f"{proposal.action_type}:{target.get('tablespace_name')}"
    return proposal.action_type


def _proposal_safety_level(proposal: RemediationProposal) -> str:
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        mode = str(target.get("recommendation_mode") or "").strip().lower()
        return "high_risk" if mode == "terminate" else "medium_risk"
    return "low_risk"


def _proposal_severity(proposal: RemediationProposal) -> str:
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        blocked = _coerce_int(target.get("blocked_session_count")) or 0
        wait_s = _coerce_int(target.get("max_blocked_wait_seconds")) or 0
        if blocked >= 2 or wait_s >= 300:
            return "CRITICAL"
        return "WARNING"
    if proposal.action_type == "extend_tablespace":
        pct = float(target.get("used_pct") or 0)
        return "CRITICAL" if pct >= 90.0 else "WARNING"
    return "INFO"


def _proposal_review_status(state: dict[str, Any]) -> str:
    primary_status = str(state.get("primary_reviewer_status") or "").strip().lower()
    fallback_used = bool(state.get("fallback_used"))
    fallback_status = str(state.get("fallback_reviewer_status") or "").strip().lower()
    effective_status = str(state.get("effective_reviewer_status") or state.get("reviewer_status") or "").strip().lower()
    if primary_status in {"timeout", "error"} and fallback_used:
        return "fallback_approved" if fallback_status == "approved" else "fallback_rejected"
    if primary_status in {"timeout", "error"} and not fallback_used:
        return "review_unavailable"
    if effective_status in {"approved", "rejected", "pending"}:
        return effective_status
    return state.get("reviewer_status") or "pending"


def _normalized_sql_command(sql: str | None) -> str:
    text = str(sql or "").strip()
    if not text:
        return ""
    if not text.endswith(";"):
        return f"{text};"
    return text


def _reviewer_decision_lines(state: dict[str, Any]) -> list[str]:
    primary_provider = str(state.get("primary_reviewer_provider") or state.get("reviewer_display_name") or "Unknown Reviewer")
    primary_model = str(state.get("primary_reviewer_model") or state.get("reviewer_model_raw") or state.get("openai_model") or "")
    primary_status = str(state.get("primary_reviewer_status") or state.get("reviewer_status") or "pending").strip().lower()
    fallback_used = bool(state.get("fallback_used"))
    fallback_reason = str(state.get("fallback_reason") or "")
    fallback_provider = str(state.get("fallback_reviewer_provider") or "Deterministic Guardrail Reviewer").strip()
    fallback_status = str(state.get("fallback_reviewer_status") or state.get("reviewer_status") or "").strip().lower()
    reason = str(state.get("reviewer_reason") or "").strip()
    elapsed = state.get("openai_elapsed_ms")
    timeout_sec = state.get("openai_timeout_sec")
    if primary_status in {"timeout", "error"} and fallback_used:
        icon = "🟢" if fallback_status == "approved" else "🔴"
        lines = [
            "- ⚪ ChatGPT reviewer unavailable",
            f"- Primary reviewer: {primary_provider}",
            f"- Primary reviewer model: {primary_model or '-'}",
            f"- Fallback reviewer: {fallback_provider}",
            f"- Fallback decision: {icon} {fallback_status or 'rejected'}",
            f"- Fallback reason: {reason or 'ChatGPT reviewer unavailable; deterministic fallback applied.'}",
            f"- Fallback reason code: {fallback_reason or 'openai_error'}",
        ]
        if elapsed is not None:
            lines.append(f"- OpenAI elapsed ms: {elapsed}")
        if timeout_sec is not None:
            lines.append(f"- OpenAI timeout sec: {timeout_sec}")
        return lines
    if primary_status in {"timeout", "error"} and not fallback_used:
        lines = [
            "- ⚪ ChatGPT reviewer unavailable",
            f"- Reviewer: {primary_provider}",
            f"- Reviewer model: {primary_model or '-'}",
            f"- Reason: {reason or 'Reviewer unavailable; fallback disabled.'}",
            f"- Fallback reason code: {fallback_reason or 'openai_error'}",
        ]
        if elapsed is not None:
            lines.append(f"- OpenAI elapsed ms: {elapsed}")
        if timeout_sec is not None:
            lines.append(f"- OpenAI timeout sec: {timeout_sec}")
        return lines
    decision_icon = state["reviewer_icon"]
    decision_label = str(state["reviewer_decision_label"] or "").lower()
    return [
        f"- {decision_icon} {decision_label}",
        f"- Reviewer: {primary_provider}",
        f"- Reviewer model: {primary_model or state.get('reviewer_model_raw') or '-'}",
        f"- Reason: {reason or 'No reviewer rationale provided.'}",
    ]


def _render_evidence_rows(proposal: RemediationProposal) -> list[tuple[str, str]]:
    if proposal.action_type == "extend_tablespace":
        target = proposal.target or {}
        pct_used = target.get("used_pct")
        pct_free = target.get("pct_free")
        if pct_free in (None, "") and pct_used not in (None, ""):
            try:
                pct_free = round(100.0 - float(pct_used), 4)
            except Exception:
                pct_free = None
        contents = str(target.get("contents") or "PERMANENT").upper()
        allocated_mb = target.get("total_mb") if target.get("total_mb") not in (None, "") else target.get("allocated_mb")
        free_mb = target.get("free_mb") if target.get("free_mb") not in (None, "") else target.get("free_allocated_mb")
        allocated_gb = round(float(allocated_mb) / 1024.0, 4) if allocated_mb not in (None, "") else "unknown"
        free_allocated_gb = round(float(free_mb) / 1024.0, 4) if free_mb not in (None, "") else "unknown"
        max_gb = target.get("max_gb")
        if max_gb in (None, "") and target.get("max_mb") not in (None, ""):
            max_gb = round(float(target.get("max_mb")) / 1024.0, 4)
        return [
            ("tablespace_name", str(target.get("tablespace_name") or "unknown")),
            ("pct_used", str(pct_used if pct_used not in (None, "") else "unknown")),
            ("pct_free", str(pct_free if pct_free not in (None, "") else "unknown")),
            ("tablespace_type", "temp" if contents == "TEMPORARY" else "permanent"),
            ("autoextend_status", str(target.get("autoextensible") or "unknown")),
            ("allocated_gb", str(allocated_gb)),
            ("max_gb", str(max_gb if max_gb not in (None, "") else "unknown")),
            ("free_allocated_gb", str(free_allocated_gb)),
            (
                "proposed_size_change",
                (
                    f"initial_gb={target.get('initial_gb') if target.get('initial_gb') not in (None, '') else 'unknown'}, "
                    f"next_mb={target.get('next_mb') if target.get('next_mb') not in (None, '') else 'unknown'}, "
                    f"max_gb={target.get('max_gb') if target.get('max_gb') not in (None, '') else 'unknown'}"
                ),
            ),
        ]
    if proposal.action_type not in {"clear_blocking_lock", "kill_session"}:
        return [
            ("rationale", str(proposal.reason_for_action or proposal.rationale or proposal.description)),
        ]
    target = proposal.target or {}
    blocked_details = target.get("blocked_session_details")
    blocked_sample = blocked_details[0] if isinstance(blocked_details, list) and blocked_details else {}
    blocked_sid = blocked_sample.get("sid")
    blocked_serial = blocked_sample.get("serial#")
    object_owner = str(target.get("object_owner") or "").strip()
    object_name = str(target.get("object_name") or "").strip()
    object_label = f"{object_owner}.{object_name}" if object_owner and object_name else (object_name or "unknown")
    wait_event = str(blocked_sample.get("event") or target.get("wait_event") or "unknown")
    wait_class = str(blocked_sample.get("wait_class") or target.get("wait_class") or "unknown")
    return [
        ("blocked_sid", str(blocked_sid if blocked_sid is not None else "unknown")),
        ("blocked_serial", str(blocked_serial if blocked_serial is not None else "unknown")),
        ("blocker_sid", str(target.get("sid") if target.get("sid") is not None else "unknown")),
        ("blocker_serial", str(target.get("serial#") if target.get("serial#") is not None else "unknown")),
        ("blocker_inst_id", str(target.get("inst_id") if target.get("inst_id") is not None else "unknown")),
        ("blocked_sessions", str(target.get("blocked_session_count") if target.get("blocked_session_count") is not None else "unknown")),
        ("wait_seconds", str(target.get("max_blocked_wait_seconds") if target.get("max_blocked_wait_seconds") is not None else "unknown")),
        ("wait_event", wait_event),
        ("wait_class", wait_class),
        ("blocker_user", str(target.get("username") or "-")),
        ("blocker_program", str(target.get("program") or "-")),
        ("blocker_module", str(target.get("module") or "-")),
        ("blocker_classification", str(target.get("blocker_classification") or "unknown")),
        ("idle_in_transaction", str(bool(target.get("blocker_idle_in_transaction")))),
        ("object", object_label),
        ("evidence_complete", str(bool(target.get("evidence_complete")))),
    ]


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
        review_state = reviewer_state_fields(record.review)
        rationale = record.review.rationale or "No reviewer rationale provided."
        notes = "; ".join(record.review.reviewer_notes[:2]) if record.review.reviewer_notes else "No reviewer notes."
        passed_count = int(review_state.get("guardrails_passed_count") or 0)
        failed_count = int(review_state.get("guardrails_failed_count") or 0)
        status_word = "approved" if str(record.review.status).lower() == "approved" else "rejected"
        guardrail_icon = "🟢" if status_word == "approved" else "🔴"
        review_label = f"{guardrail_icon} Guardrails {status_word}"
        lines.append(
            f"- {icon} {record.created_at} — {record.proposal.title} — "
            f"guardrails={review_label} ({passed_count} passed/{failed_count} failed) — execution={record.execution.status} "
            f"(details: {rationale}; {notes})"
        )
    return "\n".join(lines)
