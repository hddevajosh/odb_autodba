from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from odb_autodba.models.schemas import (
    HealthIssue,
    HealthSnapshot,
    HistoryContext,
    OraclePlannerMemoryRecord,
    RecurringIssueIndexRecord,
    TraceEvidenceChunk,
    TraceHealthRunRecord,
)
from odb_autodba.utils.env_loader import load_project_dotenv


PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNS_ROOT = PACKAGE_ROOT / "runs"
DEFAULT_TRACES_ROOT = DEFAULT_RUNS_ROOT / "traces"
DEFAULT_INDEXES_ROOT = DEFAULT_RUNS_ROOT / "indexes"


def traces_root() -> Path:
    load_project_dotenv()
    configured = os.getenv("ODB_AUTODBA_TRACE_DIR") or os.getenv("TRACE_DIR")
    root = Path(configured) if configured else DEFAULT_TRACES_ROOT
    if not root.is_absolute():
        root = Path.cwd() / root
    return root


def indexes_root() -> Path:
    load_project_dotenv()
    configured = os.getenv("ODB_AUTODBA_HISTORY_INDEX_DIR") or os.getenv("PLANNER_HISTORY_INDEX_DIR")
    root = Path(configured) if configured else DEFAULT_INDEXES_ROOT
    if not root.is_absolute():
        root = Path.cwd() / root
    return root


def ensure_runtime_dirs() -> None:
    traces_root().mkdir(parents=True, exist_ok=True)
    indexes_root().mkdir(parents=True, exist_ok=True)


def health_run_trace_path() -> Path:
    return traces_root() / "health_runs.jsonl"


def recurring_issue_index_path() -> Path:
    return indexes_root() / "recurring_issues.jsonl"


def trace_chunk_index_path() -> Path:
    return indexes_root() / "trace_chunks.jsonl"


def database_behavior_profile_path() -> Path:
    return indexes_root() / "database_behavior_profiles.jsonl"


def history_indexing_path() -> Path:
    load_project_dotenv()
    configured = os.getenv("ODB_AUTODBA_HISTORY_INDEX_FILE") or os.getenv("PLANNER_HISTORY_INDEX_FILE")
    if configured:
        path = Path(configured)
        if not path.is_absolute():
            path = Path.cwd() / path
        return path
    return indexes_root() / "history_indexing.jsonl"


def history_data_source_paths() -> dict[str, Path]:
    return {
        "health_runs": health_run_trace_path(),
        "trace_chunks": trace_chunk_index_path(),
        "recurring_issues": recurring_issue_index_path(),
        "database_behavior_profiles": database_behavior_profile_path(),
        "history_indexing": history_indexing_path(),
    }


def health_run_trace_file_path(*, recorded_at: datetime, database_name: str) -> Path:
    stamp = recorded_at.strftime("%Y%m%dT%H%M%S%fZ")
    safe_db = _safe_slug(database_name or "database")
    return traces_root() / f"health_run_{stamp}_{safe_db}.json"


def append_health_run_trace(
    snapshot_summary: dict[str, Any] | None = None,
    *,
    snapshot: HealthSnapshot | None = None,
    report_markdown: str | None = None,
    history_context: HistoryContext | None = None,
    rebuild_artifacts: bool = True,
) -> TraceHealthRunRecord:
    """Persist a full Oracle health trace and append a compact JSONL summary.

    The first positional argument is kept for compatibility with the previous
    summary-only writer. New call sites should pass ``snapshot`` and
    ``report_markdown`` so each health run has a full JSON trace.
    """

    ensure_runtime_dirs()
    now = datetime.now(UTC)
    summary = dict(snapshot_summary or {})
    if snapshot is not None:
        summary = _summary_from_snapshot(snapshot, summary)

    database_name = str(summary.get("database_name") or _snapshot_database_name(snapshot) or "database")
    run_id = str(summary.get("run_id") or f"odb_autodba_{now.strftime('%Y%m%d_%H%M%S')}")
    completed_at = str(summary.get("completed_at") or (snapshot.generated_at if snapshot else now.isoformat()))
    overall_status = _overall_status(summary, snapshot)
    trace_file = health_run_trace_file_path(recorded_at=now, database_name=database_name)

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
    _append_jsonl(health_run_trace_path(), _compact_record(record))

    if rebuild_artifacts:
        try:
            from odb_autodba.rag.indexer import rebuild_planner_memory_artifacts

            rebuild_planner_memory_artifacts(database_name=database_name)
        except Exception:
            pass
    return record


def read_health_run_traces(
    *,
    database_name: str | None = None,
    limit: int | None = None,
    completed_after: datetime | None = None,
    completed_before: datetime | None = None,
) -> list[TraceHealthRunRecord]:
    ensure_runtime_dirs()
    records: list[TraceHealthRunRecord] = []
    seen: set[str] = set()
    full_files = sorted(traces_root().glob("health_run_*.json"), key=lambda item: item.name, reverse=True)
    for path in full_files:
        payload = _read_json(path)
        if not isinstance(payload, dict):
            continue
        payload.setdefault("trace_path", str(path))
        try:
            record = TraceHealthRunRecord.model_validate(payload)
        except Exception:
            continue
        if not _trace_matches(record, database_name, completed_after, completed_before):
            continue
        seen.add(record.run_id or record.trace_path or str(path))
        records.append(record)

    if health_run_trace_path().exists():
        for payload in _read_jsonl(health_run_trace_path()):
            try:
                record = TraceHealthRunRecord.model_validate(_expand_compact_record(payload))
            except Exception:
                continue
            key = record.run_id or record.trace_path or record.completed_at
            if key in seen:
                continue
            if not _trace_matches(record, database_name, completed_after, completed_before):
                continue
            seen.add(key)
            records.append(record)

    records.sort(key=lambda item: item.recorded_at, reverse=True)
    return records[:limit] if limit is not None else records


def read_health_run_summaries(
    *,
    database_name: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    ensure_runtime_dirs()
    rows = _read_jsonl(health_run_trace_path()) if health_run_trace_path().exists() else []
    if not rows:
        rows = [_compact_record(record) for record in read_health_run_traces(database_name=database_name, limit=limit)]
    if database_name:
        rows = [row for row in rows if row.get("database_name") == database_name]
    rows.sort(key=lambda item: str(item.get("completed_at") or item.get("recorded_at") or ""), reverse=True)
    return rows[:limit] if limit is not None else rows


def write_trace_evidence_chunks(records: list[TraceEvidenceChunk]) -> None:
    _write_jsonl_file(trace_chunk_index_path(), [record.model_dump(mode="json") for record in records])


def read_trace_evidence_chunks(
    *,
    database_name: str | None = None,
    completed_after: datetime | None = None,
    completed_before: datetime | None = None,
    limit: int | None = None,
) -> list[TraceEvidenceChunk]:
    rows = []
    for payload in _read_jsonl(trace_chunk_index_path()):
        try:
            record = TraceEvidenceChunk.model_validate(payload)
        except Exception:
            continue
        if database_name and record.database_name != database_name:
            continue
        recorded_at = _parse_dt(record.recorded_at)
        if completed_after and recorded_at and recorded_at < completed_after:
            continue
        if completed_before and recorded_at and recorded_at >= completed_before:
            continue
        rows.append(record)
    rows.sort(key=lambda item: (item.recorded_at, item.chunk_id), reverse=True)
    return rows[:limit] if limit is not None else rows


def write_recurring_issue_index(records: list[RecurringIssueIndexRecord]) -> None:
    _write_jsonl_file(recurring_issue_index_path(), [record.model_dump(mode="json") for record in records])


def read_recurring_issue_index(
    *,
    database_name: str | None = None,
    limit: int | None = None,
) -> list[RecurringIssueIndexRecord]:
    rows = []
    for payload in _read_jsonl(recurring_issue_index_path()):
        try:
            record = RecurringIssueIndexRecord.model_validate(payload)
        except Exception:
            continue
        if database_name and record.database_name != database_name:
            continue
        rows.append(record)
    rows.sort(key=lambda item: (item.run_count, item.unhealthy_run_count, item.last_seen), reverse=True)
    return rows[:limit] if limit is not None else rows


def write_database_planner_memory(records: list[OraclePlannerMemoryRecord]) -> None:
    _write_jsonl_file(database_behavior_profile_path(), [record.model_dump(mode="json") for record in records])


def read_database_planner_memory(
    *,
    database_name: str | None = None,
    limit: int | None = None,
) -> list[OraclePlannerMemoryRecord]:
    rows = []
    for payload in _read_jsonl(database_behavior_profile_path()):
        try:
            record = OraclePlannerMemoryRecord.model_validate(payload)
        except Exception:
            continue
        if database_name and record.database_name != database_name:
            continue
        rows.append(record)
    rows.sort(key=lambda item: item.latest_trace_recorded_at or item.generated_at, reverse=True)
    return rows[:limit] if limit is not None else rows


def write_history_index_entries(entries: list[dict[str, Any]]) -> None:
    _write_jsonl_file(history_indexing_path(), entries)


def read_history_index_entries(
    *,
    database_name: str | None = None,
    limit: int | None = None,
    entry_type: str | None = None,
) -> list[dict[str, Any]]:
    rows = []
    for payload in _read_jsonl(history_indexing_path()):
        if entry_type and payload.get("entry_type") != entry_type:
            continue
        candidate = payload.get("payload") if isinstance(payload.get("payload"), dict) else payload
        if database_name and candidate.get("database_name") != database_name:
            continue
        rows.append(payload)
    rows.sort(key=lambda item: str((item.get("payload") or item).get("completed_at") or ""), reverse=True)
    return rows[:limit] if limit is not None else rows


def _summary_from_snapshot(snapshot: HealthSnapshot, base: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(base.get("metrics") or {})
    metrics.update(_snapshot_metrics(snapshot))
    issues = [issue.model_dump(mode="json") for issue in snapshot.issues]
    return {
        **base,
        "completed_at": base.get("completed_at") or snapshot.generated_at,
        "database_name": base.get("database_name") or _snapshot_database_name(snapshot),
        "database_host": snapshot.instance_info.host_name,
        "instance_name": snapshot.instance_info.instance_name,
        "db_unique_name": snapshot.instance_info.db_unique_name,
        "database_role": snapshot.instance_info.database_role,
        "open_mode": snapshot.instance_info.open_mode,
        "summary": base.get("summary") or f"Oracle health check with {len(snapshot.issues)} issue(s).",
        "metrics": metrics,
        "issues": issues,
    }


def _snapshot_metrics(snapshot: HealthSnapshot) -> dict[str, Any]:
    hottest = snapshot.tablespaces[0] if snapshot.tablespaces else None
    host = snapshot.host_snapshot
    docker_stats = host.docker_stats if host else {}
    raw = snapshot.raw_evidence or {}
    return {
        "active_sessions": snapshot.session_summary.active_sessions,
        "total_sessions": snapshot.session_summary.total_sessions,
        "blocking_count": len(snapshot.blocking_chains),
        "hottest_tablespace": hottest.tablespace_name if hottest else None,
        "hottest_tablespace_pct": hottest.used_pct if hottest else None,
        "temp_usage_pct": raw.get("temp_pct"),
        "alert_log_count": len(raw.get("alert_log") or []),
        "listener_error_count": len((raw.get("listener_errors") or {}).get("errors") or []),
        "invalid_object_count": len(raw.get("invalid_objects") or []),
        "plan_churn_count": len(raw.get("plan_churn") or []),
        "stale_stats_count": len(raw.get("stale_stats") or []),
        "redo_switch_count": (raw.get("redo") or {}).get("count"),
        "redo_per_hour": (raw.get("redo") or {}).get("rate_per_hr"),
        "fra_pct": raw.get("fra_pct"),
        "top_cpu_sql_id": snapshot.top_sql_by_cpu[0].sql_id if snapshot.top_sql_by_cpu else None,
        "top_cpu_sql_cpu_s": snapshot.top_sql_by_cpu[0].cpu_s if snapshot.top_sql_by_cpu else 0,
        "top_elapsed_sql_id": snapshot.top_sql_by_elapsed[0].sql_id if snapshot.top_sql_by_elapsed else None,
        "top_elapsed_sql_elapsed_s": snapshot.top_sql_by_elapsed[0].elapsed_s if snapshot.top_sql_by_elapsed else 0,
        "critical_count": sum(1 for issue in snapshot.issues if issue.severity == "CRITICAL"),
        "warning_count": sum(1 for issue in snapshot.issues if issue.severity == "WARNING"),
        "host_cpu_pct": host.cpu_pct if host else None,
        "host_memory_pct": host.memory_pct if host else None,
        "host_swap_pct": host.swap_pct if host else None,
        "container_cpu_pct": docker_stats.get("cpu_pct") if docker_stats else None,
        "container_memory_pct": docker_stats.get("memory_pct") if docker_stats else None,
    }


def _overall_status(summary: dict[str, Any], snapshot: HealthSnapshot | None) -> str:
    explicit = str(summary.get("overall_status") or "").upper()
    if explicit in {"OK", "WARNING", "CRITICAL", "INFO"}:
        return explicit
    issues = snapshot.issues if snapshot else _coerce_issues(summary.get("issues") or [])
    if any(issue.severity == "CRITICAL" for issue in issues):
        return "CRITICAL"
    if any(issue.severity == "WARNING" for issue in issues):
        return "WARNING"
    return "OK"


def _snapshot_database_name(snapshot: HealthSnapshot | None) -> str | None:
    if snapshot is None:
        return None
    return snapshot.instance_info.db_name or snapshot.instance_info.instance_name or snapshot.instance_info.db_unique_name


def _coerce_issues(items: Any) -> list[HealthIssue]:
    out: list[HealthIssue] = []
    for item in items or []:
        try:
            out.append(item if isinstance(item, HealthIssue) else HealthIssue.model_validate(item))
        except Exception:
            continue
    return out


def _compact_record(record: TraceHealthRunRecord) -> dict[str, Any]:
    trace = record.trace_path or ""
    return {
        "trace_version": record.trace_version,
        "run_id": record.run_id,
        "recorded_at": record.recorded_at,
        "completed_at": record.completed_at,
        "database_name": record.database_name,
        "database_host": record.database_host,
        "instance_name": record.instance_name,
        "trace_path": trace,
        "overall_status": record.overall_status,
        "summary": record.summary,
        "metrics": record.metrics,
        "issues": [issue.model_dump(mode="json") for issue in record.issues],
    }


def _expand_compact_record(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "trace_version": payload.get("trace_version") or "1",
        "run_id": payload.get("run_id") or "",
        "recorded_at": payload.get("recorded_at") or payload.get("completed_at") or datetime.now(UTC).isoformat(),
        "completed_at": payload.get("completed_at") or payload.get("recorded_at") or "",
        "database_name": payload.get("database_name") or "database",
        "database_host": payload.get("database_host"),
        "instance_name": payload.get("instance_name"),
        "trace_path": payload.get("trace_path"),
        "overall_status": payload.get("overall_status") or "INFO",
        "summary": payload.get("summary") or "",
        "metrics": payload.get("metrics") or {},
        "issues": payload.get("issues") or [],
    }


def _history_context_summary(history_context: HistoryContext | None) -> dict[str, Any]:
    if history_context is None:
        return {}
    return {
        "latest_run": history_context.latest_run.model_dump(mode="json") if history_context.latest_run else None,
        "previous_run": history_context.previous_run.model_dump(mode="json") if history_context.previous_run else None,
        "recent_run_count": len(history_context.recent_runs),
        "recurring_finding_count": len(history_context.recurring_findings),
        "trend_count": len(history_context.trend_summaries),
    }


def _trace_matches(
    record: TraceHealthRunRecord,
    database_name: str | None,
    completed_after: datetime | None,
    completed_before: datetime | None,
) -> bool:
    if database_name and record.database_name not in {database_name, "database", ""}:
        return False
    completed_at = _parse_dt(record.completed_at or record.recorded_at)
    if completed_after and completed_at and completed_at < completed_after:
        return False
    if completed_before and completed_at and completed_at >= completed_before:
        return False
    return True


def _safe_slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_") or "database"


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2, default=str), encoding="utf-8")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")


def _write_jsonl_file(path: Path, payloads: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for payload in payloads:
            handle.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    return rows
