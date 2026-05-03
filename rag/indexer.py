from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import mean
from typing import Any

from odb_autodba.models.schemas import (
    OracleDatabaseBehaviorProfile,
    OraclePlannerMemoryRecord,
    RecurringIssueIndexRecord,
    TraceEvidenceChunk,
    TraceHealthRunRecord,
)
from odb_autodba.rag.trace_store import (
    history_indexing_path,
    read_health_run_traces,
    recurring_issue_index_path,
    trace_chunk_index_path,
    write_database_planner_memory,
    write_history_index_entries,
    write_recurring_issue_index,
    write_trace_evidence_chunks,
)


def rebuild_history_index() -> dict[str, Any]:
    artifacts = rebuild_planner_memory_artifacts()
    return {
        "record_count": len(artifacts.get("history_indexing") or []),
        "trace_chunk_count": len(artifacts.get("trace_chunks") or []),
        "recurring_issue_count": len(artifacts.get("recurring_issue_index") or []),
    }


def get_index_status(db_key: str, *, freshness_tolerance_seconds: int = 120) -> dict[str, Any]:
    files = {
        "trace_chunks": trace_chunk_index_path(db_key=db_key),
        "recurring_issues": recurring_issue_index_path(db_key=db_key),
        "history_indexing": history_indexing_path(db_key=db_key),
    }
    exists_map = {name: path.exists() for name, path in files.items()}
    available = all(exists_map.values())
    required_paths = [path for path in files.values() if path.exists()]
    latest_index_timestamp = _latest_file_mtime(required_paths)
    traces = read_health_run_traces(limit=1, db_key=db_key)
    latest_trace_timestamp = None
    if traces:
        latest_trace_timestamp = _to_datetime(traces[0].recorded_at) or _to_datetime(traces[0].completed_at)

    fresh = False
    if available:
        if latest_trace_timestamp is None:
            fresh = True
        elif latest_index_timestamp is not None:
            tolerance = freshness_tolerance_seconds if freshness_tolerance_seconds >= 0 else 0
            fresh = latest_trace_timestamp <= (latest_index_timestamp + timedelta(seconds=tolerance))

    return {
        "available": available,
        "fresh": fresh,
        "last_updated": latest_index_timestamp.isoformat() if latest_index_timestamp else None,
        "latest_trace_timestamp": latest_trace_timestamp.isoformat() if latest_trace_timestamp else None,
        "files": {name: str(path) for name, path in files.items()},
        "exists": exists_map,
    }


def rebuild_planner_memory_artifacts(*, database_name: str | None = None, db_key: str | None = None) -> dict[str, Any]:
    recurring = rebuild_recurring_issue_index(database_name=database_name, db_key=db_key)
    chunks = rebuild_trace_chunk_index(database_name=database_name, db_key=db_key)
    memory = rebuild_database_planner_memory(database_name=database_name, db_key=db_key)
    history_entries = rebuild_history_index_entries(database_name=database_name, db_key=db_key)
    return {
        "recurring_issue_index": recurring,
        "trace_chunks": chunks,
        "database_planner_memory": memory,
        "history_indexing": history_entries,
    }


def rebuild_trace_chunk_index(*, database_name: str | None = None, db_key: str | None = None) -> list[TraceEvidenceChunk]:
    traces = read_health_run_traces(database_name=database_name, limit=None, db_key=db_key)
    chunks: list[TraceEvidenceChunk] = []
    for trace in traces:
        chunks.extend(_chunks_for_trace(trace))
    chunks.sort(key=lambda item: (item.recorded_at, item.chunk_id), reverse=True)
    write_trace_evidence_chunks(chunks, db_key=db_key)
    return chunks


def rebuild_recurring_issue_index(*, database_name: str | None = None, db_key: str | None = None) -> list[RecurringIssueIndexRecord]:
    traces = read_health_run_traces(database_name=database_name, limit=None, db_key=db_key)
    grouped: dict[str, dict[str, Any]] = {}
    for trace in traces:
        for item in _issue_patterns(trace):
            fingerprint = item["fingerprint"]
            entry = grouped.setdefault(
                fingerprint,
                {
                    "fingerprint": fingerprint,
                    "database_name": trace.database_name,
                    "category": item["category"],
                    "title": item["title"],
                    "severity": item["severity"],
                    "first_seen": trace.completed_at,
                    "last_seen": trace.completed_at,
                    "run_ids": set(),
                    "unhealthy_run_ids": set(),
                    "sample_evidence": [],
                    "latest_summary": item["summary"],
                    "trace_paths": [],
                },
            )
            entry["first_seen"] = min(str(entry["first_seen"]), trace.completed_at)
            entry["last_seen"] = max(str(entry["last_seen"]), trace.completed_at)
            entry["severity"] = _worst_status(str(entry["severity"]), str(item["severity"]))
            entry["latest_summary"] = item["summary"]
            entry["run_ids"].add(trace.run_id)
            if trace.overall_status != "OK" or item["severity"] in {"WARNING", "CRITICAL"}:
                entry["unhealthy_run_ids"].add(trace.run_id)
            if trace.trace_path and trace.trace_path not in entry["trace_paths"]:
                entry["trace_paths"].append(trace.trace_path)
            for evidence in item["evidence"]:
                if evidence and evidence not in entry["sample_evidence"]:
                    entry["sample_evidence"].append(evidence)
                if len(entry["sample_evidence"]) >= 5:
                    break

    records = [
        RecurringIssueIndexRecord(
            fingerprint=str(entry["fingerprint"]),
            database_name=str(entry["database_name"]),
            category=str(entry["category"]),
            title=str(entry["title"]),
            severity=entry["severity"],
            first_seen=str(entry["first_seen"]),
            last_seen=str(entry["last_seen"]),
            run_count=len(entry["run_ids"]),
            unhealthy_run_count=len(entry["unhealthy_run_ids"]),
            sample_evidence=list(entry["sample_evidence"])[:5],
            latest_summary=str(entry["latest_summary"] or ""),
            trace_paths=list(entry["trace_paths"])[:5],
        )
        for entry in grouped.values()
    ]
    records.sort(key=lambda item: (item.run_count, item.unhealthy_run_count, item.last_seen), reverse=True)
    write_recurring_issue_index(records, db_key=db_key)
    return records


def rebuild_database_planner_memory(*, database_name: str | None = None, db_key: str | None = None) -> list[OraclePlannerMemoryRecord]:
    traces = read_health_run_traces(database_name=database_name, limit=None, db_key=db_key)
    grouped: dict[str, list[TraceHealthRunRecord]] = defaultdict(list)
    for trace in traces:
        grouped[trace.database_name].append(trace)

    records: list[OraclePlannerMemoryRecord] = []
    for db_name, db_traces in grouped.items():
        sorted_traces = sorted(db_traces, key=lambda item: item.completed_at)
        profile = _behavior_profile(db_name, sorted_traces)
        records.append(
            OraclePlannerMemoryRecord(
                generated_at=datetime.now(UTC).isoformat(),
                database_name=db_name,
                source_trace_count=len(sorted_traces),
                latest_trace_recorded_at=sorted_traces[-1].completed_at if sorted_traces else None,
                database_behavior_profile=profile,
            )
        )
    records.sort(key=lambda item: item.latest_trace_recorded_at or item.generated_at, reverse=True)
    write_database_planner_memory(records, db_key=db_key)
    return records


def rebuild_history_index_entries(*, database_name: str | None = None, db_key: str | None = None) -> list[dict[str, Any]]:
    traces = read_health_run_traces(database_name=database_name, limit=None, db_key=db_key)
    entries: list[dict[str, Any]] = []
    for trace in traces:
        entries.append(
            {
                "entry_type": "run_history",
                "payload": {
                    "run_id": trace.run_id,
                    "completed_at": trace.completed_at,
                    "recorded_at": trace.recorded_at,
                    "database_name": trace.database_name,
                    "overall_status": trace.overall_status,
                    "summary": trace.summary,
                    "trace_path": trace.trace_path,
                    "metrics": trace.metrics,
                    "issues": [issue.model_dump(mode="json") for issue in trace.issues],
                },
            }
        )
    for issue in rebuild_recurring_issue_index(database_name=database_name, db_key=db_key):
        entries.append({"entry_type": "recurring_issue", "payload": issue.model_dump(mode="json")})
    entries.sort(key=lambda item: str((item.get("payload") or {}).get("completed_at") or ""), reverse=True)
    write_history_index_entries(entries, db_key=db_key)
    return entries


def _chunks_for_trace(trace: TraceHealthRunRecord) -> list[TraceEvidenceChunk]:
    chunks: list[TraceEvidenceChunk] = []

    def add(category: str, title: str, summary: str, facts: list[str], severity: str = "INFO", metric_names: list[str] | None = None, sql_ids: list[str] | None = None) -> None:
        chunks.append(
            TraceEvidenceChunk(
                chunk_id=_chunk_id(trace, category, title),
                trace_path=trace.trace_path,
                recorded_at=trace.completed_at,
                database_name=trace.database_name,
                run_overall_status=trace.overall_status,
                category=category,
                title=title,
                summary=summary,
                facts=[fact for fact in facts if fact][:8],
                severity=severity if severity in {"OK", "WARNING", "CRITICAL", "INFO"} else "INFO",
                metric_names=metric_names or [],
                sql_ids=sql_ids or [],
            )
        )

    add(
        "summary",
        "Oracle health run summary",
        trace.summary,
        [f"Overall status: {trace.overall_status}", f"Database: {trace.database_name}"],
        trace.overall_status,
    )
    for issue in trace.issues:
        add(issue.category or "issue", issue.title, issue.description, issue.evidence + [issue.recommendation], issue.severity)
    for item in trace.actionable_items:
        add(item.category or "actionable", item.title, item.detail, item.evidence + [item.recommendation], item.severity)
    for section in trace.health_sections:
        status = section.status if section.status in {"OK", "WARNING", "CRITICAL", "INFO"} else "INFO"
        facts = list(section.notes[:4])
        for row in section.rows[:3]:
            facts.append(_row_fact(row))
        add(_category_for_section(section.name), section.name, section.summary, facts, status)

    metrics = trace.metrics
    sql_ids = [str(metrics[key]) for key in ("top_cpu_sql_id", "top_elapsed_sql_id") if metrics.get(key)]
    add(
        "metrics",
        "Oracle metric snapshot",
        "Key Oracle health metrics captured for trend analysis.",
        [f"{key}={value}" for key, value in sorted(metrics.items()) if value is not None][:12],
        trace.overall_status,
        metric_names=list(metrics.keys()),
        sql_ids=sql_ids,
    )
    return chunks


def _issue_patterns(trace: TraceHealthRunRecord) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for issue in trace.issues:
        items.append(
            {
                "fingerprint": _fingerprint(trace.database_name, issue.category, issue.title),
                "category": issue.category or "issue",
                "title": issue.title,
                "severity": issue.severity,
                "summary": issue.description,
                "evidence": issue.evidence + ([issue.recommendation] if issue.recommendation else []),
            }
        )
    metrics = trace.metrics
    top_sql = metrics.get("top_cpu_sql_id")
    if top_sql:
        items.append(
            {
                "fingerprint": _fingerprint(trace.database_name, "sql", str(top_sql)),
                "category": "sql",
                "title": f"Top CPU SQL_ID {top_sql}",
                "severity": "WARNING" if _to_float(metrics.get("top_cpu_sql_cpu_s")) else "INFO",
                "summary": f"SQL_ID {top_sql} appeared as top CPU SQL.",
                "evidence": [f"cpu_s={metrics.get('top_cpu_sql_cpu_s')}", f"elapsed_s={metrics.get('top_elapsed_sql_elapsed_s')}"],
            }
        )
    tablespace = metrics.get("hottest_tablespace")
    if tablespace:
        items.append(
            {
                "fingerprint": _fingerprint(trace.database_name, "tablespace", str(tablespace)),
                "category": "tablespace",
                "title": f"Highest tablespace usage on {tablespace}",
                "severity": "WARNING" if (_to_float(metrics.get("hottest_tablespace_pct")) or 0) >= 80 else "INFO",
                "summary": f"{tablespace} was the highest usage tablespace.",
                "evidence": [f"used_pct={metrics.get('hottest_tablespace_pct')}"],
            }
        )
    return items


def _behavior_profile(database_name: str, traces: list[TraceHealthRunRecord]) -> OracleDatabaseBehaviorProfile:
    statuses = Counter(trace.overall_status for trace in traces)
    metric_baselines = _metric_baselines_from_traces(traces)

    issue_counter = Counter(issue.title for trace in traces for issue in trace.issues)
    sql_counter = Counter(str(trace.metrics.get("top_cpu_sql_id")) for trace in traces if trace.metrics.get("top_cpu_sql_id"))
    host_lines = _metric_profile_lines(metric_baselines, ("host_cpu_pct", "host_memory_pct", "container_cpu_pct", "container_memory_pct"))
    storage_lines = _metric_profile_lines(metric_baselines, ("hottest_tablespace_pct", "temp_usage_pct", "fra_pct"))
    return OracleDatabaseBehaviorProfile(
        database_name=database_name,
        sampled_run_count=len(traces),
        healthy_run_count=statuses.get("OK", 0),
        warning_run_count=statuses.get("WARNING", 0),
        critical_run_count=statuses.get("CRITICAL", 0),
        latest_recorded_at=traces[-1].completed_at if traces else None,
        metric_baselines=metric_baselines,
        recurring_issue_summary=[f"{title}: {count} run(s)" for title, count in issue_counter.most_common(8) if count >= 2],
        sql_behavior_summary=[f"SQL_ID {sql_id}: top CPU in {count} run(s)" for sql_id, count in sql_counter.most_common(5) if sql_id != "None"],
        host_behavior_summary=host_lines,
        storage_behavior_summary=storage_lines,
    )


def _metric_profile_lines(baselines: dict[str, dict[str, float | int | None]], keys: tuple[str, ...]) -> list[str]:
    lines = []
    for key in keys:
        payload = baselines.get(key)
        if payload:
            lines.append(
                f"{key}: avg_normal={payload.get('average_normal')}, recent_avg={payload.get('recent_average')}, "
                f"latest={payload.get('latest')}, state={payload.get('state')}"
            )
    return lines


def _metric_baselines_from_traces(traces: list[TraceHealthRunRecord]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[tuple[datetime | None, float, str]]] = defaultdict(list)
    for trace in traces:
        recorded_at = _to_datetime(trace.completed_at) or _to_datetime(trace.recorded_at)
        status = str(trace.overall_status or "INFO").upper()
        for metric_name, raw_value in (trace.metrics or {}).items():
            numeric_value = _to_float(raw_value)
            if numeric_value is None:
                continue
            grouped[str(metric_name)].append((recorded_at, numeric_value, status))

    baselines: dict[str, dict[str, Any]] = {}
    for metric_name, points in grouped.items():
        ordered = sorted(points, key=lambda item: item[0] or datetime.min.replace(tzinfo=UTC))
        values = [value for _, value, _ in ordered]
        if not values:
            continue
        current_value = values[-1]
        recent_values = values[-5:]
        previous_values = values[:-1]
        normal_points = [value for _, value, status in ordered if status == "OK"]
        if len(normal_points) < 2:
            normal_points = previous_values or values
        recent_normal = normal_points[-5:] if normal_points else []
        average_normal = round(mean(recent_normal), 3) if recent_normal else None
        recent_average = round(mean(recent_values), 3) if recent_values else None
        pressure_threshold = _pressure_threshold_for_metric(metric_name)
        pressure_runs = sum(1 for value in values if value >= pressure_threshold)
        stable_runs = max(len(values) - pressure_runs, 0)
        first_seen = ordered[0][0].isoformat() if ordered[0][0] else None
        last_seen = ordered[-1][0].isoformat() if ordered[-1][0] else None
        baselines[metric_name] = {
            "sample_count": len(values),
            "average_normal": average_normal,
            "recent_average": recent_average,
            "min": round(min(values), 3),
            "max": round(max(values), 3),
            "latest": round(current_value, 3),
            "state": _classify_metric_state(
                metric_name=metric_name,
                latest=current_value,
                average_normal=average_normal,
                pressure_threshold=pressure_threshold,
            ),
            "pressure_run_count": pressure_runs,
            "stable_run_count": stable_runs,
            "recent_values": [round(value, 3) for value in recent_values],
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
    return baselines


def _pressure_threshold_for_metric(metric_name: str) -> float:
    key = str(metric_name or "").lower()
    if key.endswith("_pct"):
        return 85.0
    if key.endswith("_count"):
        return 1.0
    if key.endswith("_cpu_s") or key.endswith("_elapsed_s"):
        return 120.0
    if any(token in key for token in ("latency", "wait")):
        return 1.0
    return 1.0


def _classify_metric_state(
    *,
    metric_name: str,
    latest: float,
    average_normal: float | None,
    pressure_threshold: float,
) -> str:
    if latest is None:
        return "unknown"
    if latest >= pressure_threshold:
        return "pressured"
    if average_normal is None:
        return "unknown"
    if average_normal == 0:
        return "elevated" if latest > 0 else "normal"
    if latest >= average_normal * 1.2:
        return "elevated"
    return "normal"


def _category_for_section(name: str) -> str:
    lowered = name.lower()
    if "alert" in lowered or "listener" in lowered:
        return "errors"
    if "tablespace" in lowered or "temp" in lowered or "fra" in lowered or "archive" in lowered:
        return "storage"
    if "sql" in lowered or "performance" in lowered or "wait" in lowered or "awr" in lowered:
        return "sql"
    if "host" in lowered or "memory" in lowered:
        return "host"
    if "lock" in lowered:
        return "blocking"
    if "backup" in lowered or "rman" in lowered:
        return "backup"
    return "oracle"


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _latest_file_mtime(paths: list[Path]) -> datetime | None:
    latest: datetime | None = None
    for path in paths:
        try:
            value = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        except Exception:
            continue
        if latest is None or value > latest:
            latest = value
    return latest


def _row_fact(row: dict[str, Any]) -> str:
    parts = [f"{key}={value}" for key, value in row.items() if value not in (None, "")]
    return ", ".join(parts[:8])


def _fingerprint(*parts: str) -> str:
    basis = "|".join(str(part).strip().lower() for part in parts if str(part).strip())
    digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]
    return f"oracle:{digest}"


def _chunk_id(trace: TraceHealthRunRecord, category: str, title: str) -> str:
    return _fingerprint(trace.run_id, category, title)


def _to_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _worst_status(left: str, right: str) -> str:
    rank = {"OK": 0, "INFO": 0, "WARNING": 1, "CRITICAL": 2}
    return left if rank.get(left, 0) >= rank.get(right, 0) else right
