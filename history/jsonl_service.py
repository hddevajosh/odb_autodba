from __future__ import annotations

import json
import os
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from odb_autodba.db.awr_checks import (
    build_awr_state_diff,
    get_awr_report_text_summary_for_window,
    get_awr_capabilities,
    map_run_pair_to_awr_windows,
)
from odb_autodba.models.schemas import (
    AwrFallbackInfo,
    AwrStateDiff,
    HealthIssue,
    HistoricalComparisonWindow,
    HistoricalConfidence,
    HistoricalEventTimelineEntry,
    HistoricalIssueState,
    HistoricalLearningFeatures,
    HistoricalRecoveryDriver,
    HistoricalResidualDriver,
    HistoricalRun,
    HistoricalSectionNaming,
    HistoricalStateTransition,
    HistoricalTransitionDriver,
    HistoricalTransitionOutcome,
    HistoricalTransitionSummary,
    HistoryContext,
    LearningFeatureVector,
    MetricDelta,
    MetricTrendSummary,
    OraclePlannerMemoryRecord,
    RecurringIssueIndexRecord,
    StateFingerprint,
    TransitionDriver,
    TransitionIssueClassification,
    TraceEvidenceChunk,
    TraceHealthRunRecord,
)
from odb_autodba.rag.indexer import rebuild_planner_memory_artifacts
from odb_autodba.rag.trace_store import (
    health_run_trace_path,
    history_data_source_paths,
    read_database_planner_memory,
    read_health_run_summaries,
    read_history_index_entries,
    read_recurring_issue_index,
    read_health_run_traces,
    read_trace_evidence_chunks,
)


TRACE_DIR = health_run_trace_path().parent
HEALTH_RUNS_FILE = health_run_trace_path()


DEFAULT_TREND_METRICS: tuple[tuple[str, str], ...] = (
    ("Host CPU %", "host_cpu_pct"),
    ("Host Memory %", "host_memory_pct"),
    ("Oracle Container CPU %", "container_cpu_pct"),
    ("Oracle Container Memory %", "container_memory_pct"),
    ("Active Sessions", "active_sessions"),
    ("Blocking Sessions", "blocking_count"),
    ("Alert ORA/TNS Count", "alert_log_count"),
    ("Highest Tablespace %", "hottest_tablespace_pct"),
    ("TEMP Usage %", "temp_usage_pct"),
    ("Plan Churn Count", "plan_churn_count"),
    ("Stale Stats Count", "stale_stats_count"),
    ("Top SQL CPU Seconds", "top_cpu_sql_cpu_s"),
    ("Top SQL Elapsed Seconds", "top_elapsed_sql_elapsed_s"),
)

DOMAIN_METRIC_HINTS: dict[str, tuple[str, ...]] = {
    "cpu": ("host_cpu_pct", "container_cpu_pct", "top_cpu_sql_cpu_s"),
    "memory": ("host_memory_pct", "container_memory_pct"),
    "storage": ("hottest_tablespace_pct", "temp_usage_pct", "fra_pct"),
    "errors": ("alert_log_count", "listener_error_count"),
    "sql": ("plan_churn_count", "top_cpu_sql_cpu_s", "top_elapsed_sql_elapsed_s"),
    "blocking": ("blocking_count",),
    "awr": ("top_cpu_sql_cpu_s", "top_elapsed_sql_elapsed_s", "plan_churn_count"),
    "transition": ("blocking_count", "alert_log_count", "top_elapsed_sql_elapsed_s", "top_cpu_sql_cpu_s"),
}

SQL_REGRESSION_ABS_THRESHOLD = 120.0
SQL_REGRESSION_RATIO_THRESHOLD = 3.0
SQL_REGRESSION_CRITICAL_ABS_THRESHOLD = 800.0

METRIC_HIGH_THRESHOLDS: dict[str, float] = {
    "blocking_count": 2.0,
    "alert_log_count": 1.0,
    "hottest_tablespace_pct": 85.0,
    "host_cpu_pct": 85.0,
    "host_memory_pct": 85.0,
    "top_elapsed_sql_elapsed_s": 120.0,
    "top_cpu_sql_cpu_s": 120.0,
}


def resolve_time_window(label: str | None, now_utc: datetime | None = None) -> dict[str, Any] | None:
    normalized = " ".join((label or "").strip().lower().split())
    if not normalized:
        return None
    now = (now_utc or datetime.now(UTC)).astimezone(UTC)
    today_start = datetime(now.year, now.month, now.day, tzinfo=UTC)

    if normalized in {"from beginning", "beginning", "all history", "since beginning", "all days"}:
        return {"label": "from beginning", "completed_after": None, "completed_before": now, "history_only": True}
    if normalized == "today":
        return {"label": "today", "completed_after": today_start, "completed_before": now, "history_only": True}
    if normalized == "yesterday":
        start = today_start - timedelta(days=1)
        return {"label": "yesterday", "completed_after": start, "completed_before": today_start, "history_only": True}

    match = re.search(r"\blast\s+(\d+)\s+days?\b", normalized)
    if match:
        days = max(int(match.group(1)), 1)
        return {
            "label": f"last {days} days",
            "completed_after": today_start - timedelta(days=days - 1),
            "completed_before": now,
            "history_only": True,
        }

    match = re.search(r"\b(\d+)\s+days?\s+(ago|back|earlier|before)\b", normalized)
    if match:
        days = max(int(match.group(1)), 1)
        start = today_start - timedelta(days=days)
        return {
            "label": f"{days} days ago",
            "completed_after": start,
            "completed_before": start + timedelta(days=1),
            "history_only": True,
        }

    match = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", normalized)
    if match:
        start = datetime.fromisoformat(match.group(1)).replace(tzinfo=UTC)
        return {
            "label": match.group(1),
            "completed_after": start,
            "completed_before": start + timedelta(days=1),
            "history_only": True,
        }

    if normalized in {"recent", "latest", "last run"}:
        return {"label": normalized, "completed_after": None, "completed_before": now, "history_only": True}
    return None


class JsonlHistoryService:
    def resolve_time_scope(self, user_query: str | None) -> dict[str, Any] | None:
        return resolve_time_window(user_query)

    def append_run_summary(self, summary: dict[str, Any]) -> None:
        HEALTH_RUNS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with HEALTH_RUNS_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(summary, ensure_ascii=True, default=str) + "\n")

    def load_recent_runs(self, limit: int = 10, database_name: str | None = None) -> list[HistoricalRun]:
        traces = read_health_run_traces(database_name=database_name, limit=limit)
        if traces:
            return [self._historical_run(trace) for trace in traces]

        rows = read_health_run_summaries(database_name=database_name, limit=limit)
        return [self._historical_run_from_summary(row) for row in rows]

    def compare_recent_runs(
        self,
        limit: int = 10,
        database_name: str | None = None,
        time_scope: dict[str, Any] | None = None,
    ) -> HistoryContext:
        traces = self._load_traces(limit=limit, database_name=database_name, time_scope=time_scope)
        runs = [self._historical_run(trace) for trace in traces]
        recurring = self._recurring_findings(traces)
        trends = self.get_metric_trends_from_jsonl(database_name=database_name, traces=traces)
        trace_paths = [trace.trace_path for trace in traces if trace.trace_path]
        latest_trace = traces[0] if traces else None
        previous_trace = traces[1] if len(traces) > 1 else None
        latest_fingerprint = self._state_fingerprint(latest_trace)
        previous_fingerprint = self._state_fingerprint(previous_trace)
        state_transition = self._build_state_transition(
            previous=previous_trace,
            current=latest_trace,
            recurring=recurring,
            traces=traces,
        )
        awr_capabilities = state_transition.awr_state_diff.capabilities if state_transition and state_transition.awr_state_diff else None
        return HistoryContext(
            recent_runs=runs,
            recurring_findings=recurring,
            trend_summaries=trends,
            latest_run=runs[0] if runs else None,
            previous_run=runs[1] if len(runs) > 1 else None,
            database_name=database_name or (runs[0].database_name if runs else None),
            trace_paths=trace_paths,
            history_window_label=(time_scope or {}).get("label") if time_scope else None,
            latest_fingerprint=latest_fingerprint,
            previous_fingerprint=previous_fingerprint,
            state_transition=state_transition,
            awr_capabilities=awr_capabilities,
            runs_scanned=len(traces),
        )

    def build_history_context_from_jsonl(
        self,
        *,
        user_query: str | None = None,
        database_name: str | None = None,
        limit: int = 10,
    ) -> HistoryContext:
        time_scope = resolve_time_window(user_query)
        return self.compare_recent_runs(limit=limit, database_name=database_name, time_scope=time_scope)

    def get_latest_jsonl_run(self, database_name: str | None = None) -> TraceHealthRunRecord | None:
        traces = read_health_run_traces(database_name=database_name, limit=1)
        return traces[0] if traces else None

    def get_previous_jsonl_runs(self, database_name: str | None = None, limit: int = 5) -> list[TraceHealthRunRecord]:
        return read_health_run_traces(database_name=database_name, limit=limit)

    def get_jsonl_runs_in_time_window(
        self,
        *,
        start: datetime | None,
        end: datetime | None,
        database_name: str | None = None,
        limit: int = 50,
    ) -> list[TraceHealthRunRecord]:
        return read_health_run_traces(
            database_name=database_name,
            completed_after=start,
            completed_before=end,
            limit=limit,
        )

    def get_metric_trends_from_jsonl(
        self,
        *,
        database_name: str | None = None,
        traces: list[TraceHealthRunRecord] | None = None,
        limit: int = 20,
    ) -> list[MetricTrendSummary]:
        source = traces if traces is not None else read_health_run_traces(database_name=database_name, limit=limit)
        chronological = list(reversed(source))
        trends: list[MetricTrendSummary] = []
        for label, key in DEFAULT_TREND_METRICS:
            raw_values = [_to_float(trace.metrics.get(key)) for trace in chronological]
            values = [value for value in raw_values if value is not None]
            if not values:
                continue
            latest, previous = _latest_and_previous(raw_values)
            direction = _trend_direction(latest=latest, previous=previous)
            trends.append(
                MetricTrendSummary(
                    metric_name=label,
                    values=values,
                    direction=direction,
                    latest_value=latest,
                    previous_value=previous,
                    min_value=min(values),
                    max_value=max(values),
                    sample_count=len(values),
                    summary=_trend_summary(label, values, direction, previous=previous, latest=latest),
                )
            )
        return trends

    def answer_history_question_from_jsonl(
        self,
        *,
        user_query: str,
        database_name: str | None = None,
        requested_domain: str | None = None,
    ) -> dict[str, Any]:
        time_scope = resolve_time_window(user_query)
        traces = self._load_traces(limit=100, database_name=database_name, time_scope=time_scope)
        context = self.compare_recent_runs(limit=100, database_name=database_name, time_scope=time_scope)
        audit = self.audit_history_pipeline(
            database_name=database_name,
            time_scope=time_scope,
            traces=traces,
            auto_rebuild=True,
        )
        indexed_recurring = audit.get("indexed_recurring_findings") or []
        if audit.get("recurrence_computation_mode") == "indexed" and indexed_recurring:
            context.recurring_findings = indexed_recurring
        context.history_source_used = str(audit.get("history_source_used") or "raw JSONL only")
        context.recurrence_computation_mode = str(audit.get("recurrence_computation_mode") or "raw_scan")
        context.index_usage_summary = str(audit.get("index_usage_summary") or "none")
        context.runs_scanned = int(audit.get("runs_scanned") or len(traces))
        context.index_records_scanned = int(audit.get("index_records_scanned") or 0)
        context.history_index_status = str(audit.get("history_index_status") or "unknown")
        context.history_index_freshness = str(audit.get("history_index_freshness") or "unknown")
        context.history_index_rebuilt = bool(audit.get("history_index_rebuilt"))
        context.history_index_notes = list(audit.get("history_index_notes") or [])
        domain = (requested_domain or _infer_domain(user_query) or "").lower()
        metric_keys = DOMAIN_METRIC_HINTS.get(domain, tuple(key for _, key in DEFAULT_TREND_METRICS))
        series = self._metric_series(traces, metric_keys)
        transition = context.state_transition
        if transition and transition.available:
            confidence_block = transition.historical_confidence
            if confidence_block:
                confidence_block = confidence_block.model_copy(
                    update={"history_source_used": context.history_source_used}
                )
            transition = transition.model_copy(
                update={
                    "history_source_summary": f"History source: {context.history_source_used}",
                    "historical_confidence": confidence_block,
                }
            )
            context.state_transition = transition
        summary_lines = self._history_summary_lines(context, series, domain)
        return {
            "kind": "oracle_history",
            "domain": domain or None,
            "time_scope": time_scope,
            "matched_run_count": len(traces),
            "context": context,
            "series": series,
            "summary_lines": summary_lines,
            "state_transition": transition,
            "learning_features": (transition.learning_features if transition else None),
            "awr_state_diff": (transition.awr_state_diff if transition else None),
            "history_source_used": context.history_source_used,
            "recurrence_computation_mode": context.recurrence_computation_mode,
            "index_usage_summary": context.index_usage_summary,
            "runs_scanned": context.runs_scanned,
            "index_records_scanned": context.index_records_scanned,
            "history_index_status": context.history_index_status,
            "history_index_freshness": context.history_index_freshness,
            "history_index_rebuilt": context.history_index_rebuilt,
            "history_index_notes": context.history_index_notes,
            "history_source_files_read": audit.get("history_source_files_read") or [],
            "history_source_note": self._history_source_note(context),
            "history_source_summary": f"History source: {context.history_source_used}",
            "awr_source_summary": (transition.awr_source_summary if transition else "AWR source: unavailable, JSONL fallback used"),
            "fallback_summary": (transition.fallback_summary if transition else "Fallback mode unavailable."),
        }

    def _load_traces(
        self,
        *,
        limit: int,
        database_name: str | None,
        time_scope: dict[str, Any] | None,
    ) -> list[TraceHealthRunRecord]:
        return read_health_run_traces(
            database_name=database_name,
            completed_after=(time_scope or {}).get("completed_after"),
            completed_before=(time_scope or {}).get("completed_before"),
            limit=limit,
        )

    def audit_history_pipeline(
        self,
        *,
        database_name: str | None = None,
        time_scope: dict[str, Any] | None = None,
        traces: list[TraceHealthRunRecord] | None = None,
        auto_rebuild: bool = True,
    ) -> dict[str, Any]:
        source_traces = traces if traces is not None else self._load_traces(limit=100, database_name=database_name, time_scope=time_scope)
        runs_scanned = len(source_traces)
        latest_health_run_at = _to_datetime(source_traces[0].completed_at) if source_traces else None
        snapshot = self._index_snapshot(database_name=database_name, time_scope=time_scope)
        latest_indexed_at = _to_datetime(snapshot.get("latest_indexed_at"))
        if latest_health_run_at and latest_indexed_at and latest_indexed_at < latest_health_run_at:
            snapshot["history_index_status"] = "stale"
            snapshot["history_index_freshness"] = "stale"
            snapshot.setdefault("notes", []).append("History indexes are older than the latest health run.")
        elif latest_health_run_at and latest_indexed_at is None:
            snapshot["history_index_freshness"] = "missing"
        notes = list(snapshot.get("notes") or [])
        rebuilt = False
        if auto_rebuild and runs_scanned and self._should_rebuild_indexes(snapshot):
            try:
                rebuild_planner_memory_artifacts(database_name=database_name)
                rebuilt = True
                notes.append("History indexes were rebuilt during this request.")
                snapshot = self._index_snapshot(database_name=database_name, time_scope=time_scope)
                notes.extend(snapshot.get("notes") or [])
            except Exception as exc:
                notes.append(f"History index rebuild failed; continued with fallback: {exc}")

        recurrence_mode = "indexed" if self._can_use_indexed_recurrence(snapshot, latest_health_run_at=latest_health_run_at) else "raw_scan"
        indexed_recurring = self._recurring_findings_from_index_records(
            snapshot.get("recurring_records") or [],
            sampled_runs=runs_scanned,
        )
        if recurrence_mode != "indexed":
            notes.append(self._raw_fallback_reason(snapshot))

        history_source_used = "indexed recurrence + raw run metrics" if recurrence_mode == "indexed" else "raw JSONL only"
        index_usage_summary = self._index_usage_summary(snapshot, recurrence_mode=recurrence_mode)
        index_records_scanned = int(snapshot.get("index_records_scanned") or 0)
        files_read = list(snapshot.get("files_read") or [])
        return {
            "history_source_used": history_source_used,
            "recurrence_computation_mode": recurrence_mode,
            "index_usage_summary": index_usage_summary,
            "runs_scanned": runs_scanned,
            "index_records_scanned": index_records_scanned,
            "history_index_status": snapshot.get("history_index_status") or "unknown",
            "history_index_freshness": snapshot.get("history_index_freshness") or "unknown",
            "history_index_rebuilt": rebuilt,
            "history_index_notes": _dedupe_preserve_order(notes),
            "history_source_files_read": files_read,
            "latest_health_run_at": source_traces[0].completed_at if source_traces else None,
            "latest_indexed_at": snapshot.get("latest_indexed_at"),
            "indexed_recurring_findings": indexed_recurring,
        }

    def _index_snapshot(
        self,
        *,
        database_name: str | None,
        time_scope: dict[str, Any] | None,
    ) -> dict[str, Any]:
        paths = history_data_source_paths()
        files_present = {name: path.exists() for name, path in paths.items() if name != "health_runs"}
        files_read: list[str] = []
        notes: list[str] = []
        recurring_records: list[RecurringIssueIndexRecord] = []
        chunk_records: list[TraceEvidenceChunk] = []
        behavior_profiles: list[OraclePlannerMemoryRecord] = []
        history_entries: list[dict[str, Any]] = []

        if files_present.get("recurring_issues"):
            recurring_records = read_recurring_issue_index(database_name=database_name, limit=None)
            files_read.append(str(paths["recurring_issues"]))
        if files_present.get("trace_chunks"):
            chunk_records = read_trace_evidence_chunks(
                database_name=database_name,
                completed_after=(time_scope or {}).get("completed_after"),
                completed_before=(time_scope or {}).get("completed_before"),
                limit=None,
            )
            files_read.append(str(paths["trace_chunks"]))
        if files_present.get("database_behavior_profiles"):
            behavior_profiles = read_database_planner_memory(database_name=database_name, limit=None)
            files_read.append(str(paths["database_behavior_profiles"]))
        if files_present.get("history_indexing"):
            history_entries = read_history_index_entries(database_name=database_name, limit=None)
            files_read.append(str(paths["history_indexing"]))

        latest_values = [
            _to_datetime(record.last_seen) for record in recurring_records if getattr(record, "last_seen", None)
        ]
        latest_values.extend(_to_datetime(record.recorded_at) for record in chunk_records if getattr(record, "recorded_at", None))
        latest_values.extend(
            _to_datetime(record.latest_trace_recorded_at or record.generated_at)
            for record in behavior_profiles
            if getattr(record, "latest_trace_recorded_at", None) or getattr(record, "generated_at", None)
        )
        for entry in history_entries:
            payload = entry.get("payload") if isinstance(entry.get("payload"), dict) else entry
            latest_values.append(_to_datetime(payload.get("completed_at") or payload.get("recorded_at")))
        latest_values = [value for value in latest_values if value is not None]
        latest_indexed_at = max(latest_values) if latest_values else None

        missing_files = [name for name, present in files_present.items() if not present]
        if len(missing_files) == len(files_present):
            history_index_status = "missing"
        elif missing_files:
            history_index_status = "partial"
            notes.append("Some history index files are missing: " + ", ".join(missing_files))
        else:
            history_index_status = "present"

        if latest_indexed_at is None:
            history_index_freshness = "missing"
        else:
            history_index_freshness = "fresh"

        return {
            "history_index_status": history_index_status,
            "history_index_freshness": history_index_freshness,
            "latest_indexed_at": latest_indexed_at.isoformat() if latest_indexed_at else None,
            "index_records_scanned": len(recurring_records) + len(chunk_records) + len(behavior_profiles) + len(history_entries),
            "files_present": files_present,
            "files_read": files_read,
            "recurring_records": recurring_records,
            "notes": notes,
        }

    def _should_rebuild_indexes(self, snapshot: dict[str, Any]) -> bool:
        return str(snapshot.get("history_index_status") or "") in {"missing", "partial"} or str(snapshot.get("history_index_freshness") or "") == "stale"

    def _can_use_indexed_recurrence(
        self,
        snapshot: dict[str, Any],
        *,
        latest_health_run_at: datetime | None,
    ) -> bool:
        recurring_records = snapshot.get("recurring_records") or []
        if not recurring_records:
            return False
        latest_indexed_at = _to_datetime(snapshot.get("latest_indexed_at"))
        if latest_health_run_at and latest_indexed_at and latest_indexed_at < latest_health_run_at:
            snapshot["history_index_freshness"] = "stale"
            snapshot["history_index_status"] = "stale"
            return False
        if latest_health_run_at and latest_indexed_at is None:
            snapshot["history_index_freshness"] = "missing"
            return False
        snapshot["history_index_freshness"] = "fresh"
        return True

    def _recurring_findings_from_index_records(
        self,
        records: list[RecurringIssueIndexRecord],
        *,
        sampled_runs: int,
        limit: int = 8,
    ) -> list[str]:
        findings: list[str] = []
        for record in records[:limit]:
            denominator = sampled_runs if sampled_runs > 0 else record.run_count
            findings.append(f"{record.title} recurred in {record.run_count}/{denominator} saved health run(s).")
        return findings

    def _raw_fallback_reason(self, snapshot: dict[str, Any]) -> str:
        status = str(snapshot.get("history_index_status") or "unknown")
        freshness = str(snapshot.get("history_index_freshness") or "unknown")
        recurring_records = snapshot.get("recurring_records") or []
        files_present = snapshot.get("files_present") or {}
        recurring_file_present = bool(files_present.get("recurring_issues"))
        if not recurring_file_present:
            return "Recurring issue analysis used raw health_runs.jsonl because recurring_issues.jsonl was missing."
        if status == "missing":
            return "Recurring issue analysis used raw health_runs.jsonl because recurring_issues.jsonl was missing."
        if freshness == "stale":
            return "History trend fell back to raw scan because history indexes were stale."
        if not recurring_records:
            return "Recurring issue analysis used raw health_runs.jsonl because recurring_issues.jsonl had no matching records."
        return "Recurring issue analysis used raw health_runs.jsonl because indexed recurrence data was not usable."

    def _index_usage_summary(self, snapshot: dict[str, Any], *, recurrence_mode: str) -> str:
        files_read = snapshot.get("files_read") or []
        if recurrence_mode == "indexed":
            used = []
            for marker in ("recurring_issues.jsonl", "trace_chunks.jsonl", "history_indexing.jsonl", "database_behavior_profiles.jsonl"):
                if any(path.endswith(marker) for path in files_read):
                    used.append(marker.replace(".jsonl", ""))
            return " + ".join(used) or "recurring_issues"
        if files_read:
            return "health_runs + index audit (no indexed recurrence)"
        return "health_runs only"

    def _history_source_note(self, context: HistoryContext) -> str:
        if context.recurrence_computation_mode == "indexed":
            return f"History source: {context.history_source_used}."
        for note in context.history_index_notes:
            if "Recurring issue analysis used raw" in note or "fell back to raw scan" in note:
                return note
        return "History source: raw JSONL only (indexes unavailable)."

    def _recurring_findings(self, traces: list[TraceHealthRunRecord]) -> list[str]:
        if len(traces) < 2:
            return []
        issue_counter: Counter[str] = Counter()
        sql_counter: Counter[str] = Counter()
        tablespace_counter: Counter[str] = Counter()
        for trace in traces:
            seen_titles = set()
            for issue in trace.issues:
                key = issue.title.strip()
                if key and key not in seen_titles:
                    issue_counter[key] += 1
                    seen_titles.add(key)
            sql_id = trace.metrics.get("top_cpu_sql_id")
            if sql_id:
                sql_counter[str(sql_id)] += 1
            ts = trace.metrics.get("hottest_tablespace")
            if ts:
                tablespace_counter[str(ts)] += 1

        findings: list[str] = []
        sampled = len(traces)
        for title, count in issue_counter.most_common(5):
            if count >= 2:
                findings.append(f"{title} recurred in {count}/{sampled} saved health run(s).")
        for sql_id, count in sql_counter.most_common(3):
            if count >= 2:
                findings.append(f"SQL_ID {sql_id} appeared as top CPU SQL in {count}/{sampled} run(s).")
        for ts, count in tablespace_counter.most_common(2):
            if count >= 2:
                findings.append(f"Tablespace {ts} was the highest-usage tablespace in {count}/{sampled} run(s).")
        return findings

    def _metric_series(self, traces: list[TraceHealthRunRecord], metric_keys: tuple[str, ...]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for trace in reversed(traces):
            row = {
                "completed_at": trace.completed_at,
                "database_name": trace.database_name,
                "overall_status": trace.overall_status,
                "trace_path": trace.trace_path,
            }
            has_value = False
            for key in metric_keys:
                value = _to_float(trace.metrics.get(key))
                if value is not None:
                    row[key] = value
                    has_value = True
            if has_value:
                rows.append(row)
        return rows

    def _history_summary_lines(self, context: HistoryContext, series: list[dict[str, Any]], domain: str) -> list[str]:
        lines: list[str] = []
        if context.history_source_used:
            lines.append(
                f"History source: {context.history_source_used} "
                f"(recurrence_mode={context.recurrence_computation_mode}, runs_scanned={context.runs_scanned}, "
                f"index_records_scanned={context.index_records_scanned})."
            )
        if context.latest_run:
            lines.append(f"Latest saved run is {context.latest_run.overall_status or 'INFO'} at {context.latest_run.completed_at}.")
        if context.previous_run:
            lines.append(f"Previous run was {context.previous_run.overall_status or 'INFO'} at {context.previous_run.completed_at}.")
        if series:
            lines.append(f"Matched {len(series)} historical metric point(s){f' for {domain}' if domain else ''}.")
        if context.state_transition and context.state_transition.available:
            lines.append(
                f"State transition: {context.state_transition.status_transition} "
                f"(confidence={context.state_transition.confidence})."
            )
            lines.append(f"Transition outcome: {context.state_transition.transition_outcome}.")
            primary_label = context.state_transition.section_naming.primary_driver_section_title.rstrip("s")
            secondary_label = context.state_transition.section_naming.secondary_driver_section_title.rstrip("s")
            if context.state_transition.recovery_drivers:
                lines.append(f"{primary_label}: {context.state_transition.recovery_drivers[0].title}.")
            if context.state_transition.residual_warning_drivers:
                lines.append(f"{secondary_label}: {context.state_transition.residual_warning_drivers[0].title}.")
        return lines or ["No saved Oracle health traces matched the requested history window."]

    def _state_fingerprint(self, trace: TraceHealthRunRecord | None) -> StateFingerprint | None:
        if trace is None:
            return None
        metrics = trace.metrics or {}
        snapshot = trace.snapshot
        wait_class = None
        if snapshot and snapshot.wait_classes:
            wait_class = snapshot.wait_classes[0].wait_class
        dominant_sql = metrics.get("top_cpu_sql_id") or metrics.get("top_elapsed_sql_id")
        return StateFingerprint(
            overall_status=str(trace.overall_status or "INFO"),
            blocking_present=(float(metrics.get("blocking_count") or 0) > 0),
            alert_errors_present=(float(metrics.get("alert_log_count") or 0) + float(metrics.get("listener_error_count") or 0) > 0),
            dominant_wait_class=str(wait_class or "unknown"),
            dominant_sql_id=str(dominant_sql) if dominant_sql else None,
            db_time_bucket=self._bucket(metrics.get("top_elapsed_sql_elapsed_s"), warning=20, critical=60),
            cpu_bucket=self._bucket(metrics.get("host_cpu_pct"), warning=70, critical=85),
            io_bucket=self._bucket(metrics.get("top_elapsed_sql_elapsed_s"), warning=15, critical=45),
            tablespace_pressure=self._bucket_label(metrics.get("hottest_tablespace_pct"), warning=85, critical=92, labels=("normal", "warning", "critical")),
            memory_pressure=self._bucket_label(metrics.get("host_memory_pct"), warning=80, critical=92, labels=("normal", "warning", "critical")),
            plan_churn_present=(float(metrics.get("plan_churn_count") or 0) > 0),
            stale_stats_present=(float(metrics.get("stale_stats_count") or 0) > 0),
        )

    def _build_state_transition(
        self,
        *,
        previous: TraceHealthRunRecord | None,
        current: TraceHealthRunRecord | None,
        recurring: list[str],
        traces: list[TraceHealthRunRecord],
    ) -> HistoricalStateTransition:
        if previous is None or current is None:
            return HistoricalStateTransition(
                available=False,
                coverage_notes=["At least two historical runs are required for state transition analysis."],
            )

        previous_status = str(previous.overall_status or "INFO")
        current_status = str(current.overall_status or "INFO")
        status_transition = f"{previous_status.lower()} -> {current_status.lower()}"
        comparison_window = self._build_comparison_window(previous, current)

        issue_transitions = self._classify_issue_transitions(previous.issues, current.issues)
        awr_result = self._build_optional_awr_diff(previous, current, comparison_window=comparison_window)
        awr_diff: AwrStateDiff | None
        awr_notes: list[str]
        fallback_mode: str
        awr_debug_message = ""
        if len(awr_result) == 3:
            awr_diff, awr_notes, fallback_mode = awr_result
        else:
            awr_diff, awr_notes, fallback_mode, awr_debug_message = awr_result
        sql_regression = self._sql_regression_signal(previous, current, awr_diff)
        metric_deltas = self._build_metric_deltas(previous, current)
        outcome = self._determine_transition_outcome(
            previous_status=previous_status,
            current_status=current_status,
            issue_transitions=issue_transitions,
            metric_deltas=metric_deltas,
        )
        recovery_drivers = self._build_recovery_drivers(
            previous,
            current,
            issue_transitions=issue_transitions,
        )
        residual_drivers = self._build_residual_warning_drivers(
            previous,
            current,
            issue_transitions=issue_transitions,
            awr_diff=awr_diff,
            sql_regression=sql_regression,
        )
        outcome = outcome.model_copy(
            update={
                "recovery_detected": bool(recovery_drivers),
                "residual_risk_present": bool(residual_drivers),
            }
        )
        ranked_primary, ranked_secondary = self._rank_transition_drivers(
            previous,
            current,
            issue_transitions,
            awr_diff,
            sql_regression,
        )
        primary_drivers, secondary_drivers = self._compose_transition_drivers(
            transition_outcome=outcome.transition_outcome,
            recovery_drivers=recovery_drivers,
            residual_drivers=residual_drivers,
            fallback_primary=ranked_primary,
            fallback_secondary=ranked_secondary,
        )
        suppressed = self._suppressed_background_signals(
            traces=traces,
            issue_transitions=issue_transitions,
            primary_drivers=primary_drivers,
        )
        learning = self._learning_features(
            previous,
            current,
            issue_transitions,
            awr_diff,
            sql_regression,
            primary_drivers,
            fallback_mode=fallback_mode,
        )
        learning = learning.model_copy(
            update={
                "recovery_detected": outcome.recovery_detected,
                "residual_risk_present": outcome.residual_risk_present,
                "recovery_driver_category": recovery_drivers[0].category if recovery_drivers else None,
                "residual_driver_category": residual_drivers[0].category if residual_drivers else None,
                "transition_outcome": outcome.transition_outcome,
            }
        )
        issue_states = self._historical_issue_states(issue_transitions)
        awr_user_message = self._awr_user_message(awr_diff=awr_diff, fallback_mode=fallback_mode, notes=awr_notes)
        awr_source_summary = self._awr_source_summary(awr_diff=awr_diff, fallback_mode=fallback_mode)
        awr_workload_interpretation = self._awr_workload_interpretation(awr_diff=awr_diff, fallback_mode=fallback_mode)
        snapshot_mapping_summary = self._snapshot_mapping_summary(awr_diff=awr_diff)
        section_naming = self._section_naming_for_outcome(outcome.transition_outcome)
        fallback_summary = awr_user_message if fallback_mode != "none" else "No fallback required."
        timeline_entries = self._build_event_timeline(
            previous=previous,
            current=current,
            recovery_drivers=recovery_drivers,
            residual_drivers=residual_drivers,
            transition_outcome=outcome.transition_outcome,
            learning=learning,
            awr_user_message=awr_user_message,
            awr_diff=awr_diff,
        )

        confidence, confidence_reason = self._transition_confidence(
            primary_drivers=primary_drivers,
            awr_diff=awr_diff,
            metric_deltas=metric_deltas,
            fallback_mode=fallback_mode,
        )
        learning.transition_confidence_reason = confidence_reason

        coverage_notes = [note for note in awr_notes if note]
        coverage_notes.extend(
            self._interpret_transition_patterns(
                issue_transitions=issue_transitions,
                primary_drivers=primary_drivers,
                learning=learning,
            )
        )
        if not primary_drivers:
            coverage_notes.append("No dominant transition drivers were identified from available evidence.")
        coverage_notes.extend(item.interpretation for item in metric_deltas[:4] if item.interpretation)

        confidence_block = HistoricalConfidence(
            confidence_level=confidence,
            confidence_reason=confidence_reason,
            coverage_quality=(awr_diff.snapshot_quality.coverage_quality if awr_diff and awr_diff.snapshot_quality else ("HIGH" if fallback_mode == "jsonl_inference_only" else "LOW")),
            history_source_used="raw run metrics from JSONL traces",
            fallback_mode=fallback_mode,
            fallback_reason=fallback_summary,
            notes=coverage_notes[:8],
        )

        primary_transition_drivers = [self._to_historical_driver(driver, rank="primary") for driver in primary_drivers]
        secondary_transition_drivers = [self._to_historical_driver(driver, rank="secondary") for driver in secondary_drivers]

        summary = HistoricalTransitionSummary(
            status_transition=status_transition,
            primary_drivers=primary_transition_drivers,
            secondary_drivers=secondary_transition_drivers,
            recovery_drivers=recovery_drivers,
            residual_warning_drivers=residual_drivers,
            transition_outcome=outcome,
            suppressed_background_signals=suppressed,
            issue_states=issue_states,
            metric_deltas=metric_deltas,
            event_timeline=timeline_entries,
            learning_features=HistoricalLearningFeatures.model_validate(learning.model_dump(mode="json")),
            confidence=confidence_block,
            comparison_window=comparison_window,
        )

        recurring_ranked = self._rank_recurring_patterns(
            traces=traces,
            primary_drivers=primary_drivers,
            suppressed=suppressed,
        )

        return HistoricalStateTransition(
            available=True,
            previous_run_id=previous.run_id,
            current_run_id=current.run_id,
            previous_status=previous_status,
            current_status=current_status,
            status_transition=status_transition,
            transition_outcome=outcome.transition_outcome,
            recovery_detected=outcome.recovery_detected,
            residual_risk_present=outcome.residual_risk_present,
            issue_transitions=issue_transitions,
            recovery_drivers=recovery_drivers,
            residual_warning_drivers=residual_drivers,
            primary_drivers=primary_drivers,
            secondary_drivers=secondary_drivers,
            recurring_patterns_ranked=recurring_ranked,
            event_timeline=[f"{item.at}: {item.summary}" for item in timeline_entries],
            learning_features=learning,
            confidence=confidence,
            coverage_notes=coverage_notes,
            awr_state_diff=awr_diff,
            primary_transition_drivers=primary_transition_drivers,
            secondary_transition_drivers=secondary_transition_drivers,
            suppressed_background_signals=suppressed,
            metric_deltas=metric_deltas,
            historical_issue_states=issue_states,
            event_timeline_entries=timeline_entries,
            historical_learning_features=summary.learning_features,
            historical_confidence=confidence_block,
            comparison_window=comparison_window,
            history_source_summary="raw run metrics from JSONL traces",
            awr_source_summary=awr_source_summary,
            fallback_summary=fallback_summary,
            section_naming=section_naming,
            awr_workload_interpretation=awr_workload_interpretation,
            snapshot_mapping_summary=snapshot_mapping_summary,
            awr_fallback_info=AwrFallbackInfo(
                fallback_mode=fallback_mode,
                awr_user_message=awr_user_message,
                awr_debug_message=awr_debug_message,
            ),
            summary=summary,
        )

    def _build_optional_awr_diff(
        self,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        *,
        comparison_window: HistoricalComparisonWindow,
    ) -> tuple[AwrStateDiff | None, list[str], str, str]:
        notes: list[str] = []
        debug_message = ""
        if not _awr_feature_enabled():
            notes.append("AWR workload comparison is disabled; JSONL fallback used.")
            return None, notes, "awr_disabled", debug_message
        try:
            caps = get_awr_capabilities()
        except Exception as exc:
            debug_message = str(exc)
            return None, ["AWR workload comparison unavailable because capability metadata could not be collected; JSONL fallback used."], "awr_capability_failure", debug_message
        if not caps.available:
            notes.append("AWR source unavailable, JSONL fallback used.")
            return AwrStateDiff(available=False, capabilities=caps), notes, "awr_unavailable", debug_message
        try:
            mapping = map_run_pair_to_awr_windows(
                previous.completed_at,
                current.completed_at,
                dbid=caps.dbid,
                previous_window_start=comparison_window.window_start,
                previous_window_end=previous.completed_at,
                current_window_start=current.completed_at,
                current_window_end=comparison_window.window_end,
            )
            notes.extend(mapping.notes[:4])
            debug_message = json.dumps(mapping.debug or {}, ensure_ascii=True, default=str)
            awr_diff = build_awr_state_diff(window_mapping=mapping, capabilities=caps)
            notes.extend(awr_diff.snapshot_quality.notes[:4] if awr_diff.snapshot_quality else [])
            awr_diff = self._enrich_awr_with_report_text_if_needed(awr_diff=awr_diff, mapping=mapping, capabilities=caps, notes=notes)
            if not awr_diff.available:
                notes.append("AWR snapshot mapping was weak; JSONL fallback used for transition reasoning.")
                return awr_diff, notes, "awr_mapping_weak", debug_message
            same_window = (
                mapping.previous.begin_snap_id is not None
                and mapping.previous.end_snap_id is not None
                and mapping.previous.begin_snap_id == mapping.current.begin_snap_id
                and mapping.previous.end_snap_id == mapping.current.end_snap_id
            )
            if same_window or bool((mapping.debug or {}).get("same_snap_selected")):
                notes.append("AWR snapshots mapped successfully but same-window comparison is weak.")
                return awr_diff, notes, "awr_same_window_weak", debug_message
            if awr_diff.snapshot_quality and awr_diff.snapshot_quality.coverage_quality in {"LOW", "NONE"}:
                notes.append("AWR snapshots mapped successfully but metric rows were incomplete; partial AWR comparison shown.")
                return awr_diff, notes, "awr_metric_incomplete", debug_message
            return awr_diff, notes, "none", debug_message
        except Exception as exc:
            debug_message = str(exc)
            notes.append("AWR query failed while building workload comparison; JSONL fallback used.")
            return None, notes, "awr_query_failure", debug_message

    def _enrich_awr_with_report_text_if_needed(
        self,
        *,
        awr_diff: AwrStateDiff,
        mapping: AwrRunPairWindowMapping,
        capabilities: Any,
        notes: list[str],
    ) -> AwrStateDiff:
        if not awr_diff.available:
            return awr_diff
        if awr_diff.awr_report_text_summary and awr_diff.awr_report_text_summary.available:
            return awr_diff
        if not self._should_use_awr_report_text_enrichment(awr_diff=awr_diff, mapping=mapping):
            return awr_diff

        summary = get_awr_report_text_summary_for_window(
            window=mapping.current,
            dbid=getattr(capabilities, "dbid", None),
        )
        if not summary.available:
            notes.extend(summary.notes[:2])
            if mapping.previous.begin_snap_id is not None and mapping.previous.end_snap_id is not None:
                fallback_summary = get_awr_report_text_summary_for_window(
                    window=mapping.previous,
                    dbid=getattr(capabilities, "dbid", None),
                )
                if fallback_summary.available:
                    summary = fallback_summary
                else:
                    notes.extend(fallback_summary.notes[:2])

        if summary.available:
            notes.append(
                f"AWR report-text summary added for SNAP {summary.begin_snap_id}..{summary.end_snap_id} to enrich sparse metric extraction."
            )
            awr_diff = awr_diff.model_copy(update={"awr_report_text_summary": summary})
        return awr_diff

    def _should_use_awr_report_text_enrichment(
        self,
        *,
        awr_diff: AwrStateDiff,
        mapping: AwrRunPairWindowMapping,
    ) -> bool:
        if not awr_diff.available:
            return False
        same_snap_selected = bool((mapping.debug or {}).get("same_snap_selected"))
        same_window_expansion_applied = bool((mapping.debug or {}).get("same_window_expansion_applied"))
        coverage_quality = str((awr_diff.snapshot_quality.coverage_quality if awr_diff.snapshot_quality else "NONE") or "NONE").upper()
        mostly_unavailable = False
        if awr_diff.workload_metrics:
            unavailable = sum(
                1
                for item in awr_diff.workload_metrics
                if item.previous_value is None or item.current_value is None
            )
            mostly_unavailable = unavailable >= max(2, int(len(awr_diff.workload_metrics) * 0.6))
        return same_snap_selected or same_window_expansion_applied or coverage_quality in {"LOW", "NONE"} or mostly_unavailable

    def _classify_issue_transitions(
        self,
        previous_issues: list[HealthIssue],
        current_issues: list[HealthIssue],
    ) -> list[TransitionIssueClassification]:
        out: list[TransitionIssueClassification] = []
        previous_map = {self._issue_key(issue): issue for issue in previous_issues}
        current_map = {self._issue_key(issue): issue for issue in current_issues}
        all_keys = sorted(set(previous_map) | set(current_map))
        for key in all_keys:
            prev_issue = previous_map.get(key)
            curr_issue = current_map.get(key)
            if prev_issue and not curr_issue:
                transition = "resolved"
            elif curr_issue and not prev_issue:
                transition = "new"
            else:
                prev_rank = _severity_rank(str(prev_issue.severity if prev_issue else "INFO"))
                curr_rank = _severity_rank(str(curr_issue.severity if curr_issue else "INFO"))
                if curr_rank > prev_rank:
                    transition = "worsened"
                elif curr_rank < prev_rank:
                    transition = "improved"
                else:
                    transition = "persistent"
            issue = curr_issue or prev_issue
            if issue is None:
                continue
            out.append(
                TransitionIssueClassification(
                    category=issue.category,
                    title=issue.title,
                    transition=transition,
                    previous_severity=(str(prev_issue.severity) if prev_issue else None),
                    current_severity=(str(curr_issue.severity) if curr_issue else None),
                )
            )
        return out

    def _sql_regression_signal(
        self,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        awr_diff: AwrStateDiff | None,
    ) -> dict[str, Any]:
        prev_metrics = previous.metrics or {}
        curr_metrics = current.metrics or {}
        prev_elapsed = _to_float(prev_metrics.get("top_elapsed_sql_elapsed_s")) or 0.0
        curr_elapsed = _to_float(curr_metrics.get("top_elapsed_sql_elapsed_s")) or 0.0
        delta = curr_elapsed - prev_elapsed
        ratio = (curr_elapsed / prev_elapsed) if prev_elapsed > 0 else (float("inf") if curr_elapsed > 0 else 1.0)

        awr_flag = bool(awr_diff and awr_diff.available and awr_diff.sql_change.sql_regression_flag)
        metric_flag = bool((ratio >= SQL_REGRESSION_RATIO_THRESHOLD) or (delta >= SQL_REGRESSION_ABS_THRESHOLD))
        flag = awr_flag or metric_flag

        severity = "NONE"
        if flag:
            if ratio >= 10 or delta >= SQL_REGRESSION_CRITICAL_ABS_THRESHOLD:
                severity = "CRITICAL"
            elif ratio >= 6 or delta >= 300:
                severity = "HIGH"
            elif ratio >= 3 or delta >= 120:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        blocking_delta = _delta((previous.metrics or {}).get("blocking_count"), (current.metrics or {}).get("blocking_count"))
        sql_cpu_delta = _delta((previous.metrics or {}).get("top_cpu_sql_cpu_s"), (current.metrics or {}).get("top_cpu_sql_cpu_s"))
        elapsed_exploded_vs_cpu = bool(delta > 0 and (sql_cpu_delta <= 0 or abs(delta) > (abs(sql_cpu_delta) * 3)))
        sql_amplified_by_blocking = bool(flag and blocking_delta > 0 and elapsed_exploded_vs_cpu)

        evidence = [
            f"top_elapsed_sql_elapsed_s {prev_elapsed:.2f} -> {curr_elapsed:.2f} (delta={delta:.2f})",
            f"elapsed_ratio={ratio:.2f}x" if ratio != float("inf") else "elapsed_ratio=inf (previous baseline was zero)",
            f"top_cpu_sql_cpu_s delta={sql_cpu_delta:.2f}",
        ]
        if awr_flag:
            evidence.append("AWR SQL change intelligence also marked sql_regression_flag=true.")
        if sql_amplified_by_blocking:
            evidence.append("Elapsed increased much faster than CPU while blocking increased; likely lock/wait amplification.")
        return {
            "flag": flag,
            "severity": severity,
            "delta": delta,
            "ratio": ratio,
            "sql_amplified_by_blocking_flag": sql_amplified_by_blocking,
            "evidence": evidence,
        }

    def _rank_transition_drivers(
        self,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        issue_transitions: list[TransitionIssueClassification],
        awr_diff: AwrStateDiff | None,
        sql_regression: dict[str, Any],
    ) -> tuple[list[TransitionDriver], list[TransitionDriver]]:
        scored: list[tuple[float, TransitionDriver]] = []
        prev_metrics = previous.metrics or {}
        curr_metrics = current.metrics or {}
        issue_text = " ".join(f"{item.category} {item.title}".lower() for item in issue_transitions)

        def add_driver(score: float, name: str, driver_type: str, evidence: list[str]) -> None:
            scored.append(
                (
                    score,
                    TransitionDriver(
                        name=name,
                        driver_type=driver_type,
                        evidence=evidence,
                    ),
                )
            )

        if sql_regression.get("flag"):
            severity = str(sql_regression.get("severity") or "HIGH")
            severity_score = {
                "CRITICAL": 1.0,
                "HIGH": 0.99,
                "MEDIUM": 0.96,
                "LOW": 0.9,
            }.get(severity, 0.92)
            add_driver(
                severity_score,
                f"SQL regression detected ({severity})",
                "sql_regression",
                list(sql_regression.get("evidence") or []),
            )

        blocking_delta = _delta(prev_metrics.get("blocking_count"), curr_metrics.get("blocking_count"))
        if blocking_delta > 0:
            add_driver(
                0.88,
                "New or increased blocker pressure",
                "blocking",
                [
                    f"blocking_count {prev_metrics.get('blocking_count') or 0} -> {curr_metrics.get('blocking_count') or 0} (delta={blocking_delta:.0f})",
                ],
            )
        elif blocking_delta == 0 and any(item.transition == "persistent" and "lock" in f"{item.category} {item.title}".lower() for item in issue_transitions):
            workload_worsened = _delta(prev_metrics.get("top_elapsed_sql_elapsed_s"), curr_metrics.get("top_elapsed_sql_elapsed_s")) > SQL_REGRESSION_ABS_THRESHOLD
            add_driver(
                0.87 if workload_worsened else 0.74,
                "Persistent blocker with worsening workload impact" if workload_worsened else "Blocking remained persistent",
                "blocking",
                [
                    f"blocking_count persisted at {curr_metrics.get('blocking_count') or 0}",
                    f"top_elapsed_sql_elapsed_s delta={_delta(prev_metrics.get('top_elapsed_sql_elapsed_s'), curr_metrics.get('top_elapsed_sql_elapsed_s')):.2f}",
                ],
            )

        alert_delta = _delta(prev_metrics.get("alert_log_count"), curr_metrics.get("alert_log_count"))
        if alert_delta > 0:
            add_driver(
                0.84,
                "ORA/TNS errors increased",
                "ora_error_emergence",
                [f"alert_log_count {prev_metrics.get('alert_log_count') or 0} -> {curr_metrics.get('alert_log_count') or 0} (delta={alert_delta:.0f})"],
            )

        transaction_related = any(
            item.transition in {"new", "worsened"}
            and ("transaction" in item.category.lower() or "transaction" in item.title.lower() or "undo" in item.category.lower() or "undo" in item.title.lower())
            for item in issue_transitions
        )
        if transaction_related:
            add_driver(
                0.86,
                "New long transaction/undo anomaly",
                "long_transaction",
                ["New/worsened transaction or undo issue detected in transition set."],
            )

        stale_delta = _delta(prev_metrics.get("stale_stats_count"), curr_metrics.get("stale_stats_count"))
        if stale_delta > 0:
            add_driver(
                0.35,
                "Stale statistics increased",
                "stale_stats_noise",
                [f"stale_stats_count {prev_metrics.get('stale_stats_count') or 0} -> {curr_metrics.get('stale_stats_count') or 0}"],
            )
        elif (_to_float(curr_metrics.get("stale_stats_count")) or 0) > 0:
            add_driver(
                0.18,
                "Persistent stale stats background noise",
                "persistent_background_noise",
                [f"stale_stats_count persisted at {curr_metrics.get('stale_stats_count') or 0}"],
            )

        tablespace_curr = _to_float(curr_metrics.get("hottest_tablespace_pct")) or 0.0
        tablespace_prev = _to_float(prev_metrics.get("hottest_tablespace_pct")) or 0.0
        if tablespace_curr >= 85 and tablespace_curr > tablespace_prev:
            add_driver(
                0.61,
                "Tablespace pressure increased",
                "tablespace_pressure",
                [f"hottest_tablespace_pct {tablespace_prev:.2f} -> {tablespace_curr:.2f}"],
            )
        elif tablespace_curr >= 85 and abs(tablespace_curr - tablespace_prev) < 0.01:
            add_driver(
                0.32,
                "Tablespace pressure persisted without worsening",
                "tablespace_pressure",
                [f"hottest_tablespace_pct persisted at {tablespace_curr:.2f}"],
            )

        plan_churn_delta = _delta(prev_metrics.get("plan_churn_count"), curr_metrics.get("plan_churn_count"))
        if plan_churn_delta > 0 and not sql_regression.get("flag"):
            add_driver(
                0.5,
                "Plan churn increased without direct SQL regression",
                "plan_instability",
                [f"plan_churn_count {prev_metrics.get('plan_churn_count') or 0} -> {curr_metrics.get('plan_churn_count') or 0}"],
            )

        if awr_diff and awr_diff.available and awr_diff.wait_class_shift.wait_class_shift_flag:
            add_driver(
                0.76,
                "Wait class shifted",
                "wait_class_shift",
                [
                    f"dominant_wait_class {awr_diff.wait_class_shift.dominant_wait_class_previous} -> "
                    f"{awr_diff.wait_class_shift.dominant_wait_class_current}"
                ],
            )
        if awr_diff and awr_diff.available and awr_diff.host_cpu_state.cpu_pressure_flag:
            add_driver(0.7, "CPU pressure increased", "resource_pressure", ["AWR host CPU section indicates pressure."])
        if awr_diff and awr_diff.available and awr_diff.io_profile.io_pressure_flag:
            add_driver(0.68, "I/O pressure increased", "resource_pressure", ["AWR I/O profile indicates higher request volume."])
        if awr_diff and awr_diff.available and awr_diff.memory_state.memory_pressure_flag:
            add_driver(0.62, "Memory pressure increased", "resource_pressure", ["AWR memory state indicates pressure growth."])

        if not (awr_diff and awr_diff.available):
            sql_cpu_delta = _delta(prev_metrics.get("top_cpu_sql_cpu_s"), curr_metrics.get("top_cpu_sql_cpu_s"))
            if sql_cpu_delta > 50:
                add_driver(
                    0.72,
                    "Top SQL CPU load increased",
                    "sql",
                    [f"top_cpu_sql_cpu_s {prev_metrics.get('top_cpu_sql_cpu_s') or 0} -> {curr_metrics.get('top_cpu_sql_cpu_s') or 0}"],
                )
            active_delta = _delta(prev_metrics.get("active_sessions"), curr_metrics.get("active_sessions"))
            if active_delta > 5:
                add_driver(
                    0.66,
                    "Active session pressure increased",
                    "transaction" if "transaction" in issue_text else "cpu",
                    [f"active_sessions {prev_metrics.get('active_sessions') or 0} -> {curr_metrics.get('active_sessions') or 0}"],
                )

        scored.sort(key=lambda item: item[0], reverse=True)
        primary = [driver.model_copy(update={"rank": "primary", "strength": round(score, 2)}) for score, driver in scored[:3]]
        secondary = [driver.model_copy(update={"rank": "secondary", "strength": round(score, 2)}) for score, driver in scored[3:8]]
        return primary, secondary

    def _determine_transition_outcome(
        self,
        *,
        previous_status: str,
        current_status: str,
        issue_transitions: list[TransitionIssueClassification],
        metric_deltas: list[MetricDelta],
    ) -> HistoricalTransitionOutcome:
        prev_rank = _severity_rank(previous_status)
        curr_rank = _severity_rank(current_status)
        if curr_rank < prev_rank:
            outcome = "recovered" if prev_rank == _severity_rank("CRITICAL") else "improved"
            return HistoricalTransitionOutcome(transition_outcome=outcome, recovery_detected=True, residual_risk_present=(curr_rank >= _severity_rank("WARNING")))
        if curr_rank > prev_rank:
            return HistoricalTransitionOutcome(transition_outcome="worsened", recovery_detected=False, residual_risk_present=True)

        worsened_signals = any(
            item.transition in {"new", "worsened"}
            for item in issue_transitions
        ) or any(
            row.state_label in {"worsened", "newly_present", "persistent_high"} and row.significance in {"HIGH", "CRITICAL"}
            for row in metric_deltas
        )
        improved_signals = any(item.transition in {"resolved", "improved"} for item in issue_transitions) or any(
            row.state_label in {"improved", "no_longer_present"} for row in metric_deltas
        )

        if worsened_signals and not improved_signals:
            return HistoricalTransitionOutcome(
                transition_outcome="persisted_but_worsened",
                recovery_detected=False,
                residual_risk_present=True,
            )
        if improved_signals and not worsened_signals:
            return HistoricalTransitionOutcome(
                transition_outcome="persisted_but_improved",
                recovery_detected=True,
                residual_risk_present=(curr_rank >= _severity_rank("WARNING")),
            )
        return HistoricalTransitionOutcome(
            transition_outcome="unchanged",
            recovery_detected=False,
            residual_risk_present=(curr_rank >= _severity_rank("WARNING")),
        )

    def _build_recovery_drivers(
        self,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        *,
        issue_transitions: list[TransitionIssueClassification],
    ) -> list[HistoricalRecoveryDriver]:
        prev_metrics = previous.metrics or {}
        curr_metrics = current.metrics or {}
        drivers: list[HistoricalRecoveryDriver] = []

        prev_blocking = _to_float(prev_metrics.get("blocking_count")) or 0.0
        curr_blocking = _to_float(curr_metrics.get("blocking_count")) or 0.0
        if prev_blocking > 0 and curr_blocking == 0:
            drivers.append(
                HistoricalRecoveryDriver(
                    title="Blocking pressure cleared",
                    category="blocker_resolution",
                    score=0.99,
                    evidence=[f"blocking_count {int(prev_blocking)} -> {int(curr_blocking)}"],
                )
            )
        elif prev_blocking > curr_blocking:
            drivers.append(
                HistoricalRecoveryDriver(
                    title="Blocking pressure reduced",
                    category="blocker_resolution",
                    score=0.86,
                    evidence=[f"blocking_count {int(prev_blocking)} -> {int(curr_blocking)}"],
                )
            )

        transaction_resolved = any(
            item.transition in {"resolved", "improved"}
            and (
                "transaction" in item.category.lower()
                or "transaction" in item.title.lower()
                or "undo" in item.category.lower()
                or "undo" in item.title.lower()
            )
            for item in issue_transitions
        )
        if transaction_resolved:
            drivers.append(
                HistoricalRecoveryDriver(
                    title="Long transaction or undo pressure eased",
                    category="long_transaction_resolution",
                    score=0.9,
                    evidence=["Transaction/undo warning moved to resolved or improved state."],
                )
            )

        prev_active = _to_float(prev_metrics.get("active_sessions")) or 0.0
        curr_active = _to_float(curr_metrics.get("active_sessions")) or 0.0
        if prev_active > curr_active:
            drivers.append(
                HistoricalRecoveryDriver(
                    title="Active session pressure reduced",
                    category="active_session_reduction",
                    score=0.66,
                    evidence=[f"active_sessions {int(prev_active)} -> {int(curr_active)}"],
                )
            )

        prev_cpu = _to_float(prev_metrics.get("host_cpu_pct"))
        curr_cpu = _to_float(curr_metrics.get("host_cpu_pct"))
        if prev_cpu is not None and curr_cpu is not None:
            if prev_cpu >= 85.0 and curr_cpu < 70.0:
                drivers.append(
                    HistoricalRecoveryDriver(
                        title="Host CPU normalized",
                        category="host_cpu_normalization",
                        score=0.64,
                        evidence=[f"host_cpu_pct {prev_cpu:.2f} -> {curr_cpu:.2f}"],
                    )
                )
            elif prev_cpu > curr_cpu and (prev_cpu - curr_cpu) >= 20.0:
                drivers.append(
                    HistoricalRecoveryDriver(
                        title="Host CPU pressure eased",
                        category="host_cpu_normalization",
                        score=0.57,
                        evidence=[f"host_cpu_pct {prev_cpu:.2f} -> {curr_cpu:.2f}"],
                    )
                )

        drivers.sort(key=lambda item: item.score, reverse=True)
        return drivers[:6]

    def _build_residual_warning_drivers(
        self,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        *,
        issue_transitions: list[TransitionIssueClassification],
        awr_diff: AwrStateDiff | None,
        sql_regression: dict[str, Any],
    ) -> list[HistoricalResidualDriver]:
        prev_metrics = previous.metrics or {}
        curr_metrics = current.metrics or {}
        drivers: list[HistoricalResidualDriver] = []

        if sql_regression.get("flag"):
            severity = str(sql_regression.get("severity") or "MEDIUM")
            severity_score = {
                "CRITICAL": 0.96,
                "HIGH": 0.9,
                "MEDIUM": 0.82,
                "LOW": 0.7,
            }.get(severity, 0.78)
            drivers.append(
                HistoricalResidualDriver(
                    title=f"SQL elapsed regression remains ({severity})",
                    category="sql_regression",
                    score=severity_score,
                    evidence=list(sql_regression.get("evidence") or [])[:3],
                    follow_up_reason="Review SQL_ID deep dive, plan/hash changes, and wait profile before mitigation.",
                )
            )

        prev_alert = _to_float(prev_metrics.get("alert_log_count")) or 0.0
        curr_alert = _to_float(curr_metrics.get("alert_log_count")) or 0.0
        alert_delta = curr_alert - prev_alert
        if alert_delta > 0:
            drivers.append(
                HistoricalResidualDriver(
                    title="ORA/TNS errors increased",
                    category="error_growth",
                    score=0.79,
                    evidence=[f"alert_log_count {int(prev_alert)} -> {int(curr_alert)}"],
                    follow_up_reason="Review alert and listener logs to isolate recurring ORA/TNS signatures.",
                )
            )
        elif curr_alert > 0:
            drivers.append(
                HistoricalResidualDriver(
                    title="ORA/TNS errors remain present",
                    category="error_growth",
                    score=0.54,
                    evidence=[f"alert_log_count persisted at {int(curr_alert)}"],
                    follow_up_reason="Keep monitoring ORA/TNS patterns until error count returns to zero.",
                )
            )

        prev_ts = _to_float(prev_metrics.get("hottest_tablespace_pct")) or 0.0
        curr_ts = _to_float(curr_metrics.get("hottest_tablespace_pct")) or 0.0
        if curr_ts >= 85.0:
            title = "Tablespace pressure increased" if curr_ts > prev_ts else "Tablespace pressure persists"
            score = 0.74 if curr_ts > prev_ts else 0.6
            drivers.append(
                HistoricalResidualDriver(
                    title=title,
                    category="persistent_storage_pressure",
                    score=score,
                    evidence=[f"hottest_tablespace_pct {prev_ts:.2f} -> {curr_ts:.2f}"],
                    follow_up_reason="Confirm growth source and capacity plan before usage approaches critical threshold.",
                )
            )

        prev_plan = _to_float(prev_metrics.get("plan_churn_count")) or 0.0
        curr_plan = _to_float(curr_metrics.get("plan_churn_count")) or 0.0
        if curr_plan > prev_plan:
            drivers.append(
                HistoricalResidualDriver(
                    title="Plan instability increased",
                    category="residual_plan_instability",
                    score=0.67,
                    evidence=[f"plan_churn_count {int(prev_plan)} -> {int(curr_plan)}"],
                    follow_up_reason="Validate plan baseline stability and recent stats/bind changes.",
                )
            )
        elif curr_plan > 0:
            drivers.append(
                HistoricalResidualDriver(
                    title="Plan instability persists",
                    category="residual_plan_instability",
                    score=0.52,
                    evidence=[f"plan_churn_count persisted at {int(curr_plan)}"],
                    follow_up_reason="Continue monitoring plan churn across subsequent health runs.",
                )
            )

        stale_count = _to_float(curr_metrics.get("stale_stats_count")) or 0.0
        if stale_count > 0:
            drivers.append(
                HistoricalResidualDriver(
                    title="Stale statistics remain in warning overlap",
                    category="persistent_background_noise_with_warning_overlap",
                    score=0.46,
                    evidence=[f"stale_stats_count={int(stale_count)}"],
                    follow_up_reason="Refresh stale objects to reduce optimizer drift during peak workload.",
                )
            )

        curr_blocking = _to_float(curr_metrics.get("blocking_count")) or 0.0
        if curr_blocking > 0:
            drivers.append(
                HistoricalResidualDriver(
                    title="Residual wait pressure from blocking remains",
                    category="residual_wait_pressure",
                    score=0.85,
                    evidence=[f"blocking_count remained at {int(curr_blocking)}"],
                    follow_up_reason="Validate blocker ownership and wait chains before remediation actions.",
                )
            )
        elif awr_diff and awr_diff.available and awr_diff.wait_class_shift.wait_class_shift_flag:
            drivers.append(
                HistoricalResidualDriver(
                    title="Wait-class pressure shifted materially",
                    category="residual_wait_pressure",
                    score=0.62,
                    evidence=[
                        f"dominant_wait_class {awr_diff.wait_class_shift.dominant_wait_class_previous} -> "
                        f"{awr_diff.wait_class_shift.dominant_wait_class_current}"
                    ],
                    follow_up_reason="Correlate shifted wait class with SQL, object, and concurrency evidence.",
                )
            )

        for issue in issue_transitions:
            if issue.transition in {"new", "worsened"} and issue.current_severity in {"WARNING", "CRITICAL"}:
                if "background" in issue.title.lower() or "stale" in issue.title.lower():
                    drivers.append(
                        HistoricalResidualDriver(
                            title=f"Persistent warning overlap: {issue.title}",
                            category="persistent_background_noise_with_warning_overlap",
                            score=0.42,
                            evidence=[f"{issue.category}: {issue.transition} ({issue.previous_severity} -> {issue.current_severity})"],
                            follow_up_reason="Track persistence across additional runs to confirm operational impact.",
                        )
                    )
                    break

        deduped: list[HistoricalResidualDriver] = []
        seen: set[tuple[str, str]] = set()
        for driver in sorted(drivers, key=lambda item: item.score, reverse=True):
            key = (driver.category, driver.title)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(driver)
        return deduped[:8]

    def _compose_transition_drivers(
        self,
        *,
        transition_outcome: str,
        recovery_drivers: list[HistoricalRecoveryDriver],
        residual_drivers: list[HistoricalResidualDriver],
        fallback_primary: list[TransitionDriver],
        fallback_secondary: list[TransitionDriver],
    ) -> tuple[list[TransitionDriver], list[TransitionDriver]]:
        merged: list[TransitionDriver] = []
        recovery_as_transition = [
            TransitionDriver(
                name=driver.title,
                driver_type=self._transition_driver_type_for_recovery(driver.category),
                strength=round(driver.score, 2),
                evidence=list(driver.evidence),
            )
            for driver in recovery_drivers
        ]
        residual_as_transition = [
            TransitionDriver(
                name=driver.title,
                driver_type=self._transition_driver_type_for_residual(driver.category),
                strength=round(driver.score, 2),
                evidence=list(driver.evidence) + ([driver.follow_up_reason] if driver.follow_up_reason else []),
            )
            for driver in residual_drivers
        ]

        if transition_outcome in {"recovered", "improved", "persisted_but_improved"}:
            merged.extend(recovery_as_transition)
            merged.extend(residual_as_transition)
        elif transition_outcome in {"worsened", "persisted_but_worsened"}:
            merged.extend(residual_as_transition)
            merged.extend(recovery_as_transition)
        else:
            merged.extend(residual_as_transition)
            merged.extend(recovery_as_transition)

        if not merged:
            return fallback_primary, fallback_secondary

        primary = [
            driver.model_copy(update={"rank": "primary", "strength": round(driver.strength or 0.0, 2)})
            for driver in merged[:3]
        ]
        secondary = [
            driver.model_copy(update={"rank": "secondary", "strength": round(driver.strength or 0.0, 2)})
            for driver in merged[3:8]
        ]
        if not secondary and fallback_secondary:
            secondary = fallback_secondary[:5]
        return primary, secondary

    def _transition_driver_type_for_recovery(self, category: str) -> str:
        return {
            "blocker_resolution": "blocking",
            "long_transaction_resolution": "long_transaction",
            "active_session_reduction": "transaction",
            "host_cpu_normalization": "cpu",
        }.get(category, "other")

    def _transition_driver_type_for_residual(self, category: str) -> str:
        return {
            "sql_regression": "sql_regression",
            "error_growth": "ora_error_emergence",
            "persistent_storage_pressure": "tablespace_pressure",
            "persistent_background_noise_with_warning_overlap": "persistent_background_noise",
            "residual_wait_pressure": "wait_class_shift",
            "residual_plan_instability": "plan_instability",
        }.get(category, "other")

    def _awr_user_message(self, *, awr_diff: AwrStateDiff | None, fallback_mode: str, notes: list[str]) -> str:
        text_enriched = bool(awr_diff and awr_diff.awr_report_text_summary and awr_diff.awr_report_text_summary.available)
        if fallback_mode == "none" and awr_diff and awr_diff.available:
            if awr_diff.awr_mode == "single_window_interpretation":
                if text_enriched:
                    return "AWR used single-window interpretation with report-text enrichment; historical context was applied."
                return "AWR used single-window interpretation; historical context was applied."
            if text_enriched:
                return "AWR workload comparison used run-pair snapshot windows and was enriched with AWR report-text summaries."
            return "AWR workload comparison used run-pair snapshot windows."
        if fallback_mode == "awr_same_window_weak":
            if text_enriched:
                return "AWR used single-window interpretation with report-text enrichment; comparison is not applicable."
            return "AWR used single-window interpretation because both runs resolved to the same snapshot window."
        if fallback_mode == "awr_metric_incomplete":
            if text_enriched:
                return (
                    "AWR snapshots mapped successfully, but structured metric rows were incomplete; AWR report-text summaries were used for richer context."
                )
            return "AWR snapshots mapped successfully, but metric rows were incomplete; partial AWR comparison was used."
        if fallback_mode == "awr_query_failure":
            return "AWR query failed while building workload comparison; JSONL fallback used."
        if fallback_mode == "awr_mapping_weak":
            return "AWR snapshots were found but mapping strength was weak; JSONL fallback used."
        if fallback_mode == "awr_capability_failure":
            return "AWR capability check failed; JSONL fallback used."
        if fallback_mode == "awr_unavailable":
            return "AWR source is unavailable; JSONL fallback used."
        if fallback_mode == "awr_disabled":
            return "AWR workload comparison is disabled; JSONL fallback used."
        if notes:
            return str(notes[0])
        return "AWR workload comparison unavailable; JSONL fallback used."

    def _awr_source_summary(self, *, awr_diff: AwrStateDiff | None, fallback_mode: str) -> str:
        text_enriched = bool(awr_diff and awr_diff.awr_report_text_summary and awr_diff.awr_report_text_summary.available)
        if awr_diff and awr_diff.available:
            if awr_diff.awr_mode == "single_window_interpretation":
                if text_enriched:
                    return "AWR source: single-window analysis with report-text enrichment (comparison not applicable)"
                return "AWR source: single-window analysis (comparison not applicable)"
            if fallback_mode == "awr_same_window_weak":
                if text_enriched:
                    return "AWR source: single-window analysis with report-text enrichment (comparison not applicable)"
                return "AWR source: single-window analysis (comparison not applicable)"
            if fallback_mode == "awr_metric_incomplete":
                if text_enriched:
                    return "AWR source: available, partial metrics + report-text enrichment"
                return "AWR source: available, partial metrics"
            if text_enriched:
                return "AWR source: available, run-pair diff + report-text enrichment"
            return "AWR source: available, run-pair workload diff used"
        if fallback_mode == "awr_disabled":
            return "AWR source: disabled, JSONL fallback used"
        if fallback_mode == "awr_unavailable":
            return "AWR source: unavailable, JSONL fallback used"
        if fallback_mode == "awr_query_failure":
            return "AWR source: query failure, JSONL fallback used"
        if fallback_mode == "awr_capability_failure":
            return "AWR source: capability check failed, JSONL fallback used"
        if fallback_mode == "awr_mapping_weak":
            return "AWR source: snapshot mapping weak, JSONL fallback used"
        return "AWR source: unavailable, JSONL fallback used"

    def _awr_workload_interpretation(self, *, awr_diff: AwrStateDiff | None, fallback_mode: str) -> str:
        if awr_diff and awr_diff.awr_mode == "single_window_interpretation":
            return "AWR single-window interpretation is used because previous and current runs mapped to the same snapshot interval."
        if awr_diff and awr_diff.available and awr_diff.workload_interpretation.summary:
            if awr_diff.awr_report_text_summary and awr_diff.awr_report_text_summary.available:
                return awr_diff.workload_interpretation.summary + " AWR report-text summary was used to supplement sparse sections."
            return awr_diff.workload_interpretation.summary
        if fallback_mode in {"awr_metric_incomplete", "awr_same_window_weak"}:
            return "AWR workload interpretation is partial due to limited snapshot comparability or incomplete metric rows."
        if fallback_mode != "none":
            return "AWR workload interpretation unavailable; transition reasoning is based on JSONL trend evidence."
        return "AWR workload interpretation unavailable."

    def _snapshot_mapping_summary(self, *, awr_diff: AwrStateDiff | None) -> str:
        if not awr_diff or not awr_diff.window_mapping:
            return "Snapshot mapping unavailable."
        previous = awr_diff.window_mapping.previous
        current = awr_diff.window_mapping.current
        prev_window = f"SNAP {previous.begin_snap_id}..{previous.end_snap_id}" if previous.begin_snap_id is not None else "unmapped"
        curr_window = f"SNAP {current.begin_snap_id}..{current.end_snap_id}" if current.begin_snap_id is not None else "unmapped"
        return f"Previous window: {prev_window}; Current window: {curr_window}"

    def _section_naming_for_outcome(self, transition_outcome: str) -> HistoricalSectionNaming:
        if transition_outcome in {"recovered", "improved", "persisted_but_improved"}:
            return HistoricalSectionNaming(
                primary_driver_section_title="Recovery Drivers",
                secondary_driver_section_title="Residual Warning Drivers",
            )
        if transition_outcome in {"worsened", "persisted_but_worsened"}:
            return HistoricalSectionNaming(
                primary_driver_section_title="Incident Drivers",
                secondary_driver_section_title="Persistent Background Risks",
            )
        return HistoricalSectionNaming(
            primary_driver_section_title="Persistent Drivers",
            secondary_driver_section_title="Worsening Signals",
        )

    def _learning_features(
        self,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        issue_transitions: list[TransitionIssueClassification],
        awr_diff: AwrStateDiff | None,
        sql_regression: dict[str, Any],
        primary_drivers: list[TransitionDriver],
        fallback_mode: str,
    ) -> LearningFeatureVector:
        prev_metrics = previous.metrics or {}
        curr_metrics = current.metrics or {}

        plan_change_flag = bool((_to_float(curr_metrics.get("plan_churn_count")) or 0) > 0)
        dominant_sql_changed = str(prev_metrics.get("top_cpu_sql_id") or "") != str(curr_metrics.get("top_cpu_sql_id") or "")
        blocking_delta = _delta(prev_metrics.get("blocking_count"), curr_metrics.get("blocking_count"))
        blocking_persistent_flag = bool(
            (_to_float(prev_metrics.get("blocking_count")) or 0) > 0
            and (_to_float(curr_metrics.get("blocking_count")) or 0) > 0
        )
        alert_delta = _delta(prev_metrics.get("alert_log_count"), curr_metrics.get("alert_log_count"))
        new_alert_flag = bool((_to_float(prev_metrics.get("alert_log_count")) or 0) == 0 and (_to_float(curr_metrics.get("alert_log_count")) or 0) > 0)
        sql_elapsed_delta = _delta(prev_metrics.get("top_elapsed_sql_elapsed_s"), curr_metrics.get("top_elapsed_sql_elapsed_s"))
        sql_cpu_delta = _delta(prev_metrics.get("top_cpu_sql_cpu_s"), curr_metrics.get("top_cpu_sql_cpu_s"))
        blocking_amplification_flag = (blocking_delta > 0 or blocking_persistent_flag) and any(
            item.transition in {"persistent", "worsened"} and "lock" in f"{item.category} {item.title}".lower()
            for item in issue_transitions
        )
        dominant_sql_persistent_flag = bool(
            str(prev_metrics.get("top_cpu_sql_id") or "") != ""
            and str(prev_metrics.get("top_cpu_sql_id") or "") == str(curr_metrics.get("top_cpu_sql_id") or "")
        )
        state_persisted_but_worsened_flag = bool(
            str(previous.overall_status or "") == str(current.overall_status or "")
            and (
                sql_elapsed_delta >= SQL_REGRESSION_ABS_THRESHOLD
                or blocking_amplification_flag
                or any(item.transition == "persistent" and item.current_severity in {"WARNING", "CRITICAL"} for item in issue_transitions)
            )
        )
        persistent_issue_with_higher_impact_flag = bool(
            any(item.transition == "persistent" for item in issue_transitions)
            and (sql_elapsed_delta > 0 or alert_delta > 0 or blocking_delta > 0)
        )
        transaction_anomaly_flag = any(
            item.transition in {"new", "worsened"}
            and ("transaction" in item.category.lower() or "transaction" in item.title.lower() or "undo" in item.category.lower() or "undo" in item.title.lower())
            for item in issue_transitions
        )
        incident_driver_category = primary_drivers[0].driver_type if primary_drivers else None

        if awr_diff and awr_diff.available:
            dominant_sql_changed = dominant_sql_changed or awr_diff.sql_change.dominant_sql_changed_flag
            plan_change_flag = plan_change_flag or awr_diff.sql_change.plan_hash_changed_flag

        return LearningFeatureVector(
            status_delta=float(_severity_rank(str(current.overall_status or "INFO")) - _severity_rank(str(previous.overall_status or "INFO"))),
            state_persisted_but_worsened_flag=state_persisted_but_worsened_flag,
            persistent_issue_with_higher_impact_flag=persistent_issue_with_higher_impact_flag,
            blocking_delta=blocking_delta,
            blocking_persistent_flag=blocking_persistent_flag,
            alert_delta=alert_delta,
            new_alert_flag=new_alert_flag,
            sql_elapsed_delta=sql_elapsed_delta,
            sql_cpu_delta=sql_cpu_delta,
            sql_regression_flag=bool(sql_regression.get("flag")),
            sql_regression_severity=str(sql_regression.get("severity") or "NONE"),
            sql_regression_evidence=list(sql_regression.get("evidence") or []),
            incident_driver_sql=str(curr_metrics.get("top_elapsed_sql_id") or curr_metrics.get("top_cpu_sql_id") or "") or None,
            sql_amplified_by_blocking_flag=bool(sql_regression.get("sql_amplified_by_blocking_flag")),
            dominant_sql_changed_flag=dominant_sql_changed,
            dominant_sql_persistent_flag=dominant_sql_persistent_flag,
            wait_class_shift_flag=bool(awr_diff.wait_class_shift.wait_class_shift_flag) if awr_diff and awr_diff.available else False,
            cpu_to_io_shift_flag=bool(awr_diff.wait_class_shift.cpu_to_io_shift) if awr_diff and awr_diff.available else False,
            plan_change_flag=plan_change_flag,
            memory_pressure_flag=bool(awr_diff.memory_state.memory_pressure_flag) if awr_diff and awr_diff.available else False,
            blocking_amplification_flag=blocking_amplification_flag,
            transaction_anomaly_flag=transaction_anomaly_flag,
            incident_driver_category=incident_driver_category,
            transition_confidence_reason=f"fallback_mode={fallback_mode}",
        )

    def _build_comparison_window(self, previous: TraceHealthRunRecord, current: TraceHealthRunRecord) -> HistoricalComparisonWindow:
        prev_dt = _parse_dt(previous.completed_at)
        curr_dt = _parse_dt(current.completed_at)
        if prev_dt is None or curr_dt is None:
            return HistoricalComparisonWindow(notes=["Could not parse run timestamps for comparison window."], window_confidence="LOW")

        gap_minutes = max((curr_dt - prev_dt).total_seconds() / 60.0, 1.0)
        half_gap = gap_minutes / 2.0
        base_window = min(30.0, half_gap)
        prev_window_start = prev_dt - timedelta(minutes=base_window)
        curr_window_end = curr_dt + timedelta(minutes=base_window)
        overlap_adjusted = (prev_dt + timedelta(minutes=base_window)) > (curr_dt - timedelta(minutes=base_window))

        notes = [f"Adaptive window size={base_window:.1f} minutes based on run gap={gap_minutes:.1f} minutes."]
        if overlap_adjusted:
            notes.append("Window overlap adjustment applied because runs were close together.")
        return HistoricalComparisonWindow(
            window_start=prev_window_start.isoformat(),
            window_end=curr_window_end.isoformat(),
            window_duration_minutes=round((curr_window_end - prev_window_start).total_seconds() / 60.0, 2),
            window_overlap_adjusted=overlap_adjusted,
            window_confidence="HIGH" if base_window >= 15 else "MEDIUM",
            notes=notes,
        )

    def _build_metric_deltas(self, previous: TraceHealthRunRecord, current: TraceHealthRunRecord) -> list[MetricDelta]:
        prev_metrics = previous.metrics or {}
        curr_metrics = current.metrics or {}
        metric_specs = [
            ("blocking_count", "Blocking Sessions"),
            ("alert_log_count", "Alert ORA/TNS Count"),
            ("top_elapsed_sql_elapsed_s", "Top SQL Elapsed Seconds"),
            ("top_cpu_sql_cpu_s", "Top SQL CPU Seconds"),
            ("hottest_tablespace_pct", "Highest Tablespace %"),
            ("plan_churn_count", "Plan Churn Count"),
            ("stale_stats_count", "Stale Stats Count"),
            ("host_cpu_pct", "Host CPU %"),
            ("host_memory_pct", "Host Memory %"),
        ]
        out: list[MetricDelta] = []
        for key, label in metric_specs:
            previous_value = _to_float(prev_metrics.get(key))
            current_value = _to_float(curr_metrics.get(key))
            delta = _delta(previous_value, current_value) if (previous_value is not None or current_value is not None) else None
            pct_delta = _pct_delta(previous_value, current_value)
            state_label = _metric_state_label(
                previous_value=previous_value,
                current_value=current_value,
                high_threshold=METRIC_HIGH_THRESHOLDS.get(key),
            )
            significance = _metric_significance(state_label=state_label, absolute_delta=delta, percent_delta=pct_delta)
            interpretation = _metric_interpretation(label=label, state_label=state_label, previous=previous_value, current=current_value, delta=delta)
            out.append(
                MetricDelta(
                    metric_name=label,
                    previous_value=previous_value,
                    current_value=current_value,
                    absolute_delta=delta,
                    percent_delta=pct_delta,
                    state_label=state_label,
                    significance=significance,
                    interpretation=interpretation,
                )
            )
        return out

    def _historical_issue_states(self, issue_transitions: list[TransitionIssueClassification]) -> list[HistoricalIssueState]:
        out: list[HistoricalIssueState] = []
        for issue in issue_transitions:
            state_label = _transition_to_state_label(issue.transition, issue.previous_severity, issue.current_severity)
            impact_changed = issue.transition in {"worsened", "improved"} or (
                issue.transition == "persistent" and issue.current_severity in {"WARNING", "CRITICAL"}
            )
            out.append(
                HistoricalIssueState(
                    category=issue.category,
                    title=issue.title,
                    previous_severity=issue.previous_severity,
                    current_severity=issue.current_severity,
                    state_label=state_label,
                    impact_changed=impact_changed,
                    interpretation=f"{issue.title}: {state_label} ({issue.previous_severity} -> {issue.current_severity})",
                )
            )
        return out

    def _build_event_timeline(
        self,
        *,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        recovery_drivers: list[HistoricalRecoveryDriver],
        residual_drivers: list[HistoricalResidualDriver],
        transition_outcome: str,
        learning: LearningFeatureVector,
        awr_user_message: str,
        awr_diff: AwrStateDiff | None,
    ) -> list[HistoricalEventTimelineEntry]:
        previous_notes: list[str] = []
        current_notes: list[str] = []
        current_notes.extend(driver.title for driver in recovery_drivers[:2])
        current_notes.extend(driver.title for driver in residual_drivers[:2])
        if learning.state_persisted_but_worsened_flag:
            current_notes.append("State persisted with worsening internal impact.")
        if awr_user_message and "fallback" in awr_user_message.lower():
            current_notes.append(awr_user_message)

        transition_label = transition_outcome.replace("_", " ")
        awr_mild = bool(
            awr_diff
            and awr_diff.available
            and awr_diff.workload_interpretation
            and awr_diff.workload_interpretation.low_significance_majority
        )
        awr_material = bool(
            awr_diff
            and awr_diff.available
            and awr_diff.workload_interpretation
            and awr_diff.workload_interpretation.material_change_detected
        )
        if transition_outcome in {"recovered", "improved", "persisted_but_improved"}:
            recovery_text = recovery_drivers[0].title.lower() if recovery_drivers else "material pressure eased"
            residual_text = residual_drivers[0].title.lower() if residual_drivers else "no residual warning drivers remained"
            current_summary = (
                f"Status improved to {str(current.overall_status or 'INFO').upper()} after {recovery_text}; "
                f"residual signal: {residual_text}."
            )
        elif transition_outcome in {"worsened", "persisted_but_worsened"}:
            residual_text = residual_drivers[0].title.lower() if residual_drivers else "warning pressure increased"
            if awr_mild:
                current_summary = (
                    f"Status worsened to {str(current.overall_status or 'INFO').upper()}. "
                    f"AWR workload deltas were mild, but {residual_text} remained the primary risk driver."
                )
            elif awr_material:
                current_summary = (
                    f"Status worsened to {str(current.overall_status or 'INFO').upper()} with material AWR workload change and primary driver: {residual_text}."
                )
            else:
                current_summary = (
                    f"Status worsened to {str(current.overall_status or 'INFO').upper()} with primary driver: {residual_text}."
                )
        else:
            if transition_outcome == "persisted_but_worsened":
                current_summary = (
                    f"Status remained {str(current.overall_status or 'INFO').upper()} with stronger internal pressure and persistent warning drivers."
                )
            elif transition_outcome == "persisted_but_improved":
                current_summary = (
                    f"Status remained {str(current.overall_status or 'INFO').upper()} with measurable internal recovery drivers."
                )
            else:
                current_summary = (
                    f"Status stayed {str(current.overall_status or 'INFO').upper()} ({transition_label}); no dominant directional shift was detected."
                )
        return [
            HistoricalEventTimelineEntry(
                at=previous.completed_at,
                summary=previous.summary or "Previous health run",
                change_notes=previous_notes or ["Baseline reference run."],
                source="JSONL",
                impact_level="MEDIUM" if str(previous.overall_status or "INFO") in {"WARNING", "CRITICAL"} else "LOW",
            ),
            HistoricalEventTimelineEntry(
                at=current.completed_at,
                summary=current_summary,
                change_notes=current_notes or ["No major incident-driver transition detected."],
                source="JSONL+AWR" if "run-pair" in awr_user_message.lower() else "JSONL",
                impact_level="CRITICAL" if str(current.overall_status or "INFO") == "CRITICAL" else "HIGH",
            ),
        ]

    def _suppressed_background_signals(
        self,
        *,
        traces: list[TraceHealthRunRecord],
        issue_transitions: list[TransitionIssueClassification],
        primary_drivers: list[TransitionDriver],
    ) -> list[HistoricalTransitionDriver]:
        primary_types = {driver.driver_type for driver in primary_drivers}
        issue_counter: Counter[str] = Counter()
        for trace in traces:
            for issue in trace.issues:
                issue_counter[issue.title] += 1
        suppressed: list[HistoricalTransitionDriver] = []
        for issue in issue_transitions:
            recurrence_count = issue_counter.get(issue.title, 0)
            if recurrence_count < 2:
                continue
            if issue.transition in {"persistent", "improved"} and issue.current_severity in {"OK", "WARNING"}:
                category = "persistent_background_noise"
                if "stale" in issue.title.lower() or "stats" in issue.title.lower():
                    category = "stale_stats_noise"
                if category in primary_types:
                    continue
                suppressed.append(
                    HistoricalTransitionDriver(
                        name=issue.title,
                        category=category,
                        score=0.2,
                        rank="suppressed",
                        evidence=[f"recurrence_count={recurrence_count}", f"state={issue.transition}"],
                        transition_relevance_score=0.2,
                        recurrence_count=recurrence_count,
                        persistence_score=0.7,
                        recency_score=0.4,
                        severity_overlap_score=0.3,
                    )
                )
        suppressed.sort(key=lambda item: item.score, reverse=True)
        return suppressed[:6]

    def _to_historical_driver(self, driver: TransitionDriver, *, rank: str) -> HistoricalTransitionDriver:
        return HistoricalTransitionDriver(
            name=driver.name,
            category=driver.driver_type,
            score=driver.strength,
            rank=rank,
            evidence=driver.evidence,
            transition_relevance_score=driver.strength,
            recurrence_count=0,
            persistence_score=0.0,
            recency_score=1.0,
            severity_overlap_score=driver.strength,
        )

    def _rank_recurring_patterns(
        self,
        *,
        traces: list[TraceHealthRunRecord],
        primary_drivers: list[TransitionDriver],
        suppressed: list[HistoricalTransitionDriver],
    ) -> list[str]:
        issue_counter: Counter[str] = Counter()
        critical_counter: Counter[str] = Counter()
        for trace in traces:
            for issue in trace.issues:
                issue_counter[issue.title] += 1
                if str(issue.severity) == "CRITICAL":
                    critical_counter[issue.title] += 1
        suppressed_names = {item.name for item in suppressed}
        primary_text = " ".join(driver.name.lower() + " " + driver.driver_type for driver in primary_drivers)
        ranked: list[tuple[float, str]] = []
        for title, count in issue_counter.items():
            persistence = count / max(len(traces), 1)
            recency = 1.0
            severity_overlap = critical_counter.get(title, 0) / max(count, 1)
            relevance = 1.0 if title.lower() in primary_text else (0.25 if title in suppressed_names else 0.5)
            score = (count * 0.15) + (persistence * 0.3) + (recency * 0.2) + (severity_overlap * 0.2) + (relevance * 0.6)
            ranked.append(
                (
                    score,
                    f"{title}: recurrence={count}, persistence={persistence:.2f}, "
                    f"severity_overlap={severity_overlap:.2f}, transition_relevance={relevance:.2f}",
                )
            )
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [text for _, text in ranked[:10]]

    def _interpret_transition_patterns(
        self,
        *,
        issue_transitions: list[TransitionIssueClassification],
        primary_drivers: list[TransitionDriver],
        learning: LearningFeatureVector,
    ) -> list[str]:
        notes: list[str] = []
        persistent = [item for item in issue_transitions if item.transition == "persistent"]
        amplified = [item for item in persistent if item.current_severity == item.previous_severity and item.current_severity in {"WARNING", "CRITICAL"}]
        if amplified and learning.blocking_amplification_flag:
            labels = ", ".join(item.title for item in amplified[:3])
            notes.append(f"Persistent but amplified issues: {labels}.")

        high_impact_new = [item for item in issue_transitions if item.transition in {"new", "worsened"} and item.current_severity == "CRITICAL"]
        if high_impact_new:
            labels = ", ".join(item.title for item in high_impact_new[:3])
            notes.append(f"New/high-impact issues detected: {labels}.")

        if len(primary_drivers) >= 2:
            combined = " + ".join(driver.driver_type for driver in primary_drivers[:2])
            notes.append(f"Combined-effect pattern detected: {combined}.")
        return notes

    def _transition_confidence(
        self,
        *,
        primary_drivers: list[TransitionDriver],
        awr_diff: AwrStateDiff | None,
        metric_deltas: list[MetricDelta],
        fallback_mode: str,
    ) -> tuple[str, str]:
        critical_delta_present = any(item.significance == "CRITICAL" for item in metric_deltas)
        strong_primary = bool(primary_drivers and (primary_drivers[0].strength or 0.0) >= 0.95)
        awr_high = bool(awr_diff and awr_diff.available and awr_diff.snapshot_quality.confidence == "HIGH")
        if awr_high and len(primary_drivers) >= 2:
            return "HIGH", "AWR and JSONL evidence agree on primary drivers."
        if strong_primary and critical_delta_present:
            return "HIGH", "JSONL metric deltas and weighted drivers strongly indicate incident transition."
        if len(primary_drivers) >= 1:
            if fallback_mode != "none":
                return "MEDIUM", f"Inference used fallback mode {fallback_mode} with strong JSONL evidence."
            return "MEDIUM", "At least one high-confidence transition driver was identified."
        return "LOW", "Insufficient driver strength or missing key metrics for high-confidence transition."

    def _history_source_used(self, awr_diff: AwrStateDiff | None, fallback_mode: str) -> str:
        if awr_diff and awr_diff.available:
            has_ash = bool(awr_diff.ash_state and awr_diff.ash_state.source)
            return "ASH+JSONL" if has_ash else "AWR+JSONL"
        if fallback_mode == "none":
            return "JSONL only"
        return "JSONL only"

    def _issue_key(self, issue: HealthIssue) -> str:
        return f"{issue.category}|{issue.title}".lower()

    def _bucket(self, value: Any, *, warning: float, critical: float) -> str:
        number = _to_float(value)
        if number is None:
            return "unknown"
        if number >= critical:
            return "critical"
        if number >= warning:
            return "warning"
        return "normal"

    def _bucket_label(self, value: Any, *, warning: float, critical: float, labels: tuple[str, str, str]) -> str:
        number = _to_float(value)
        if number is None:
            return labels[0]
        if number >= critical:
            return labels[2]
        if number >= warning:
            return labels[1]
        return labels[0]

    def _historical_run(self, trace: TraceHealthRunRecord) -> HistoricalRun:
        return HistoricalRun(
            run_id=trace.run_id,
            completed_at=trace.completed_at,
            database_name=trace.database_name,
            overall_status=trace.overall_status,
            trace_path=trace.trace_path,
            summary=trace.summary,
            metrics=trace.metrics,
            issues=trace.issues,
        )

    def _historical_run_from_summary(self, payload: dict[str, Any]) -> HistoricalRun:
        issues: list[HealthIssue] = []
        for item in payload.get("issues") or []:
            try:
                issues.append(HealthIssue.model_validate(item))
            except Exception:
                continue
        return HistoricalRun(
            run_id=str(payload.get("run_id") or ""),
            completed_at=str(payload.get("completed_at") or payload.get("recorded_at") or ""),
            database_name=payload.get("database_name"),
            overall_status=payload.get("overall_status"),
            trace_path=payload.get("trace_path"),
            summary=str(payload.get("summary") or ""),
            metrics=dict(payload.get("metrics") or {}),
            issues=issues,
        )


def _infer_domain(text: str) -> str | None:
    lowered = (text or "").lower()
    for domain, tokens in {
        "cpu": ("cpu", "ash", "top sql"),
        "memory": ("memory", "pga", "sga", "swap"),
        "storage": ("tablespace", "temp", "fra", "storage", "archive"),
        "errors": ("ora", "tns", "alert", "listener", "error"),
        "sql": ("sql", "sql_id", "plan", "elapsed", "awr"),
        "blocking": ("blocking", "lock", "locks"),
        "transition": ("transition", "changed", "change", "previous", "current", "driver"),
    }.items():
        if any(_contains_domain_token(lowered, token) for token in tokens):
            return domain
    return None


def _contains_domain_token(text: str, token: str) -> bool:
    if token == "ora":
        return "ora-" in text or re.search(r"\bora\b", text) is not None
    if token == "tns":
        return "tns-" in text or re.search(r"\btns\b", text) is not None
    if " " in token:
        return token in text
    return re.search(rf"\b{re.escape(token)}\b", text) is not None


def _to_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _to_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _delta(previous: Any, current: Any) -> float:
    prev = _to_float(previous) or 0.0
    curr = _to_float(current) or 0.0
    return round(curr - prev, 4)


def _severity_rank(value: str) -> int:
    normalized = (value or "INFO").upper()
    return {
        "INFO": 0,
        "OK": 1,
        "WARNING": 2,
        "CRITICAL": 3,
    }.get(normalized, 0)


def _latest_and_previous(values: list[float | None]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    latest = values[-1]
    previous = None
    for value in reversed(values[:-1]):
        if value is not None:
            previous = value
            break
    return latest, previous


def _trend_direction(*, latest: float | None, previous: float | None) -> str:
    return _metric_state_label(previous_value=previous, current_value=latest, high_threshold=None)


def _trend_summary(label: str, values: list[float], direction: str, *, previous: float | None, latest: float | None) -> str:
    latest_value = latest if latest is not None else (values[-1] if values else 0.0)
    if len(values) == 1:
        return f"{label} is {direction}; latest={latest_value:.2f}."
    prev_text = f"{previous:.2f}" if previous is not None else "n/a"
    return (
        f"{label} is {direction}; latest={latest_value:.2f}, "
        f"previous={prev_text}, min={min(values):.2f}, max={max(values):.2f} "
        f"across {len(values)} run(s)."
    )


def _pct_delta(previous_value: float | None, current_value: float | None) -> float | None:
    if previous_value is None or current_value is None:
        return None
    if previous_value == 0:
        return 100.0 if current_value != 0 else 0.0
    return round(((current_value - previous_value) / abs(previous_value)) * 100.0, 2)


def _metric_state_label(
    *,
    previous_value: float | None,
    current_value: float | None,
    high_threshold: float | None,
) -> str:
    if previous_value is None and current_value is None:
        return "missing_data"
    if previous_value in {None, 0} and (current_value or 0) > 0:
        return "newly_present"
    if (previous_value or 0) > 0 and current_value in {None, 0}:
        return "no_longer_present"
    if previous_value is None or current_value is None:
        return "missing_data"
    if current_value == previous_value:
        if current_value == 0:
            return "unchanged"
        if high_threshold is not None and current_value >= high_threshold:
            return "persistent_high"
        if high_threshold is not None and current_value < max(high_threshold * 0.3, 1):
            return "persistent_low"
        return "persistent_nonzero"
    delta = current_value - previous_value
    tolerance = max(abs(previous_value) * 0.05, 0.01)
    if delta > 0:
        return "worsened" if delta > tolerance else "increased"
    return "improved" if abs(delta) > tolerance else "decreased"


def _metric_significance(*, state_label: str, absolute_delta: float | None, percent_delta: float | None) -> str:
    magnitude = abs(percent_delta or 0.0)
    delta_abs = abs(absolute_delta or 0.0)
    if state_label in {"worsened", "newly_present"} and (magnitude >= 300 or delta_abs >= SQL_REGRESSION_CRITICAL_ABS_THRESHOLD):
        return "CRITICAL"
    if state_label in {"worsened", "increased", "persistent_high"} and (magnitude >= 100 or delta_abs >= 120):
        return "HIGH"
    if state_label in {"improved", "decreased", "persistent_nonzero", "newly_present"} and (magnitude >= 20 or delta_abs >= 10):
        return "MEDIUM"
    return "LOW"


def _metric_interpretation(
    *,
    label: str,
    state_label: str,
    previous: float | None,
    current: float | None,
    delta: float | None,
) -> str:
    if state_label == "newly_present":
        return f"{label} newly appeared ({previous or 0} -> {current or 0})."
    if state_label == "no_longer_present":
        return f"{label} dropped to zero ({previous or 0} -> {current or 0})."
    if state_label == "persistent_nonzero":
        return f"{label} persisted at non-zero level ({current or 0})."
    if state_label == "persistent_high":
        return f"{label} remained high ({current or 0}), indicating sustained pressure."
    if state_label == "worsened":
        return f"{label} worsened by {delta or 0:.2f}."
    if state_label == "improved":
        return f"{label} improved by {abs(delta or 0):.2f}."
    return f"{label} state={state_label} ({previous} -> {current})."


def _transition_to_state_label(transition: str, previous_severity: str | None, current_severity: str | None) -> str:
    mapping = {
        "new": "newly_present",
        "resolved": "no_longer_present",
        "persistent": "persistent_nonzero",
        "worsened": "worsened",
        "improved": "improved",
        "intermittent": "unchanged",
    }
    if transition == "persistent" and current_severity in {"CRITICAL", "WARNING"} and previous_severity == current_severity:
        return "persistent_high"
    return mapping.get(transition, "unchanged")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except Exception:
        return None


def _awr_feature_enabled() -> bool:
    return os.getenv("ODB_AUTODBA_ENABLE_AWR_HISTORY", "true").strip().lower() in {"1", "true", "yes", "on"}
