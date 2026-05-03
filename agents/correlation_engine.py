from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from odb_autodba.rag.trace_store import (
    health_run_trace_path,
    read_health_run_traces,
    read_history_index_entries,
    read_recurring_issue_index,
    read_trace_evidence_chunks,
)
from odb_autodba.runtime_paths import get_indexes_dir, get_traces_dir


KNOWN_METRIC_HINTS = [
    "cpu",
    "memory",
    "pga",
    "sga",
    "temp",
    "undo",
    "wait",
    "blocking",
    "alert",
    "error",
    "tablespace",
    "fra",
    "redo",
    "cache",
    "sql",
    "elapsed",
    "execution",
    "parse",
    "plan",
    "invalid",
    "session",
    "process",
    "filesystem",
    "disk",
    "io",
    "latency",
]

HUGE_TEXT_KEYS = {
    "report_markdown",
    "mount_output",
    "df_output",
    "awr_report_text",
    "raw_text",
}

ENTITY_KEYS = {
    "sql_id": "sql_id",
    "sid": "sid",
    "serial": "serial",
    "serial#": "serial",
    "blocking_session": "blocking_session",
    "event": "event",
    "wait_class": "wait_class",
    "object_name": "object_name",
    "owner": "owner",
    "tablespace_name": "tablespace_name",
    "pid": "pid",
    "spid": "spid",
}

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "WARNING": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1,
    "NONE": 0,
    "": 0,
}

CANDIDATE_PRIORITY = {
    "blocking_lock": 1,
    "sql_regression": 2,
    "sql_performance_pattern": 3,
    "io_bottleneck": 4,
    "cpu_pressure": 5,
    "memory_pressure": 6,
    "storage_or_alert_error": 7,
    "cache_efficiency": 8,
    "object_or_stats_issue": 9,
    "session_pressure": 10,
    "historical_recurrence": 11,
    "unknown_pattern": 12,
    "inconclusive": 13,
}

ALL_CANDIDATES = list(CANDIDATE_PRIORITY.keys())
CONTEXT_CHOICES = {"general", "cpu", "blocking", "sql", "memory"}


def correlate_root_cause_from_traces(db_key: str, lookback_runs: int = 30, context: str = "general") -> dict[str, Any]:
    resolved_db_key = str(db_key or "").strip() or "default"
    safe_lookback = max(int(lookback_runs or 30), 1)
    resolved_context = str(context or "general").strip().lower()
    if resolved_context not in CONTEXT_CHOICES:
        resolved_context = "general"

    traces_dir = get_traces_dir(resolved_db_key)
    indexes_dir = get_indexes_dir(resolved_db_key)
    health_jsonl_path = health_run_trace_path(resolved_db_key)

    trace_records = read_health_run_traces(limit=safe_lookback, db_key=resolved_db_key)
    runs = [record.model_dump(mode="json") for record in trace_records]
    runs = _dedupe_runs(runs)[:safe_lookback]
    runs = sorted(runs, key=lambda item: _dt(item.get("completed_at") or item.get("recorded_at")) or datetime.min.replace(tzinfo=UTC))

    recurring_index = [item.model_dump(mode="json") for item in read_recurring_issue_index(db_key=resolved_db_key)]
    history_index_entries = read_history_index_entries(limit=500, db_key=resolved_db_key)
    trace_chunks = [item.model_dump(mode="json") for item in read_trace_evidence_chunks(limit=500, db_key=resolved_db_key)]

    aux_trace_info = _read_auxiliary_traces(traces_dir)

    sources_used = {
        "db_key": resolved_db_key,
        "correlation_context": resolved_context,
        "traces_dir": str(traces_dir),
        "indexes_dir": str(indexes_dir),
        "health_run_trace_path": str(health_jsonl_path),
        "health_runs_used": len(runs),
        "recurring_issue_index_count": len(recurring_index),
        "history_index_entry_count": len(history_index_entries),
        "trace_chunk_count": len(trace_chunks),
        "investigation_trace_files": aux_trace_info.get("investigation_count", 0),
        "sql_id_trace_files": aux_trace_info.get("sql_id_count", 0),
        "awr_trace_files": aux_trace_info.get("awr_count", 0),
        "blocking_trace_files": aux_trace_info.get("blocking_count", 0),
    }

    if not runs:
        return {
            "ok": True,
            "db_key": resolved_db_key,
            "primary_cause": {
                "category": "inconclusive",
                "label": "Insufficient trace evidence",
                "confidence": "LOW",
                "score": 0.0,
                "evidence": ["No health traces were available for this db_key."],
            },
            "contributing_factors": [],
            "metric_signals": [],
            "issue_signals": [],
            "entity_signals": [],
            "contradictions": [],
            "missing_evidence": ["health_runs_missing"],
            "timeline": [],
            "recommended_next_steps": ["Run a health check to generate fresh trace evidence before correlation."],
            "score_components": {},
            "sources_used": sources_used,
            "schema_observations": {
                "metric_missing_in_latest": [],
                "new_metrics_in_latest": [],
                "discovered_metric_count": 0,
            },
        }

    flattened_by_run: list[dict[str, Any]] = []
    numeric_series: dict[str, list[float | None]] = {}
    bool_series: dict[str, list[bool | None]] = {}
    text_series: dict[str, list[str | None]] = {}
    issue_rows: list[dict[str, Any]] = []
    entity_rows: list[dict[str, Any]] = []

    for run_index, run in enumerate(runs):
        flat = flatten_trace_metrics(run)
        flattened_by_run.append(flat)

        for path, value in flat.items():
            if _is_numeric(value):
                numeric_series.setdefault(path, [None] * len(runs))
                numeric_series[path][run_index] = float(value)
            elif isinstance(value, bool):
                bool_series.setdefault(path, [None] * len(runs))
                bool_series[path][run_index] = bool(value)
            elif isinstance(value, str) and value.strip():
                text_series.setdefault(path, [None] * len(runs))
                text_series[path][run_index] = value.strip()

        issue_rows.extend(_extract_issue_rows(run=run, run_index=run_index, run_count=len(runs)))
        entity_rows.extend(_extract_entities(run=run, run_index=run_index))

    metric_trends, schema_observations = _build_metric_trends(numeric_series=numeric_series)
    issue_signals = _build_issue_signals(issue_rows=issue_rows, run_count=len(runs))
    entity_signals = _build_entity_signals(entity_rows=entity_rows, run_count=len(runs), aux_trace_info=aux_trace_info)

    latest_flat = flattened_by_run[-1] if flattened_by_run else {}
    candidate_bundle = _score_candidates(
        issue_signals=issue_signals,
        metric_trends=metric_trends,
        entity_signals=entity_signals,
        recurring_index=recurring_index,
        history_index_entries=history_index_entries,
        latest_flat=latest_flat,
        run_count=len(runs),
        context=resolved_context,
    )

    contradictions = _detect_contradictions(
        primary_category=candidate_bundle["primary_category"],
        latest_flat=latest_flat,
        issue_signals=issue_signals,
        metric_trends=metric_trends,
        entity_signals=entity_signals,
        primary_evidence=candidate_bundle["primary_evidence"],
        history_index_entries=history_index_entries,
    )

    primary_score = max(0.0, float(candidate_bundle["scores"].get(candidate_bundle["primary_category"], 0.0)) - _contradiction_penalty(contradictions))
    confidence = _confidence_from_score(primary_score, contradictions)

    primary_cause = {
        "category": candidate_bundle["primary_category"],
        "label": _label_for_category(candidate_bundle["primary_category"]),
        "confidence": confidence,
        "score": round(primary_score, 4),
        "evidence": candidate_bundle["primary_evidence"][:5],
    }

    missing_evidence = _build_missing_evidence(
        runs=runs,
        metric_trends=metric_trends,
        issue_signals=issue_signals,
        entity_signals=entity_signals,
        primary_category=candidate_bundle["primary_category"],
    )

    recommendations = _build_recommended_steps(
        primary_category=candidate_bundle["primary_category"],
        contradictions=contradictions,
        missing_evidence=missing_evidence,
    )

    timeline = [
        {
            "run_id": str(run.get("run_id") or ""),
            "completed_at": str(run.get("completed_at") or run.get("recorded_at") or ""),
            "overall_status": str(run.get("overall_status") or ""),
            "issue_count": len(run.get("issues") or []),
        }
        for run in runs[-10:]
    ]

    output = {
        "ok": True,
        "db_key": resolved_db_key,
        "primary_cause": primary_cause,
        "contributing_factors": candidate_bundle["contributing_factors"][:5],
        "metric_signals": metric_trends[:20],
        "issue_signals": issue_signals[:20],
        "entity_signals": entity_signals[:20],
        "contradictions": contradictions[:5],
        "missing_evidence": missing_evidence[:10],
        "timeline": timeline,
        "recommended_next_steps": recommendations[:5],
        "score_components": candidate_bundle["score_components"],
        "sources_used": sources_used,
        "schema_observations": schema_observations,
    }
    return json.loads(json.dumps(output, ensure_ascii=True, default=str))


def flatten_trace_metrics(trace: dict[str, Any]) -> dict[str, Any]:
    values_by_path: dict[str, list[Any]] = defaultdict(list)

    def walk(value: Any, path: str) -> None:
        if path and _should_skip_field(path, value):
            return
        if isinstance(value, dict):
            for key in sorted(value.keys()):
                child = value.get(key)
                next_path = f"{path}.{key}" if path else str(key)
                walk(child, next_path)
            return
        if isinstance(value, list):
            if not value:
                return
            if all(isinstance(item, dict) for item in value):
                for item in value:
                    walk(item, f"{path}[]" if path else "[]")
                return
            for item in value:
                walk(item, f"{path}[]" if path else "[]")
            return
        if not path:
            return
        values_by_path[path].append(value)

    walk(trace, "")
    flattened: dict[str, Any] = {}
    for path in sorted(values_by_path.keys()):
        flattened[path] = _collapse_values(values_by_path[path])
    return flattened


def render_correlation_section(correlation: dict[str, Any]) -> str:
    primary = correlation.get("primary_cause") if isinstance(correlation.get("primary_cause"), dict) else {}
    category = str(primary.get("category") or "inconclusive")
    label = str(primary.get("label") or _label_for_category(category))
    confidence = str(primary.get("confidence") or "LOW")
    score = float(primary.get("score") or 0.0)

    evidence = [str(item) for item in (primary.get("evidence") or []) if str(item).strip()][:5]
    contributing = [str(item) for item in (correlation.get("contributing_factors") or []) if str(item).strip()][:5]
    contradictions = [str(item) for item in (correlation.get("contradictions") or []) if str(item).strip()][:5]
    missing = [str(item) for item in (correlation.get("missing_evidence") or []) if str(item).strip()][:5]
    next_steps = [str(item) for item in (correlation.get("recommended_next_steps") or []) if str(item).strip()][:5]

    sources = correlation.get("sources_used") if isinstance(correlation.get("sources_used"), dict) else {}
    source_parts = [
        f"health_runs={sources.get('health_runs_used', 0)}",
        f"history_index={sources.get('history_index_entry_count', 0)}",
        f"recurring_index={sources.get('recurring_issue_index_count', 0)}",
    ]

    lines = [
        "## 🔴 Root Cause Correlation",
        "",
        f"- Primary cause: {label} (`{category}`)",
        f"- Confidence/score: {confidence} ({score:.2f})",
        f"- Corroborating sources: {', '.join(source_parts)}",
        "- Key evidence:",
    ]
    if evidence:
        lines.extend([f"  - {item}" for item in evidence])
    else:
        lines.append("  - No strong evidence lines were available.")

    lines.append("- Contributing factors:")
    if contributing:
        lines.extend([f"  - {item}" for item in contributing])
    else:
        lines.append("  - None")

    lines.append("- Contradictions:")
    if contradictions:
        lines.extend([f"  - {item}" for item in contradictions])
    else:
        lines.append("  - None")

    lines.append("- Missing evidence:")
    if missing:
        lines.extend([f"  - {item}" for item in missing])
    else:
        lines.append("  - None")

    lines.append("- Next validation steps:")
    if next_steps:
        lines.extend([f"  - {item}" for item in next_steps])
    else:
        lines.append("  - Run another scoped health check for refreshed trace evidence.")
    return "\n".join(lines)


def _collapse_values(values: list[Any]) -> Any:
    clean = [item for item in values if item is not None]
    if not clean:
        return None
    numeric = [float(item) for item in clean if _is_numeric(item)]
    if numeric:
        return max(numeric)
    bools = [item for item in clean if isinstance(item, bool)]
    if bools:
        return any(bools)
    texts = [str(item).strip() for item in clean if isinstance(item, str) and str(item).strip()]
    if texts:
        return texts[0]
    return clean[0]


def _should_skip_field(path: str, value: Any) -> bool:
    key = path.split(".")[-1].lower()
    if key in HUGE_TEXT_KEYS:
        return True
    if isinstance(value, str) and len(value) > 4000 and any(token in key for token in ("report", "markdown", "output", "log_text")):
        return True
    return False


def _is_numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and not math.isnan(float(value))


def _build_metric_trends(*, numeric_series: dict[str, list[float | None]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    trend_rows: list[dict[str, Any]] = []
    missing_in_latest: list[str] = []
    new_in_latest: list[str] = []

    for path in sorted(numeric_series.keys()):
        series = numeric_series[path]
        samples = [item for item in series if item is not None]
        if not samples:
            continue
        latest = series[-1]
        previous = _previous_present(series)
        avg_value = sum(samples) / len(samples)
        delta_prev = (latest - previous) if latest is not None and previous is not None else None
        delta_avg = (latest - avg_value) if latest is not None else None
        pct_change = None
        if delta_prev is not None and previous not in (None, 0):
            pct_change = (delta_prev / abs(previous)) * 100.0

        if latest is None and any(item is not None for item in series[:-1]):
            direction = "no_longer_present"
            missing_in_latest.append(path)
        elif latest is not None and all(item is None for item in series[:-1]):
            direction = "newly_present"
            new_in_latest.append(path)
        elif latest is None:
            direction = "unchanged"
        elif previous is None:
            direction = "newly_present"
            new_in_latest.append(path)
        elif abs(latest - previous) <= max(abs(previous) * 0.01, 0.01):
            direction = "unchanged"
        elif latest > previous:
            direction = "increased"
        else:
            direction = "decreased"

        family = _metric_family(path)
        strength = _trend_strength(delta_prev=delta_prev, pct_change=pct_change, latest=latest, avg_value=avg_value)
        threshold_crossed = _threshold_crossed(path=path, latest=latest)

        trend_rows.append(
            {
                "path": path,
                "family": family,
                "sample_count": len(samples),
                "missing_count": len(series) - len(samples),
                "latest": latest,
                "previous": previous,
                "min": min(samples),
                "max": max(samples),
                "avg": round(avg_value, 4),
                "delta_latest_previous": _round_or_none(delta_prev),
                "delta_latest_avg": _round_or_none(delta_avg),
                "pct_change": _round_or_none(pct_change),
                "direction": direction,
                "threshold_crossed": threshold_crossed,
                "trend_strength": round(strength, 4),
            }
        )

    trend_rows.sort(
        key=lambda row: (
            1 if row.get("threshold_crossed") else 0,
            float(row.get("trend_strength") or 0.0),
            str(row.get("path") or ""),
        ),
        reverse=True,
    )

    observations = {
        "metric_missing_in_latest": missing_in_latest[:50],
        "new_metrics_in_latest": new_in_latest[:50],
        "discovered_metric_count": len(trend_rows),
        "unclassified_metric_count": sum(1 for row in trend_rows if row.get("family") == "unclassified_metric"),
        "metric_missing_in_latest_records": [
            {"type": "metric_missing_in_latest", "path": item} for item in missing_in_latest[:20]
        ],
    }
    return trend_rows, observations


def _extract_issue_rows(*, run: dict[str, Any], run_index: int, run_count: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    issues = run.get("issues") if isinstance(run.get("issues"), list) else []
    completed_at = str(run.get("completed_at") or run.get("recorded_at") or "")
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        category = str(issue.get("category") or "unknown").strip() or "unknown"
        title = str(issue.get("title") or "untitled issue").strip() or "untitled issue"
        severity = str(issue.get("severity") or "INFO").upper()
        rows.append(
            {
                "key": f"{category.lower()}|{title.lower()}",
                "category": category,
                "title": title,
                "severity": severity,
                "description": str(issue.get("description") or "").strip(),
                "evidence": issue.get("evidence") if isinstance(issue.get("evidence"), list) else [],
                "recommendation": str(issue.get("recommendation") or "").strip(),
                "run_index": run_index,
                "run_count": run_count,
                "completed_at": completed_at,
            }
        )
    return rows


def _build_issue_signals(*, issue_rows: list[dict[str, Any]], run_count: int) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in issue_rows:
        grouped[str(row.get("key") or "")].append(row)

    signals: list[dict[str, Any]] = []
    for key in sorted(grouped.keys()):
        rows = sorted(grouped[key], key=lambda item: int(item.get("run_index") or 0))
        if not rows:
            continue
        latest = rows[-1]
        first = rows[0]
        severities = [str(item.get("severity") or "INFO").upper() for item in rows]
        severity_trend = _severity_trend(severities)
        recurrence = len(rows)
        persistence_ratio = recurrence / max(run_count, 1)
        latest_present = int(latest.get("run_index") or 0) == (run_count - 1)
        signals.append(
            {
                "key": key,
                "category": latest.get("category"),
                "title": latest.get("title"),
                "severity": latest.get("severity"),
                "description": latest.get("description"),
                "evidence": (latest.get("evidence") or [])[:5],
                "recommendation": latest.get("recommendation"),
                "recurrence_count": recurrence,
                "persistence_ratio": round(persistence_ratio, 4),
                "latest_present": latest_present,
                "severity_trend": severity_trend,
                "first_seen": first.get("completed_at"),
                "last_seen": latest.get("completed_at"),
            }
        )

    signals.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity") or "").upper(), 0),
            float(item.get("persistence_ratio") or 0.0),
            int(item.get("recurrence_count") or 0),
            str(item.get("key") or ""),
        ),
        reverse=True,
    )
    return signals


def _extract_entities(*, run: dict[str, Any], run_index: int) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            lowered = {str(key).lower(): key for key in value.keys()}
            for probe, entity_type in ENTITY_KEYS.items():
                if probe in lowered:
                    original = lowered[probe]
                    raw_value = value.get(original)
                    normalized = _normalize_entity_value(raw_value)
                    if normalized:
                        found.append(
                            {
                                "entity_type": entity_type,
                                "entity_value": normalized,
                                "path": f"{path}.{original}" if path else str(original),
                                "run_index": run_index,
                                "source": "trace",
                            }
                        )
            for key in sorted(value.keys()):
                next_path = f"{path}.{key}" if path else str(key)
                walk(value.get(key), next_path)
            return
        if isinstance(value, list):
            for item in value:
                walk(item, f"{path}[]" if path else "[]")

    walk(run, "")
    return found


def _build_entity_signals(*, entity_rows: list[dict[str, Any]], run_count: int, aux_trace_info: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in entity_rows:
        grouped[(str(row.get("entity_type") or ""), str(row.get("entity_value") or ""))].append(row)

    aux_entities = aux_trace_info.get("entities") if isinstance(aux_trace_info.get("entities"), list) else []
    for row in aux_entities:
        grouped[(str(row.get("entity_type") or ""), str(row.get("entity_value") or ""))].append(row)

    signals: list[dict[str, Any]] = []
    for key in sorted(grouped.keys()):
        rows = grouped[key]
        run_indexes = sorted({int(row.get("run_index") or 0) for row in rows if row.get("run_index") is not None})
        sources = sorted({str(row.get("source") or "trace") for row in rows})
        recurrence_count = len(run_indexes)
        persistence_ratio = recurrence_count / max(run_count, 1)
        signals.append(
            {
                "entity_type": key[0],
                "entity_value": key[1],
                "recurrence_count": recurrence_count,
                "persistence_ratio": round(persistence_ratio, 4),
                "latest_present": (run_count - 1) in run_indexes,
                "sources": sources,
                "source_count": len(sources),
            }
        )

    signals.sort(
        key=lambda item: (
            int(item.get("source_count") or 0),
            float(item.get("persistence_ratio") or 0.0),
            int(item.get("recurrence_count") or 0),
            str(item.get("entity_type") or ""),
            str(item.get("entity_value") or ""),
        ),
        reverse=True,
    )
    return signals


def _score_candidates(
    *,
    issue_signals: list[dict[str, Any]],
    metric_trends: list[dict[str, Any]],
    entity_signals: list[dict[str, Any]],
    recurring_index: list[dict[str, Any]],
    history_index_entries: list[dict[str, Any]],
    latest_flat: dict[str, Any],
    run_count: int,
    context: str,
) -> dict[str, Any]:
    scores = {name: 0.0 for name in ALL_CANDIDATES}
    score_components: dict[str, dict[str, float]] = {
        name: {
            "current_issue_severity": 0.0,
            "numeric_trend_threshold": 0.0,
            "cross_source_corroboration": 0.0,
            "recurrence_history": 0.0,
            "data_completeness": 0.0,
            "weighted_score": 0.0,
        }
        for name in ALL_CANDIDATES
    }
    evidence: dict[str, list[str]] = {name: [] for name in ALL_CANDIDATES}

    data_completeness = _data_completeness(latest_flat=latest_flat, run_count=run_count, issue_signals=issue_signals, metric_trends=metric_trends)

    issue_component_by_category = {name: 0.0 for name in ALL_CANDIDATES}
    recurrence_component_by_category = {name: 0.0 for name in ALL_CANDIDATES}

    for issue in issue_signals:
        category = _issue_to_candidate(issue)
        sev = SEVERITY_ORDER.get(str(issue.get("severity") or "").upper(), 0)
        issue_score = min(sev / 5.0, 1.0)
        if not bool(issue.get("latest_present")):
            issue_score *= 0.6
        issue_component_by_category[category] = max(issue_component_by_category[category], issue_score)

        recurrence_score = min(float(issue.get("persistence_ratio") or 0.0), 1.0)
        recurrence_component_by_category[category] = max(recurrence_component_by_category[category], recurrence_score)
        evidence[category].append(
            f"Issue '{issue.get('title')}' ({issue.get('severity')}) recurrence={issue.get('recurrence_count')} persistence={issue.get('persistence_ratio')}"
        )

    trend_component_by_category = {name: 0.0 for name in ALL_CANDIDATES}
    for metric in metric_trends[:40]:
        category = _metric_family_to_candidate(str(metric.get("family") or ""), str(metric.get("path") or ""))
        strength = min(float(metric.get("trend_strength") or 0.0), 1.0)
        if metric.get("threshold_crossed"):
            strength = min(1.0, strength + 0.2)
        trend_component_by_category[category] = max(trend_component_by_category[category], strength)

        if strength >= 0.35:
            evidence[category].append(
                f"Metric {metric.get('path')} {metric.get('direction')} (latest={metric.get('latest')}, previous={metric.get('previous')}, pct_change={metric.get('pct_change')})"
            )

        if category == "unknown_pattern" and metric.get("family") == "unclassified_metric":
            evidence[category].append(
                f"Unknown metric trend detected: {metric.get('path')} ({metric.get('direction')}, strength={metric.get('trend_strength')})"
            )

    entity_component_by_category = {name: 0.0 for name in ALL_CANDIDATES}
    for entity in entity_signals:
        entity_type = str(entity.get("entity_type") or "")
        source_count = int(entity.get("source_count") or 1)
        persistence = float(entity.get("persistence_ratio") or 0.0)
        score = min(1.0, 0.2 * source_count + 0.8 * persistence)
        mapped = _entity_type_to_candidates(entity_type)
        for category in mapped:
            entity_component_by_category[category] = max(entity_component_by_category[category], score)
            if source_count >= 2 or persistence >= 0.5:
                evidence[category].append(
                    f"Entity {entity_type}={entity.get('entity_value')} recurs across sources={entity.get('sources')}"
                )

    recurrence_from_index = _recurrence_from_indexes(recurring_index=recurring_index, history_index_entries=history_index_entries)
    recurrence_component_by_category["historical_recurrence"] = max(
        recurrence_component_by_category["historical_recurrence"], recurrence_from_index
    )
    if recurrence_from_index > 0:
        evidence["historical_recurrence"].append(f"Recurring issue index evidence strength={recurrence_from_index:.2f}")

    host_scope = str(latest_flat.get("metrics.host_check_scope") or latest_flat.get("snapshot.raw_evidence.host_check.host_check_scope") or "")
    cross_source_by_category = {name: 0.0 for name in ALL_CANDIDATES}

    for category in ALL_CANDIDATES:
        source_signals = 0
        if issue_component_by_category[category] > 0:
            source_signals += 1
        if trend_component_by_category[category] > 0:
            source_signals += 1
        if entity_component_by_category[category] > 0:
            source_signals += 1
        if recurrence_component_by_category[category] > 0:
            source_signals += 1
        cross_source_by_category[category] = min(source_signals / 3.0, 1.0)

        components = score_components[category]
        components["current_issue_severity"] = round(issue_component_by_category[category], 4)
        components["numeric_trend_threshold"] = round(trend_component_by_category[category], 4)
        components["cross_source_corroboration"] = round(cross_source_by_category[category], 4)
        components["recurrence_history"] = round(max(recurrence_component_by_category[category], entity_component_by_category[category]), 4)
        components["data_completeness"] = round(data_completeness, 4)

        weighted = (
            components["current_issue_severity"] * 0.25
            + components["numeric_trend_threshold"] * 0.20
            + components["cross_source_corroboration"] * 0.25
            + components["recurrence_history"] * 0.20
            + components["data_completeness"] * 0.10
        )

        if category == "cpu_pressure" and host_scope == "local_app_host":
            weighted *= 0.75
        if category == "historical_recurrence" and (issue_component_by_category["sql_regression"] > 0.3 or issue_component_by_category["blocking_lock"] > 0.3):
            weighted *= 0.6
        weighted *= _context_factor(category=category, context=context)

        components["weighted_score"] = round(weighted, 4)
        scores[category] = weighted

    strongest_current = max(
        [c for c in ALL_CANDIDATES if c not in {"historical_recurrence", "unknown_pattern", "inconclusive"}],
        key=lambda category: (scores.get(category, 0.0), -CANDIDATE_PRIORITY.get(category, 999)),
        default="inconclusive",
    )

    ranked = sorted(
        ALL_CANDIDATES,
        key=lambda category: (scores.get(category, 0.0), -CANDIDATE_PRIORITY.get(category, 999)),
        reverse=True,
    )

    primary = ranked[0] if ranked else "inconclusive"
    if primary == "historical_recurrence" and scores.get(strongest_current, 0.0) >= (scores.get(primary, 0.0) - 0.05):
        primary = strongest_current
    if scores.get(primary, 0.0) < 0.20:
        primary = "inconclusive"

    primary_evidence = _dedupe_lines(evidence.get(primary, []))[:8]
    if not primary_evidence:
        primary_evidence = ["No high-strength corroborated signal was available."]

    contributing: list[str] = []
    for category in ranked:
        if category == primary:
            continue
        score = scores.get(category, 0.0)
        if score < 0.25:
            continue
        if category == "historical_recurrence" and primary != "historical_recurrence":
            contributing.append(f"Historical recurrence supports the pattern (score={score:.2f}).")
        else:
            contributing.append(f"{_label_for_category(category)} (score={score:.2f})")

    for metric in metric_trends[:30]:
        if metric.get("family") == "unclassified_metric" and float(metric.get("trend_strength") or 0.0) >= 0.5:
            contributing.append(
                f"Unclassified metric changed strongly: {metric.get('path')} ({metric.get('direction')}, strength={metric.get('trend_strength')})."
            )

    return {
        "primary_category": primary,
        "scores": {key: round(value, 4) for key, value in scores.items()},
        "score_components": score_components,
        "primary_evidence": _dedupe_lines(primary_evidence),
        "contributing_factors": _dedupe_lines(contributing),
    }


def _context_factor(*, category: str, context: str) -> float:
    if context == "general":
        return 1.0
    relevant: dict[str, set[str]] = {
        "cpu": {"cpu_pressure", "sql_performance_pattern", "sql_regression"},
        "blocking": {"blocking_lock", "session_pressure", "io_bottleneck"},
        "sql": {"sql_regression", "sql_performance_pattern", "object_or_stats_issue"},
        "memory": {"memory_pressure", "sql_performance_pattern"},
    }
    chosen = relevant.get(context, set())
    if category in chosen:
        return 1.2
    if category in {"historical_recurrence", "unknown_pattern", "inconclusive"}:
        return 0.95
    return 0.65


def _detect_contradictions(
    *,
    primary_category: str,
    latest_flat: dict[str, Any],
    issue_signals: list[dict[str, Any]],
    metric_trends: list[dict[str, Any]],
    entity_signals: list[dict[str, Any]],
    primary_evidence: list[str],
    history_index_entries: list[dict[str, Any]],
) -> list[str]:
    out: list[str] = []

    host_cpu = _find_numeric(latest_flat, include=("host_cpu", "cpu_pct"), exclude=("sql", "elapsed"))
    container_cpu = _find_numeric(latest_flat, include=("container_cpu",), exclude=())
    memory_pct = _find_numeric(latest_flat, include=("memory_pct",), exclude=("pga", "sga"))
    top_sql_cpu = _find_numeric(latest_flat, include=("top_cpu_sql", "cpu_s"), exclude=())
    top_sql_elapsed = _find_numeric(latest_flat, include=("top_elapsed_sql", "elapsed_s"), exclude=())

    latest_issue_categories = {str(item.get("category") or "").lower() for item in issue_signals if item.get("latest_present")}
    host_scope = str(latest_flat.get("metrics.host_check_scope") or latest_flat.get("snapshot.raw_evidence.host_check.host_check_scope") or "")

    if primary_category == "cpu_pressure":
        cpu_low = (host_cpu is not None and host_cpu < 65.0) and (container_cpu is None or container_cpu < 65.0)
        no_cpu_issue = not any("cpu" in category for category in latest_issue_categories)
        if cpu_low and no_cpu_issue:
            out.append("CPU pressure selected but host/container CPU is low without DB CPU corroboration.")
        if host_scope == "local_app_host":
            out.append("Host check scope is local_app_host, so CPU evidence may not represent the DB host.")

    if primary_category == "memory_pressure":
        low_memory = memory_pct is not None and memory_pct < 70.0
        has_pga_temp = any(
            _find_token(str(metric.get("path") or ""), ("pga", "temp", "undo")) and float(metric.get("latest") or 0.0) > 0
            for metric in metric_trends
        )
        if low_memory and not has_pga_temp:
            out.append("Memory pressure selected but memory usage is low and no PGA/TEMP consumer evidence is present.")

    if any(item.get("entity_type") == "sql_id" for item in entity_signals):
        if (top_sql_cpu is not None and top_sql_cpu < 5.0) and (top_sql_elapsed is not None and top_sql_elapsed < 5.0):
            out.append("SQL_ID entity recurrence exists but elapsed/cpu metrics are negligible.")

    recurrence_high = any(float(item.get("persistence_ratio") or 0.0) >= 0.7 for item in issue_signals)
    latest_issue_present = bool([item for item in issue_signals if item.get("latest_present")])
    if recurrence_high and not latest_issue_present:
        out.append("Historical recurrence is high but latest run does not contain the recurring issue.")

    awr_weak = any("comparability" in json.dumps(entry).lower() and "low" in json.dumps(entry).lower() for entry in history_index_entries)
    if awr_weak and primary_category not in {"inconclusive", "unknown_pattern"}:
        out.append("AWR/history comparability looks weak relative to a specific primary-cause claim.")

    if primary_category not in {"inconclusive", "unknown_pattern"} and not primary_evidence:
        out.append("Selected category has no direct latest issue/entity/metric evidence.")

    worsening_categories = {"cpu_pressure", "memory_pressure", "io_bottleneck", "blocking_lock", "sql_regression"}
    if primary_category in worsening_categories:
        related = [row for row in metric_trends if _metric_family_to_candidate(str(row.get("family") or ""), str(row.get("path") or "")) == primary_category]
        if related and all(str(row.get("direction") or "") == "decreased" for row in related[:3]):
            out.append("Primary cause suggests worsening, but key related metrics improved in latest run.")

    return _dedupe_lines(out)


def _contradiction_penalty(contradictions: list[str]) -> float:
    if not contradictions:
        return 0.0
    major = sum(1 for item in contradictions if any(token in item.lower() for token in ("selected but", "scope", "weak")))
    minor = max(len(contradictions) - major, 0)
    return min(0.45, major * 0.12 + minor * 0.05)


def _build_missing_evidence(
    *,
    runs: list[dict[str, Any]],
    metric_trends: list[dict[str, Any]],
    issue_signals: list[dict[str, Any]],
    entity_signals: list[dict[str, Any]],
    primary_category: str,
) -> list[str]:
    missing: list[str] = []
    if not runs:
        missing.append("health_runs_missing")
    if not metric_trends:
        missing.append("numeric_metrics_missing")
    if not issue_signals:
        missing.append("issues_missing")
    if not entity_signals:
        missing.append("entity_signals_missing")

    category_needs = {
        "cpu_pressure": "db_host_cpu_scope_or_db_cpu_correlation",
        "memory_pressure": "pga_temp_or_memory_consumer_evidence",
        "blocking_lock": "current_blocking_chain_or_lock_wait_evidence",
        "sql_regression": "sql_change_or_plan_regression_evidence",
        "io_bottleneck": "io_wait_or_disk_latency_evidence",
    }
    if primary_category in category_needs:
        missing.append(f"missing_{category_needs[primary_category]}")

    return _dedupe_lines(missing)


def _build_recommended_steps(*, primary_category: str, contradictions: list[str], missing_evidence: list[str]) -> list[str]:
    steps = [
        "Re-run health check for the same db_key to refresh current evidence.",
        "Validate the top correlated entity (SQL_ID/session/event) in current activity traces.",
    ]
    by_category = {
        "blocking_lock": "Capture blocking chain snapshots over multiple intervals and verify blocker SQL/text.",
        "sql_regression": "Compare execution plans and elapsed/cpu deltas for repeated SQL_IDs.",
        "sql_performance_pattern": "Inspect recurring top SQL and wait profile alignment across recent runs.",
        "cpu_pressure": "Confirm CPU pressure from DB host scope and correlate with Oracle workload metrics.",
        "memory_pressure": "Validate PGA/TEMP growth and high-memory sessions in latest evidence.",
        "io_bottleneck": "Check recurring I/O wait events and storage latency signals in recent windows.",
        "storage_or_alert_error": "Review alert/error evidence and related storage utilization constraints.",
        "historical_recurrence": "Use current run evidence to confirm recurrence is still active before remediation.",
        "unknown_pattern": "Review unclassified metrics with strongest trend for schema/tagging updates.",
        "inconclusive": "Collect additional scoped traces before selecting a definitive root cause.",
    }
    if primary_category in by_category:
        steps.append(by_category[primary_category])

    if contradictions:
        steps.append("Resolve contradiction checks before escalating confidence in the selected category.")
    if missing_evidence:
        steps.append("Capture missing evidence fields in next runs to improve correlation confidence.")
    return _dedupe_lines(steps)


def _confidence_from_score(score: float, contradictions: list[str]) -> str:
    if score >= 0.75 and not contradictions:
        return "HIGH"
    if score >= 0.45:
        return "MEDIUM"
    return "LOW"


def _previous_present(series: list[float | None]) -> float | None:
    if len(series) < 2:
        return None
    for item in reversed(series[:-1]):
        if item is not None:
            return item
    return None


def _trend_strength(*, delta_prev: float | None, pct_change: float | None, latest: float | None, avg_value: float) -> float:
    if latest is None:
        return 0.0
    delta_term = abs(delta_prev or 0.0) / (abs(avg_value) + 1.0)
    pct_term = abs((pct_change or 0.0) / 100.0)
    return min(1.0, delta_term + pct_term)


def _threshold_crossed(*, path: str, latest: float | None) -> bool:
    if latest is None:
        return False
    lowered = path.lower()
    if any(token in lowered for token in ("pct", "percent", "usage")):
        return latest >= 85.0
    if any(token in lowered for token in ("count", "error", "blocking", "invalid")):
        return latest > 0.0
    if any(token in lowered for token in ("latency", "elapsed")):
        return latest >= 1.0
    return False


def _severity_trend(severities: list[str]) -> str:
    if len(severities) < 2:
        return "stable"
    first = SEVERITY_ORDER.get(str(severities[0]).upper(), 0)
    last = SEVERITY_ORDER.get(str(severities[-1]).upper(), 0)
    if last > first:
        return "worsening"
    if last < first:
        return "improving"
    return "stable"


def _metric_family(path: str) -> str:
    lowered = path.lower()
    for hint in KNOWN_METRIC_HINTS:
        if hint in lowered:
            return hint
    return "unclassified_metric"


def _metric_family_to_candidate(family: str, path: str) -> str:
    token = (family or "").lower()
    text = f"{token} {path.lower()}"
    if any(item in text for item in ("blocking", "lock", "enq")):
        return "blocking_lock"
    if any(item in text for item in ("sql", "plan", "parse", "elapsed", "execution")):
        if "regression" in text or "plan" in text:
            return "sql_regression"
        return "sql_performance_pattern"
    if "cpu" in text:
        return "cpu_pressure"
    if any(item in text for item in ("memory", "pga", "sga", "temp", "undo")):
        return "memory_pressure"
    if any(item in text for item in ("io", "disk", "latency", "wait")):
        return "io_bottleneck"
    if any(item in text for item in ("alert", "error", "tablespace", "fra", "redo", "filesystem")):
        return "storage_or_alert_error"
    if "cache" in text:
        return "cache_efficiency"
    if "invalid" in text:
        return "object_or_stats_issue"
    if any(item in text for item in ("session", "process")):
        return "session_pressure"
    return "unknown_pattern"


def _issue_to_candidate(issue: dict[str, Any]) -> str:
    text = " ".join(
        [
            str(issue.get("category") or ""),
            str(issue.get("title") or ""),
            str(issue.get("description") or ""),
        ]
    ).lower()
    if any(token in text for token in ("blocking", "lock", "enq")):
        return "blocking_lock"
    if any(token in text for token in ("regression", "plan hash", "plan changed")):
        return "sql_regression"
    if "sql" in text:
        return "sql_performance_pattern"
    if "cpu" in text:
        return "cpu_pressure"
    if any(token in text for token in ("memory", "pga", "sga", "temp", "undo")):
        return "memory_pressure"
    if any(token in text for token in ("io", "latency", "disk", "wait")):
        return "io_bottleneck"
    if any(token in text for token in ("ora-", "alert", "error", "tablespace", "fra", "filesystem", "storage")):
        return "storage_or_alert_error"
    if any(token in text for token in ("cache", "buffer")):
        return "cache_efficiency"
    if any(token in text for token in ("invalid", "stale stats", "object")):
        return "object_or_stats_issue"
    if any(token in text for token in ("session", "process")):
        return "session_pressure"
    return "unknown_pattern"


def _entity_type_to_candidates(entity_type: str) -> list[str]:
    lowered = (entity_type or "").lower()
    if lowered in {"blocking_session", "sid", "serial"}:
        return ["blocking_lock", "session_pressure"]
    if lowered == "sql_id":
        return ["sql_regression", "sql_performance_pattern"]
    if lowered in {"event", "wait_class"}:
        return ["io_bottleneck", "blocking_lock", "session_pressure"]
    if lowered in {"object_name", "owner"}:
        return ["object_or_stats_issue", "sql_performance_pattern"]
    if lowered == "tablespace_name":
        return ["storage_or_alert_error"]
    if lowered in {"pid", "spid"}:
        return ["session_pressure", "cpu_pressure"]
    return ["unknown_pattern"]


def _recurrence_from_indexes(*, recurring_index: list[dict[str, Any]], history_index_entries: list[dict[str, Any]]) -> float:
    if not recurring_index and not history_index_entries:
        return 0.0
    recurring_strength = 0.0
    if recurring_index:
        top = sorted(recurring_index, key=lambda row: int(row.get("run_count") or 0), reverse=True)[0]
        recurring_strength = min(float(int(top.get("run_count") or 0)) / 10.0, 1.0)
    history_strength = 0.0
    if history_index_entries:
        history_strength = min(float(len(history_index_entries)) / 200.0, 1.0)
    return min(1.0, max(recurring_strength, history_strength))


def _data_completeness(
    *,
    latest_flat: dict[str, Any],
    run_count: int,
    issue_signals: list[dict[str, Any]],
    metric_trends: list[dict[str, Any]],
) -> float:
    fields = 0
    checks = 0
    checks += 1
    fields += 1 if run_count > 0 else 0
    checks += 1
    fields += 1 if latest_flat else 0
    checks += 1
    fields += 1 if metric_trends else 0
    checks += 1
    fields += 1 if issue_signals else 0
    return fields / max(checks, 1)


def _find_numeric(flat: dict[str, Any], include: tuple[str, ...], exclude: tuple[str, ...]) -> float | None:
    for path in sorted(flat.keys()):
        lowered = path.lower()
        if include and not all(token in lowered for token in include):
            continue
        if exclude and any(token in lowered for token in exclude):
            continue
        value = flat[path]
        if _is_numeric(value):
            return float(value)
    return None


def _find_token(text: str, tokens: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in tokens)


def _normalize_entity_value(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    return text.lower()


def _round_or_none(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 4)


def _label_for_category(category: str) -> str:
    labels = {
        "blocking_lock": "Blocking / lock contention",
        "sql_performance_pattern": "SQL performance pattern",
        "sql_regression": "SQL regression",
        "cpu_pressure": "CPU pressure",
        "memory_pressure": "Memory pressure",
        "io_bottleneck": "I/O bottleneck",
        "storage_or_alert_error": "Storage/alert error",
        "cache_efficiency": "Cache efficiency",
        "object_or_stats_issue": "Object/statistics issue",
        "session_pressure": "Session pressure",
        "historical_recurrence": "Historical recurrence",
        "unknown_pattern": "Unknown pattern",
        "inconclusive": "Inconclusive",
    }
    return labels.get(category, "Inconclusive")


def _dt(raw: Any) -> datetime | None:
    if isinstance(raw, datetime):
        return raw.astimezone(UTC)
    text = str(raw or "").strip()
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


def _dedupe_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        text = str(line or "").strip()
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _dedupe_runs(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in runs:
        key = "|".join(
            [
                str(row.get("run_id") or ""),
                str(row.get("completed_at") or ""),
                str(row.get("trace_path") or ""),
            ]
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _read_auxiliary_traces(traces_dir: Path) -> dict[str, Any]:
    info = {
        "investigation_count": 0,
        "sql_id_count": 0,
        "awr_count": 0,
        "blocking_count": 0,
        "entities": [],
    }
    if not traces_dir.exists():
        return info

    candidates = sorted(traces_dir.glob("*.jsonl"))
    for path in candidates:
        name = path.name.lower()
        trace_kind = ""
        if "investigation" in name:
            info["investigation_count"] += 1
            trace_kind = "investigation"
        elif "sql_id" in name:
            info["sql_id_count"] += 1
            trace_kind = "sql_id"
        elif "awr" in name:
            info["awr_count"] += 1
            trace_kind = "awr"
        elif "blocking" in name:
            info["blocking_count"] += 1
            trace_kind = "blocking"
        else:
            continue

        parsed_rows = _read_jsonl_lines(path, max_rows=200)
        for row in parsed_rows:
            extracted = _extract_entities(run=row, run_index=-1)
            for entity in extracted:
                entity["source"] = trace_kind
            info["entities"].extend(extracted)

    return info


def _read_jsonl_lines(path: Path, *, max_rows: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                text = line.strip()
                if not text:
                    continue
                try:
                    payload = json.loads(text)
                except Exception:
                    continue
                if isinstance(payload, dict):
                    rows.append(payload)
                if len(rows) >= max_rows:
                    break
    except Exception:
        return []
    return rows


__all__ = [
    "correlate_root_cause_from_traces",
    "flatten_trace_metrics",
    "render_correlation_section",
]
