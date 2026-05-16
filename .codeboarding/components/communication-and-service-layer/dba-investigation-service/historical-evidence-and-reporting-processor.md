---
component_id: 2.2.3
component_name: Historical Evidence & Reporting Processor
---

# Historical Evidence & Reporting Processor

## Component Description

Manages the lifecycle of historical performance data, from filtering raw metric traces across specific time windows to rendering human-readable summaries with semantic labeling.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/services/autodba_service.py (lines 431-475)
```
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
```

### /home/neha/projects/agents/odb_autodba/services/autodba_service.py (lines 502-628)
```
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
```


## Source Files:

- `services/autodba_service.py`

