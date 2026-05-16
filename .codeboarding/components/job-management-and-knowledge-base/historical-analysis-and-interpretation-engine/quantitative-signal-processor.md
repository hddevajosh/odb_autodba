---
component_id: 5.3.3
component_name: Quantitative Signal Processor
---

# Quantitative Signal Processor

## Component Description

Performs statistical analysis on telemetry to calculate metric deltas and identify significant trends (e.g., regressions or improvements) across time intervals.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 410-441)
```
    def get_metric_trends_from_jsonl(
        self,
        *,
        database_name: str | None = None,
        traces: list[TraceHealthRunRecord] | None = None,
        limit: int = 20,
        db_key: str | None = None,
    ) -> list[MetricTrendSummary]:
        source = traces if traces is not None else read_health_run_traces(database_name=database_name, limit=limit, db_key=db_key)
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
```

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 2189-2228)
```
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
```


## Source Files:

- `history/jsonl_service.py`

