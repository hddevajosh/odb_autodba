---
component_id: 5.3.2
component_name: Temporal Query Resolver
---

# Temporal Query Resolver

## Component Description

Acts as the entry point for the AI Agent, translating natural language time windows and historical questions into specific data lookups and summarized context.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 665-701)
```
    def answer_history_question_from_index(
        self,
        *,
        user_query: str,
        database_name: str | None = None,
        requested_domain: str | None = None,
        db_key: str | None = None,
    ) -> dict[str, Any] | None:
        route = self.route_history_metric_question(user_query=user_query, requested_domain=requested_domain)
        if route is None:
            return None
        history = self.get_metric_history_from_index(route=route, database_name=database_name, db_key=db_key)
        if history is None:
            return None
        rendered, summary = _render_index_history_metric_report(question=user_query, route=route, history=history)
        supporting = {
            "question_type": "history_metric",
            "metric_family": route.get("metric_family"),
            "aggregation": route.get("aggregation"),
            "time_window": route.get("time_window") or {"label": "all"},
            "matched_runs": history.get("matched_runs"),
            "sample_count": history.get("sample_count"),
            "field_summaries": history.get("field_summaries"),
            "source": "index",
            "planner_memory_used": history.get("planner_memory_used"),
            "history_index_used": history.get("history_index_used"),
        }
        return {
            "ok": True,
            "route": route,
            "history": history,
            "rendered_report": rendered,
            "summary": summary,
            "supporting_data": supporting,
            "source": "index",
            "confident": bool(history.get("field_summaries")),
        }
```

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 264-312)
```
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
```


## Source Files:

- `history/jsonl_service.py`

