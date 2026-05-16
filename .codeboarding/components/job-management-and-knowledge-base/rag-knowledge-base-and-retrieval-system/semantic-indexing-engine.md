---
component_id: 5.4.2
component_name: Semantic Indexing Engine
---

# Semantic Indexing Engine

## Component Description

Orchestrates the transformation of raw trace files into optimized semantic indices. It implements the logic for chunking historical data and identifying recurring issue patterns to build the "memory" used by the AI agents.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/rag/indexer.py (lines 29-35)
```
def rebuild_history_index() -> dict[str, Any]:
    artifacts = rebuild_planner_memory_artifacts()
    return {
        "record_count": len(artifacts.get("history_indexing") or []),
        "trace_chunk_count": len(artifacts.get("trace_chunks") or []),
        "recurring_issue_count": len(artifacts.get("recurring_issue_index") or []),
    }
```

### /home/neha/projects/agents/odb_autodba/rag/indexer.py (lines 94-151)
```
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
```


## Source Files:

- `rag/indexer.py`

