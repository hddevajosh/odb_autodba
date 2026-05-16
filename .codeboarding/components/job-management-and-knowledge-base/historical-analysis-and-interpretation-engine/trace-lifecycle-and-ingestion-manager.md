---
component_id: 5.3.1
component_name: Trace Lifecycle & Ingestion Manager
---

# Trace Lifecycle & Ingestion Manager

## Component Description

Manages the physical data layer, including loading, deduplicating, and indexing JSONL telemetry files to ensure a clean, chronologically sorted foundation for analysis.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 703-720)
```
    def _load_traces(
        self,
        *,
        limit: int,
        database_name: str | None,
        time_scope: dict[str, Any] | None,
        db_key: str | None = None,
    ) -> list[TraceHealthRunRecord]:
        fetch_limit = max(int(limit) * 5, int(limit), 10)
        traces = read_health_run_traces(
            database_name=database_name,
            completed_after=(time_scope or {}).get("completed_after"),
            completed_before=(time_scope or {}).get("completed_before"),
            limit=fetch_limit,
            db_key=db_key,
        )
        deduped = _dedupe_trace_records(traces)
        return deduped[: max(int(limit), 0)]
```

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 790-863)
```
    def _index_snapshot(
        self,
        *,
        database_name: str | None,
        time_scope: dict[str, Any] | None,
        db_key: str | None = None,
    ) -> dict[str, Any]:
        paths = history_data_source_paths(db_key=db_key)
        files_present = {name: path.exists() for name, path in paths.items() if name != "health_runs"}
        files_read: list[str] = []
        notes: list[str] = []
        recurring_records: list[RecurringIssueIndexRecord] = []
        chunk_records: list[TraceEvidenceChunk] = []
        behavior_profiles: list[OraclePlannerMemoryRecord] = []
        history_entries: list[dict[str, Any]] = []

        if files_present.get("recurring_issues"):
            recurring_records = read_recurring_issue_index(database_name=database_name, limit=None, db_key=db_key)
            files_read.append(str(paths["recurring_issues"]))
        if files_present.get("trace_chunks"):
            chunk_records = read_trace_evidence_chunks(
                database_name=database_name,
                completed_after=(time_scope or {}).get("completed_after"),
                completed_before=(time_scope or {}).get("completed_before"),
                limit=None,
                db_key=db_key,
            )
            files_read.append(str(paths["trace_chunks"]))
        if files_present.get("database_behavior_profiles"):
            behavior_profiles = read_database_planner_memory(database_name=database_name, limit=None, db_key=db_key)
            files_read.append(str(paths["database_behavior_profiles"]))
        if files_present.get("history_indexing"):
            history_entries = read_history_index_entries(database_name=database_name, limit=None, db_key=db_key)
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
```


## Source Files:

- `history/jsonl_service.py`

