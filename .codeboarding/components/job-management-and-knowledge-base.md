---
component_id: 5
component_name: Job Management & Knowledge Base
---

# Job Management & Knowledge Base

## Component Description

Handles the asynchronous execution of diagnostic tasks and maintains the system's memory through RAG (Retrieval-Augmented Generation) and trace storage.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 194-199)
```
def run_job(job_id: str) -> None:
    reserved = _reserve_specific_pending_job(job_id)
    if reserved is None:
        return
    _execute_reserved_job(reserved)
    _drain_pending_jobs()
```

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


## Source Files:

- `db/extended_health_checks.py`
- `history/jsonl_service.py`
- `host/health_checks.py`
- `mcp/jobs.py`
- `rag/indexer.py`
- `rag/investigation_trace_store.py`
- `rag/retriever.py`
- `rag/trace_store.py`

