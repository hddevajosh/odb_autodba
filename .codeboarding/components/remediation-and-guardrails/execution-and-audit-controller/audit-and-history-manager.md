---
component_id: 6.3.2
component_name: Audit & History Manager
---

# Audit & History Manager

## Component Description

Manages the persistent, file-backed (JSONL) record of all system actions. It ensures that every execution attempt is immutable and searchable, providing the "Trace Store" that fuels the agent's RAG-based feedback loops and historical auditing.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/tools/action_history.py (lines 19-23)
```
def append_action_record(record: RemediationRecord, *, db_key: str | None = None) -> None:
    path = _history_file_path(db_key=db_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(record.model_dump_json() + "\n")
```


## Source Files:

- `tools/action_executor.py`
- `tools/action_history.py`

