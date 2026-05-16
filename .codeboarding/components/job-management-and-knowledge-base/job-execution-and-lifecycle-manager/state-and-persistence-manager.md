---
component_id: 5.1.3
component_name: State & Persistence Manager
---

# State & Persistence Manager

## Component Description

Provides the thread-safe data access layer for the subsystem. It manages the physical JSONL-backed storage, file locking mechanisms, and the retrieval of job metadata required for both execution and historical listing.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 736-751)
```
def _jobs_lock(*, exclusive: bool) -> Iterator[None]:
    with WRITE_LOCK:
        lock_file = _jobs_dir() / ".jobs.lock"
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_file.open("a+", encoding="utf-8")
        try:
            if fcntl is not None:
                lock_mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                fcntl.flock(handle.fileno(), lock_mode)
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()
```

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 177-191)
```
def update_job(job_id: str, **fields: Any) -> dict[str, Any]:
    with _jobs_lock(exclusive=True):
        path = _job_path(job_id)
        current = _load_job_file_unlocked(path)
        if current is None:
            raise FileNotFoundError(f"job not found: {job_id}")
        for key, value in fields.items():
            if key in {"payload", "result"} and isinstance(value, dict):
                current[key] = _sanitize_value(value)
            elif key in {"error"} and isinstance(value, str):
                current[key] = _sanitize_error_message(value)
            else:
                current[key] = value
        _write_job_unlocked(current)
        return current
```

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 528-529)
```
def _load_all_jobs_unlocked() -> list[dict[str, Any]]:
    return [payload for _, payload in _load_all_job_rows_unlocked()]
```


## Source Files:

- `mcp/jobs.py`

