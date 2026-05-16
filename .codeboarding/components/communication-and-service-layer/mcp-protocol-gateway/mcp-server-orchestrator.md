---
component_id: 2.1.1
component_name: MCP Server Orchestrator
---

# MCP Server Orchestrator

## Component Description

The core execution engine of the gateway. It exposes DBA capabilities (investigation, health checks) as MCP tools. It is responsible for receiving requests, scheduling them as asynchronous jobs, and managing the server-side state of these tasks.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/mcp/server.py (lines 268-298)
```
def investigate(req: InvestigateRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/investigate"
    db_key = req.db_key
    question = (req.question or "").strip()
    try:
        if not question:
            _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
            return {
                "ok": False,
                "error": "question is required",
                "error_type": "ValidationError",
                "endpoint": endpoint,
            }
        payload: dict[str, Any] = {"question": question}
        if isinstance(req.target, dict):
            payload["target"] = req.target
        job = create_job("investigation", db_key=db_key, payload=payload)
        _schedule_job(background_tasks=background_tasks, job_id=job["job_id"])
        payload = {
            "ok": True,
            "job_id": job["job_id"],
            "status": job["status"],
            "db_key": job["db_key"],
            "job_type": job["job_type"],
        }
        _log_request(endpoint=endpoint, db_key=job.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)
```

### /home/neha/projects/agents/odb_autodba/mcp/server.py (lines 613-617)
```
def _schedule_job(*, background_tasks: BackgroundTasks | None, job_id: str) -> None:
    if background_tasks is None:
        run_job(job_id)
        return
    background_tasks.add_task(run_job, job_id)
```

### /home/neha/projects/agents/odb_autodba/mcp/server.py (lines 364-377)
```
def job_by_id(job_id: str) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/job/{job_id}"
    try:
        payload = get_job(job_id)
        if payload is None:
            _log_request(endpoint=endpoint, db_key=None, start=start, ok=False)
            return {"ok": False, "error": "job not found", "job_id": job_id}
        payload = {"ok": True, **payload}
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=None, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)
```


## Source Files:

- `mcp/server.py`

