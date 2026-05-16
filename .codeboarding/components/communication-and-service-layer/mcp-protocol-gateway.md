---
component_id: 2.1
component_name: MCP Protocol Gateway
---

# MCP Protocol Gateway

## Component Description

Acts as the primary interface for the Model Context Protocol, exposing DBA capabilities as standardized tools. It handles the translation between external agent requests and internal job execution, managing both synchronous tool calls and asynchronous job polling.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/mcp/client.py (lines 94-102)
```
def submit_investigation_job(
    question: str,
    db_key: str | None = None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"db_key": db_key, "question": question}
    if target is not None:
        payload["target"] = target
    return _post_json("/investigate", payload)
```

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


## Source Files:

- `mcp/client.py`
- `mcp/server.py`

