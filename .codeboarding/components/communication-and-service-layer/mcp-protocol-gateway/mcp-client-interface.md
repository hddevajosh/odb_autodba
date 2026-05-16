---
component_id: 2.1.2
component_name: MCP Client Interface
---

# MCP Client Interface

## Component Description

Provides a high-level API for the platform's agents to interact with the MCP server. It abstracts the HTTP/MCP communication details, handling the complexities of job submission, status polling, and result retrieval.

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

### /home/neha/projects/agents/odb_autodba/mcp/client.py (lines 172-192)
```
def poll_job(job_id: str, timeout_seconds: float | None = None, poll_seconds: float | None = None) -> dict[str, Any]:
    timeout = timeout_seconds if timeout_seconds is not None else get_mcp_poll_timeout_seconds()
    sleep_s = poll_seconds if poll_seconds is not None else get_mcp_poll_seconds()
    started = time.monotonic()
    last: dict[str, Any] = {"ok": False, "error": "job polling not started", "job_id": job_id}
    while True:
        last = get_job(job_id)
        status = str(last.get("status") or "").lower()
        if status in {"completed", "failed"}:
            return last
        if time.monotonic() - started >= timeout:
            return {
                "ok": False,
                "job_id": job_id,
                "status": status or "unknown",
                "error": f"job polling timed out after {int(timeout)} seconds",
                "error_type": "TimeoutError",
                "endpoint": "/job/{job_id}",
                "last_job": last,
            }
        time.sleep(sleep_s)
```

### /home/neha/projects/agents/odb_autodba/mcp/client.py (lines 137-142)
```
def get_latest_report(report_type: str = "health", db_key: str | None = None) -> dict[str, Any]:
    params = {"report_type": report_type}
    if (db_key or "").strip():
        params["db_key"] = str(db_key).strip()
    qs = urllib.parse.urlencode(params)
    return _get_json(f"/report/latest?{qs}")
```


## Source Files:

- `mcp/client.py`

