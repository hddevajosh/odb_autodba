---
component_id: 2.1.3
component_name: Protocol Configuration & Reporting
---

# Protocol Configuration & Reporting

## Component Description

Manages the operational context of the gateway, including feature flags that toggle between local and remote execution modes. It also handles the mapping of job outputs to specific DBA report types for final delivery to the user or agent.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/mcp/client.py (lines 15-17)
```
def use_mcp_enabled() -> bool:
    load_project_dotenv()
    return _env_bool("ODB_AUTODBA_USE_MCP", alias="PGAUTODBA_USE_MCP", default=False)
```

### /home/neha/projects/agents/odb_autodba/mcp/server.py (lines 547-610)
```
def report_latest(db_key: str | None = None, report_type: str = "health") -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/report/latest"
    try:
        normalized = _normalize_report_type(report_type)
        if normalized == "health":
            traces = read_health_run_traces(limit=20, db_key=db_key)
            for trace in traces:
                rendered = str(trace.report_markdown or "").strip()
                if not rendered:
                    continue
                report_path = _write_latest_export_if_needed(
                    rendered_report=rendered,
                    db_key=db_key,
                    prefix=f"health_{trace.run_id or 'latest'}",
                    current_path=None,
                )
                payload = {
                    "ok": True,
                    "report_type": "health",
                    "db_key": db_key,
                    "summary": trace.summary,
                    "rendered_report": rendered,
                    "report_path": report_path,
                    "trace_path": trace.trace_path,
                    "created_at": trace.completed_at or trace.recorded_at,
                }
                _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=True)
                return payload
            _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
            return {"ok": False, "message": "No health report found yet.", "report_type": "health", "db_key": db_key}

        job_type = _job_type_for_report_type(normalized)
        jobs_payload = list_jobs(limit=50, status="completed", db_key=db_key, job_type=job_type)
        for job in jobs_payload:
            result = job.get("result") if isinstance(job.get("result"), dict) else {}
            rendered = str(result.get("rendered_report") or "").strip()
            if not rendered:
                continue
            report_path = _write_latest_export_if_needed(
                rendered_report=rendered,
                db_key=db_key,
                prefix=f"{normalized}_{job.get('job_id') or 'latest'}",
                current_path=result.get("report_path"),
            )
            payload = {
                "ok": True,
                "report_type": normalized,
                "db_key": db_key,
                "summary": str(result.get("summary") or ""),
                "rendered_report": rendered,
                "report_path": report_path,
                "trace_path": str(result.get("trace_path") or ""),
                "created_at": job.get("completed_at") or job.get("created_at"),
                "job_id": job.get("job_id"),
                "job_type": job.get("job_type"),
            }
            _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=True)
            return payload
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
        return {"ok": False, "message": f"No {normalized} report found yet.", "report_type": normalized, "db_key": db_key}
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)
```

### /home/neha/projects/agents/odb_autodba/mcp/server.py (lines 641-650)
```
def _job_type_for_report_type(report_type: str) -> str | None:
    return {
        "history": "historical_trends",
        "history_metric": "history_metric_question",
        "sessions": "active_sessions",
        "blocking": "blocking_analysis",
        "sql_id": "sql_id_analysis",
        "awr": "awr_analysis",
        "investigation": "investigation",
    }.get(report_type)
```


## Source Files:

- `mcp/client.py`
- `mcp/server.py`

