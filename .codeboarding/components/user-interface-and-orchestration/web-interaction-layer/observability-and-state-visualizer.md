---
component_id: 1.1.4
component_name: Observability & State Visualizer
---

# Observability & State Visualizer

## Component Description

Provides real-time visibility into the system's background operations. It monitors the asynchronous job queue and formats historical trace data into compact summaries, ensuring the user is informed of long-running diagnostic tasks.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 818-843)
```
def _recent_jobs_markdown(selected_db_key: str | None, limit: int = 10) -> str:
    if get_execution_mode() != "mcp":
        return "Recent jobs are available in MCP mode."
    payload = list_mcp_jobs(limit=max(int(limit or 1), 1), db_key=selected_db_key)
    if not payload.get("ok"):
        return f"Recent jobs unavailable: {_safe_error_message(str(payload.get('error') or 'unknown error'))}"
    rows = payload.get("jobs") if isinstance(payload.get("jobs"), list) else []
    if not rows:
        return "No recent jobs."
    lines = [
        "| job_id | type | status | db_key | created_at | completed_at | summary |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows[: max(int(limit or 1), 1)]:
        lines.append(
            "| {job_id} | {job_type} | {status} | {db_key} | {created} | {completed} | {summary} |".format(
                job_id=_truncate_inline(str(row.get("job_id") or "-"), 18),
                job_type=_truncate_inline(str(row.get("job_type") or "-"), 16),
                status=_truncate_inline(str(row.get("status") or "-"), 10),
                db_key=_truncate_inline(str(row.get("db_key") or "-"), 22),
                created=_truncate_inline(str(row.get("created_at") or "-"), 25),
                completed=_truncate_inline(str(row.get("completed_at") or "-"), 25),
                summary=_truncate_inline(_job_compact_summary(row), 72).replace("|", "/"),
            )
        )
    return "\n".join(lines)
```

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 801-815)
```
def _job_compact_summary(job: dict) -> str:
    result = job.get("result") if isinstance(job.get("result"), dict) else {}
    summary = str(result.get("summary") or job.get("summary") or "").strip()
    if summary:
        return _truncate_inline(summary, 72)
    rendered = str(result.get("rendered_report") or "").strip()
    if rendered:
        for line in rendered.splitlines():
            clean = line.strip().lstrip("#").strip()
            if clean:
                return _truncate_inline(clean, 72)
    error = str(job.get("error") or "").strip()
    if error:
        return _truncate_inline(error, 72)
    return "-"
```


## Source Files:

- `frontend/gradio_app.py`

