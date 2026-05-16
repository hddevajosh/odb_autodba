---
component_id: 5.1.4
component_name: Result Processor & Janitor
---

# Result Processor & Janitor

## Component Description

Handles the "post-execution" phase of the lifecycle. This includes transforming raw execution outputs into finalized investigation reports and performing periodic maintenance to purge expired job records and logs.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 263-287)
```
def _finalize_job_result(result: dict[str, Any], *, job: dict[str, Any]) -> dict[str, Any]:
    job_type = str(job.get("job_type") or "")
    if job_type != "investigation":
        return _ensure_result_report_export(result, job=job)

    rendered_report = str(result.get("rendered_report") or "").strip()
    trace_path = str(result.get("trace_path") or "").strip()
    db_key = str(result.get("db_key") or job.get("db_key") or "").strip() or None
    job_id = str(job.get("job_id") or "").strip()

    if trace_path and _needs_investigation_hydration(rendered_report):
        hydrated = hydrate_investigation_report_from_trace(trace_path).strip()
        if hydrated and "No investigation trace events were available for hydration." not in hydrated:
            result["rendered_report"] = hydrated
            rendered_report = hydrated

    if rendered_report:
        report_path = str(result.get("report_path") or "").strip()
        if not report_path:
            result["report_path"] = _write_investigation_export(
                rendered_report=rendered_report,
                db_key=db_key,
                job_id=job_id,
            )
    return _ensure_result_report_export(result, job=job)
```

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 290-295)
```
def _write_investigation_export(*, rendered_report: str, db_key: str | None, job_id: str) -> str:
    exports_dir = get_exports_dir(db_key=db_key)
    safe_job_id = re.sub(r"[^a-zA-Z0-9_-]+", "", job_id) or "unknown"
    path = exports_dir / f"investigation_{safe_job_id}.md"
    path.write_text(str(rendered_report or ""), encoding="utf-8")
    return str(path)
```

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 107-132)
```
def cleanup_old_jobs(*, retention_hours: float | None = None) -> int:
    horizon = timedelta(hours=retention_hours if retention_hours is not None else _job_retention_hours())
    cutoff = datetime.now(UTC) - horizon
    removed = 0
    with _jobs_lock(exclusive=True):
        for path, payload in _load_all_job_rows_unlocked():
            status = str(payload.get("status") or "").lower()
            if status not in FINAL_JOB_STATUSES:
                continue
            stamp = _parse_iso(payload.get("completed_at")) or _parse_iso(payload.get("created_at"))
            if stamp is None or stamp >= cutoff:
                continue
            try:
                path.unlink(missing_ok=True)
                removed += 1
            except Exception as exc:
                LOGGER.warning(
                    "job_cleanup_unlink_failed path=%s error_type=%s error=%s",
                    path,
                    type(exc).__name__,
                    _sanitize_error_message(str(exc)),
                )
                continue
    if removed:
        LOGGER.info("job_cleanup removed=%s retention_hours=%s", removed, retention_hours or _job_retention_hours())
    return removed
```


## Source Files:

- `mcp/jobs.py`

