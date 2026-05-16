---
component_id: 5.1
component_name: Job Execution & Lifecycle Manager
---

# Job Execution & Lifecycle Manager

## Component Description

Orchestrates the asynchronous execution of diagnostic jobs, managing concurrency, deduplication, and the transition from raw execution to finalized investigation reports.

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

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 54-98)
```
def create_job(job_type: str, db_key: str | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if job_type not in ALLOWED_JOB_TYPES:
        raise ValueError(f"Unsupported job_type: {job_type}")
    now = _utc_now_iso()
    clean_payload = _sanitize_value(payload or {})
    _register_target_from_payload(clean_payload)
    resolved_db_key = get_oracle_target(db_key).db_key

    with _jobs_lock(exclusive=True):
        jobs = _load_all_jobs_unlocked()
        if _dedup_jobs_enabled():
            deduped = _find_dedup_candidate(
                jobs,
                job_type=job_type,
                db_key=resolved_db_key,
                payload=clean_payload,
                now_iso=now,
            )
            if deduped is not None:
                existing = dict(deduped)
                existing["deduped"] = True
                _log_job_event(existing, status=str(existing.get("status") or "pending"), elapsed_ms=None)
                return existing

        queue_reason = _queue_reason_for_job(
            jobs,
            job_type=job_type,
            db_key=resolved_db_key,
        )
        job = {
            "job_id": uuid.uuid4().hex,
            "db_key": resolved_db_key,
            "job_type": job_type,
            "status": "pending",
            "created_at": now,
            "started_at": None,
            "completed_at": None,
            "payload": clean_payload,
            "result": None,
            "error": None,
            "error_type": None,
            "queue_reason": queue_reason,
        }
        _write_job_unlocked(job)
        return job
```

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

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 391-434)
```
def _execute_reserved_job(job: dict[str, Any]) -> None:
    job_id = str(job.get("job_id") or "")
    started = datetime.now(UTC)
    try:
        timeout_seconds = _job_timeout_seconds(str(job.get("job_type") or ""))
        result = _dispatch_with_timeout(job, timeout_seconds=timeout_seconds)
        if isinstance(result, dict):
            result = _finalize_job_result(result, job=job)
        update_job(
            job_id,
            status="completed",
            completed_at=_utc_now_iso(),
            result=_sanitize_value(result if isinstance(result, dict) else {"value": result}),
            error=None,
            error_type=None,
            queue_reason=None,
        )
        elapsed_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
        _log_job_event(job, status="completed", elapsed_ms=elapsed_ms)
    except TimeoutError as exc:
        message = _sanitize_error_message(str(exc) or "job exceeded timeout")
        update_job(
            job_id,
            status="failed",
            completed_at=_utc_now_iso(),
            result=None,
            error=message,
            error_type="TimeoutError",
            queue_reason=None,
        )
        elapsed_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
        _log_job_event(job, status="failed", elapsed_ms=elapsed_ms, error_type="TimeoutError")
    except Exception as exc:
        update_job(
            job_id,
            status="failed",
            completed_at=_utc_now_iso(),
            result=None,
            error=_sanitize_error_message(str(exc)),
            error_type=type(exc).__name__,
            queue_reason=None,
        )
        elapsed_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
        _log_job_event(job, status="failed", elapsed_ms=elapsed_ms, error_type=type(exc).__name__)
```


## Source Files:

- `mcp/jobs.py`

