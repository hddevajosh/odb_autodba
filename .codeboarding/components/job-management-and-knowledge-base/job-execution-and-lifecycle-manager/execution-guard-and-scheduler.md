---
component_id: 5.1.2
component_name: Execution Guard & Scheduler
---

# Execution Guard & Scheduler

## Component Description

Implements the governance logic for the subsystem. It evaluates system load and database-specific constraints to determine when a job is permitted to start, ensuring that asynchronous tasks do not overwhelm the target Oracle environments.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 460-470)
```
def _can_start_job(job: dict[str, Any], jobs: list[dict[str, Any]]) -> bool:
    running = [row for row in jobs if str(row.get("status") or "") == "running"]
    if len(running) >= _max_total_jobs():
        return False
    job_type = str(job.get("job_type") or "")
    if _running_count_for_type(running, job_type) >= _max_jobs_for_type(job_type):
        return False
    db_key = str(job.get("db_key") or "")
    if _running_count_for_db(running, db_key) >= _max_running_per_db_default():
        return False
    return True
```

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 581-598)
```
def _max_jobs_for_type(job_type: str) -> int:
    if job_type == "health_check":
        return _env_int("ODB_AUTODBA_MAX_HEALTH_JOBS", 5, minimum=1)
    if job_type == "historical_trends":
        return _env_int("ODB_AUTODBA_MAX_HISTORY_JOBS", 2, minimum=1)
    if job_type == "history_metric_question":
        return _env_int("ODB_AUTODBA_MAX_HISTORY_METRIC_JOBS", _env_int("ODB_AUTODBA_MAX_HISTORY_JOBS", 2, minimum=1), minimum=1)
    if job_type == "investigation":
        return _env_int("ODB_AUTODBA_MAX_INVESTIGATION_JOBS", 2, minimum=1)
    if job_type == "active_sessions":
        return _env_int("ODB_AUTODBA_MAX_SESSIONS_JOBS", _env_int("ODB_AUTODBA_MAX_HEALTH_JOBS", 5, minimum=1), minimum=1)
    if job_type == "blocking_analysis":
        return _env_int("ODB_AUTODBA_MAX_BLOCKING_JOBS", _env_int("ODB_AUTODBA_MAX_SESSIONS_JOBS", 5, minimum=1), minimum=1)
    if job_type == "sql_id_analysis":
        return _env_int("ODB_AUTODBA_MAX_SQL_ID_ANALYSIS_JOBS", _env_int("ODB_AUTODBA_MAX_INVESTIGATION_JOBS", 2, minimum=1), minimum=1)
    if job_type == "awr_analysis":
        return _env_int("ODB_AUTODBA_MAX_AWR_ANALYSIS_JOBS", _env_int("ODB_AUTODBA_MAX_HISTORY_JOBS", 2, minimum=1), minimum=1)
    return _env_int("ODB_AUTODBA_MAX_TOTAL_JOBS", 10, minimum=1)
```

### /home/neha/projects/agents/odb_autodba/mcp/jobs.py (lines 575-578)
```
def _running_count_for_db(running_jobs: list[dict[str, Any]], db_key: str) -> int:
    if not db_key:
        return 0
    return sum(1 for row in running_jobs if str(row.get("db_key") or "") == db_key)
```


## Source Files:

- `mcp/jobs.py`

