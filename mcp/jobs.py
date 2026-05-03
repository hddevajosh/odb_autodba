from __future__ import annotations

import json
import logging
import os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from odb_autodba.rag.investigation_trace_store import hydrate_investigation_report_from_trace
from odb_autodba.runtime_paths import get_exports_dir
from odb_autodba.services.autodba_service import (
    analyze_awr,
    analyze_blocking_sessions,
    analyze_sql_id,
    answer_history_metric_question,
    get_active_sessions,
    get_historical_trends,
    run_ai_investigation,
    run_health_check,
)
from odb_autodba.target_registry import build_transient_target, get_oracle_target, register_transient_target
from odb_autodba.utils.env_loader import load_project_dotenv

try:
    import fcntl
except Exception:  # pragma: no cover - non-posix fallback
    fcntl = None


LOGGER = logging.getLogger("odb_autodba.mcp.jobs")
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PACKAGE_ROOT.parent
DEFAULT_JOBS_DIR = REPO_ROOT / "runtime" / "jobs"
WRITE_LOCK = threading.Lock()
ALLOWED_JOB_TYPES = {
    "health_check",
    "historical_trends",
    "history_metric_question",
    "investigation",
    "active_sessions",
    "blocking_analysis",
    "sql_id_analysis",
    "awr_analysis",
}
FINAL_JOB_STATUSES = {"completed", "failed"}


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


def maybe_cleanup_on_start() -> int:
    if not _cleanup_on_start_enabled():
        return 0
    return cleanup_old_jobs()


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
            except Exception:
                continue
    if removed:
        LOGGER.info("job_cleanup removed=%s retention_hours=%s", removed, retention_hours or _job_retention_hours())
    return removed


def get_job(job_id: str) -> dict[str, Any] | None:
    path = _job_path(job_id)
    if not path.exists():
        return None
    with _jobs_lock(exclusive=False):
        payload = _load_job_file_unlocked(path)
    return payload if isinstance(payload, dict) else None


def list_jobs(
    limit: int = 20,
    status: str | None = None,
    db_key: str | None = None,
    job_type: str | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
) -> list[dict[str, Any]]:
    after_dt = _parse_iso(created_after)
    before_dt = _parse_iso(created_before)

    with _jobs_lock(exclusive=False):
        rows = [payload for _, payload in _load_all_job_rows_unlocked()]

    filtered: list[dict[str, Any]] = []
    for payload in rows:
        if status and payload.get("status") != status:
            continue
        if db_key and payload.get("db_key") != db_key:
            continue
        if job_type and payload.get("job_type") != job_type:
            continue
        created_at = _parse_iso(payload.get("created_at"))
        if after_dt and (created_at is None or created_at < after_dt):
            continue
        if before_dt and (created_at is None or created_at > before_dt):
            continue
        filtered.append(payload)

    filtered.sort(key=_job_created_sort_key, reverse=True)
    return filtered[: max(int(limit or 1), 1)]


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


def run_job(job_id: str) -> None:
    reserved = _reserve_specific_pending_job(job_id)
    if reserved is None:
        return
    _execute_reserved_job(reserved)
    _drain_pending_jobs()


def _register_target_from_payload(payload: dict[str, Any]) -> None:
    target_data = payload.get("target")
    if not isinstance(target_data, dict):
        return
    required = ["environment", "host", "port", "username"]
    for key in required:
        if not str(target_data.get(key) or "").strip():
            raise ValueError(f"target payload missing required field '{key}'")
    target = build_transient_target(
        environment=str(target_data.get("environment") or ""),
        host=str(target_data.get("host") or ""),
        port=target_data.get("port") or 1521,
        username=str(target_data.get("username") or ""),
        service_name=(str(target_data.get("service_name") or "").strip() or None),
        sid=(str(target_data.get("sid") or "").strip() or None),
        pdb_name=(str(target_data.get("pdb_name") or "").strip() or None),
        cdb_name=(str(target_data.get("cdb_name") or "").strip() or None),
        connect_descriptor=(str(target_data.get("connect_descriptor") or "").strip() or None),
        display_name=(str(target_data.get("display_name") or "").strip() or None),
        password_env=(str(target_data.get("password_env") or "").strip() or None),
        sysdba=bool(target_data.get("sysdba")),
    )
    requested_db_key = str(target_data.get("db_key") or "").strip()
    if requested_db_key and requested_db_key != target.db_key:
        raise ValueError("target payload db_key does not match computed key")
    register_transient_target(target, password=None, replace=True)


def _dispatch_job(job: dict[str, Any]) -> dict[str, Any]:
    job_type = str(job.get("job_type") or "")
    db_key = job.get("db_key")
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    if job_type == "health_check":
        return run_health_check(db_key=db_key)
    if job_type == "historical_trends":
        return get_historical_trends(db_key=db_key)
    if job_type == "history_metric_question":
        question = str(payload.get("question") or "").strip()
        if not question:
            raise ValueError("question is required for history_metric_question job")
        return answer_history_metric_question(question, db_key=db_key)
    if job_type == "investigation":
        question = str(payload.get("question") or "").strip()
        if not question:
            raise ValueError("question is required for investigation job")
        return run_ai_investigation(question, db_key=db_key)
    if job_type == "active_sessions":
        return get_active_sessions(db_key=db_key)
    if job_type == "blocking_analysis":
        return analyze_blocking_sessions(db_key=db_key)
    if job_type == "sql_id_analysis":
        sql_id = str(payload.get("sql_id") or "").strip()
        if not sql_id:
            raise ValueError("sql_id is required for sql_id_analysis job")
        return analyze_sql_id(sql_id, db_key=db_key)
    if job_type == "awr_analysis":
        question = str(payload.get("question") or "").strip()
        return analyze_awr(question or None, db_key=db_key)
    raise ValueError(f"Unsupported job_type: {job_type}")


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


def _write_investigation_export(*, rendered_report: str, db_key: str | None, job_id: str) -> str:
    exports_dir = get_exports_dir(db_key=db_key)
    safe_job_id = re.sub(r"[^a-zA-Z0-9_-]+", "", job_id) or "unknown"
    path = exports_dir / f"investigation_{safe_job_id}.md"
    path.write_text(str(rendered_report or ""), encoding="utf-8")
    return str(path)


def _needs_investigation_hydration(rendered_report: str) -> bool:
    text = str(rendered_report or "").strip()
    if not text:
        return True

    lowered = text.lower()
    placeholder_markers = (
        "no rendered report/summary was provided",
        "compact job payload",
        "investigation failed.",
    )
    if any(marker in lowered for marker in placeholder_markers):
        return True

    has_sql_section = "## sql steps run" in lowered or "## sql executed" in lowered
    has_conclusion_section = any(
        marker in lowered
        for marker in (
            "## likely cause",
            "## 🔵 investigation conclusion",
            "## 🔴 root cause analysis",
        )
    )
    return not (has_sql_section and has_conclusion_section)


def _ensure_result_report_export(result: dict[str, Any], *, job: dict[str, Any]) -> dict[str, Any]:
    rendered_report = str(result.get("rendered_report") or "").strip()
    if not rendered_report:
        return result
    report_path = str(result.get("report_path") or "").strip()
    if report_path:
        return result
    db_key = str(result.get("db_key") or job.get("db_key") or "").strip() or None
    safe_job_type = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(job.get("job_type") or "report")) or "report"
    safe_job_id = re.sub(r"[^a-zA-Z0-9_-]+", "", str(job.get("job_id") or "")) or uuid.uuid4().hex
    path = get_exports_dir(db_key=db_key) / f"{safe_job_type}_{safe_job_id}.md"
    path.write_text(rendered_report, encoding="utf-8")
    result["report_path"] = str(path)
    return result


def _drain_pending_jobs() -> None:
    while True:
        reserved = _reserve_next_pending_job()
        if reserved is None:
            return
        _execute_reserved_job(reserved)


def _reserve_specific_pending_job(job_id: str) -> dict[str, Any] | None:
    with _jobs_lock(exclusive=True):
        path = _job_path(job_id)
        payload = _load_job_file_unlocked(path)
        if payload is None:
            return None
        status = str(payload.get("status") or "")
        if status != "pending":
            return None
        jobs = _load_all_jobs_unlocked()
        if not _can_start_job(payload, jobs):
            payload["queue_reason"] = _queue_reason_for_job(jobs, job_type=str(payload.get("job_type") or ""), db_key=str(payload.get("db_key") or ""))
            _write_job_unlocked(payload)
            return None
        payload["status"] = "running"
        payload["started_at"] = _utc_now_iso()
        payload["completed_at"] = None
        payload["error"] = None
        payload["error_type"] = None
        payload["queue_reason"] = None
        _write_job_unlocked(payload)
        return payload


def _reserve_next_pending_job() -> dict[str, Any] | None:
    with _jobs_lock(exclusive=True):
        rows = _load_all_jobs_unlocked()
        pending = [row for row in rows if str(row.get("status") or "") == "pending"]
        pending.sort(key=_job_created_sort_key)
        for candidate in pending:
            if not _can_start_job(candidate, rows):
                continue
            candidate["status"] = "running"
            candidate["started_at"] = _utc_now_iso()
            candidate["completed_at"] = None
            candidate["error"] = None
            candidate["error_type"] = None
            candidate["queue_reason"] = None
            _write_job_unlocked(candidate)
            return candidate
        return None


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


def _dispatch_with_timeout(job: dict[str, Any], *, timeout_seconds: int) -> dict[str, Any]:
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_dispatch_job, job)
    try:
        return future.result(timeout=max(1, timeout_seconds))
    except FuturesTimeoutError as exc:
        future.cancel()
        raise TimeoutError(f"Job timed out after {timeout_seconds} seconds") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _queue_reason_for_job(jobs: list[dict[str, Any]], *, job_type: str, db_key: str) -> str | None:
    running = [job for job in jobs if str(job.get("status") or "") == "running"]
    if len(running) >= _max_total_jobs():
        return "total_running_limit_reached"
    if _running_count_for_type(running, job_type) >= _max_jobs_for_type(job_type):
        return f"{job_type}_running_limit_reached"
    if _running_count_for_db(running, db_key) >= _max_running_per_db_default():
        return "db_running_limit_reached"
    return None


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


def _find_dedup_candidate(
    jobs: list[dict[str, Any]],
    *,
    job_type: str,
    db_key: str,
    payload: dict[str, Any],
    now_iso: str,
) -> dict[str, Any] | None:
    now_dt = _parse_iso(now_iso)
    if now_dt is None:
        return None
    signature = _dedup_signature(job_type=job_type, db_key=db_key, payload=payload)
    window = timedelta(seconds=_dedup_window_seconds())
    best: dict[str, Any] | None = None
    for row in jobs:
        status = str(row.get("status") or "")
        if status not in {"pending", "running"}:
            continue
        created = _parse_iso(row.get("created_at"))
        if created is None or now_dt - created > window:
            continue
        if _dedup_signature(
            job_type=str(row.get("job_type") or ""),
            db_key=str(row.get("db_key") or ""),
            payload=row.get("payload") if isinstance(row.get("payload"), dict) else {},
        ) != signature:
            continue
        if best is None or _job_created_sort_key(row) > _job_created_sort_key(best):
            best = row
    return best


def _dedup_signature(*, job_type: str, db_key: str, payload: dict[str, Any]) -> str:
    canonical_payload = json.dumps(_sanitize_value(payload), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return f"{job_type}|{db_key}|{canonical_payload}"


def _jobs_dir() -> Path:
    load_project_dotenv()
    configured = (os.getenv("ODB_AUTODBA_JOBS_DIR") or "").strip()
    if configured:
        path = Path(configured)
        if not path.is_absolute():
            path = Path.cwd() / path
    else:
        path = DEFAULT_JOBS_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _job_path(job_id: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "", str(job_id))
    return _jobs_dir() / f"{safe}.json"


def _load_all_jobs_unlocked() -> list[dict[str, Any]]:
    return [payload for _, payload in _load_all_job_rows_unlocked()]


def _load_all_job_rows_unlocked() -> list[tuple[Path, dict[str, Any]]]:
    rows: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(_jobs_dir().glob("*.json"), key=lambda item: item.name):
        payload = _load_job_file_unlocked(path)
        if isinstance(payload, dict):
            rows.append((path, payload))
    return rows


def _load_job_file_unlocked(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _write_job_unlocked(job: dict[str, Any]) -> None:
    path = _job_path(str(job.get("job_id") or ""))
    payload = _sanitize_value(job)
    data = json.dumps(payload, ensure_ascii=True, indent=2, default=str)
    tmp = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _job_created_sort_key(job: dict[str, Any]) -> datetime:
    return _parse_iso(job.get("created_at")) or datetime.min.replace(tzinfo=UTC)


def _running_count_for_type(running_jobs: list[dict[str, Any]], job_type: str) -> int:
    return sum(1 for row in running_jobs if str(row.get("job_type") or "") == job_type)


def _running_count_for_db(running_jobs: list[dict[str, Any]], db_key: str) -> int:
    if not db_key:
        return 0
    return sum(1 for row in running_jobs if str(row.get("db_key") or "") == db_key)


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


def _max_total_jobs() -> int:
    return _env_int("ODB_AUTODBA_MAX_TOTAL_JOBS", 10, minimum=1)


def _max_running_per_db_default() -> int:
    return _env_int("ODB_AUTODBA_MAX_JOBS_PER_DB", _max_total_jobs(), minimum=1)


def _job_timeout_seconds(job_type: str) -> int:
    generic = _env_int("ODB_AUTODBA_JOB_TIMEOUT_SECONDS", 600, minimum=1)
    if job_type == "investigation":
        return _env_int("ODB_AUTODBA_INVESTIGATION_TIMEOUT_SECONDS", 300, minimum=1)
    if job_type == "historical_trends":
        return _env_int("ODB_AUTODBA_HISTORY_TIMEOUT_SECONDS", 600, minimum=1)
    if job_type == "history_metric_question":
        return _env_int("ODB_AUTODBA_HISTORY_METRIC_TIMEOUT_SECONDS", _env_int("ODB_AUTODBA_HISTORY_TIMEOUT_SECONDS", 600, minimum=1), minimum=1)
    if job_type == "blocking_analysis":
        return _env_int("ODB_AUTODBA_BLOCKING_TIMEOUT_SECONDS", generic, minimum=1)
    if job_type == "sql_id_analysis":
        return _env_int("ODB_AUTODBA_SQL_ID_TIMEOUT_SECONDS", _env_int("ODB_AUTODBA_INVESTIGATION_TIMEOUT_SECONDS", 300, minimum=1), minimum=1)
    if job_type == "awr_analysis":
        return _env_int("ODB_AUTODBA_AWR_TIMEOUT_SECONDS", _env_int("ODB_AUTODBA_HISTORY_TIMEOUT_SECONDS", 600, minimum=1), minimum=1)
    return generic


def _job_retention_hours() -> float:
    raw = (os.getenv("ODB_AUTODBA_JOB_RETENTION_HOURS") or "72").strip()
    try:
        value = float(raw)
    except Exception:
        value = 72.0
    return max(value, 1.0)


def _cleanup_on_start_enabled() -> bool:
    return _env_bool("ODB_AUTODBA_JOB_CLEANUP_ON_START", default=True)


def _dedup_jobs_enabled() -> bool:
    return _env_bool("ODB_AUTODBA_DEDUP_JOBS", default=True)


def _dedup_window_seconds() -> int:
    return _env_int("ODB_AUTODBA_DEDUP_WINDOW_SECONDS", 60, minimum=1)


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = (os.getenv(name) or "").strip()
    try:
        value = int(raw)
    except Exception:
        value = default
    return max(value, minimum)


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _log_job_event(job: dict[str, Any], *, status: str, elapsed_ms: int | None, error_type: str | None = None) -> None:
    LOGGER.info(
        "job_status job_id=%s job_type=%s db_key=%s status=%s elapsed_ms=%s error_type=%s",
        str(job.get("job_id") or ""),
        str(job.get("job_type") or ""),
        str(job.get("db_key") or ""),
        status,
        elapsed_ms if elapsed_ms is not None else "",
        error_type or "",
    )


def _sanitize_error_message(message: str) -> str:
    text = message or ""
    key_value_patterns = [
        r"(?i)(password\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(pass\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(token\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(secret\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(wallet[_\s-]*password\s*[:=]\s*)([^,\s;]+)",
    ]
    for pattern in key_value_patterns:
        text = re.sub(pattern, r"\1***REDACTED***", text)
    text = re.sub(r"(?i)([A-Za-z0-9_.-]+)/([^@\s/]+)@", r"\1/***REDACTED***@", text)
    text = re.sub(r"(?i)(//[^:/@\s]+:)([^@\s]+)@", r"\1***REDACTED***@", text)
    return text


def _sanitize_value(value: Any) -> Any:
    secret_keys = {"password", "pass", "token", "secret", "wallet_password"}
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).strip().lower()
            if lowered in secret_keys:
                clean[key] = "***REDACTED***"
            else:
                clean[key] = _sanitize_value(item)
        return clean
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, str):
        return _sanitize_error_message(value)
    return value


@contextmanager
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
