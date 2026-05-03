from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from fastapi import BackgroundTasks, FastAPI
from pydantic import BaseModel

from odb_autodba.mcp.jobs import create_job, get_job, list_jobs, maybe_cleanup_on_start, run_job
from odb_autodba.rag.trace_store import read_health_run_traces
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
from odb_autodba.target_registry import list_oracle_targets_safe

LOGGER = logging.getLogger("odb_autodba.mcp")


class HealthRequest(BaseModel):
    db_key: str | None = None
    target: dict[str, Any] | None = None


class HistoryRequest(BaseModel):
    db_key: str | None = None
    target: dict[str, Any] | None = None


class HistoryMetricRequest(BaseModel):
    db_key: str | None = None
    target: dict[str, Any] | None = None
    question: str


class SessionsRequest(BaseModel):
    db_key: str | None = None
    target: dict[str, Any] | None = None


class BlockingAnalyzeRequest(BaseModel):
    db_key: str | None = None
    target: dict[str, Any] | None = None


class InvestigateRequest(BaseModel):
    db_key: str | None = None
    target: dict[str, Any] | None = None
    question: str


class AwrAnalyzeRequest(BaseModel):
    db_key: str | None = None
    target: dict[str, Any] | None = None
    question: str | None = None


class SqlIdAnalyzeRequest(BaseModel):
    db_key: str | None = None
    target: dict[str, Any] | None = None
    sql_id: str


app = FastAPI(title="odb_autodba_mcp", version="skeleton")


@app.on_event("startup")
def _startup_cleanup_jobs() -> None:
    removed = maybe_cleanup_on_start()
    if removed:
        LOGGER.info("job_cleanup_on_start removed=%s", removed)


@app.get("/")
def root() -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/"
    try:
        payload = {"ok": True, "service": "odb_autodba_mcp", "version": "skeleton"}
        _log_request(endpoint=endpoint, db_key=None, start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=None, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.get("/databases")
def databases() -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/databases"
    try:
        rows = []
        safe_targets = list_oracle_targets_safe()
        for safe in safe_targets:
            rows.append(
                {
                    "db_key": safe.get("db_key"),
                    "display_name": safe.get("display_name") or safe.get("db_key"),
                    "environment": safe.get("environment"),
                    "host": safe.get("host"),
                    "port": safe.get("port"),
                    "service_name": safe.get("service_name"),
                    "sid": safe.get("sid"),
                    "pdb_name": safe.get("pdb_name"),
                    "username": safe.get("username"),
                    "tags": list(safe.get("tags") or []),
                    "source": safe.get("source"),
                    "password_env_present": bool(safe.get("password_env_present")),
                }
            )
        payload = {"ok": True, "databases": rows}
        first_db_key = rows[0].get("db_key") if rows else None
        _log_request(endpoint=endpoint, db_key=first_db_key, start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=None, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/health")
def health(req: HealthRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/health"
    db_key = req.db_key
    try:
        payload: dict[str, Any] = {}
        if isinstance(req.target, dict):
            payload["target"] = req.target
        job = create_job("health_check", db_key=db_key, payload=payload)
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


@app.post("/history")
def history(req: HistoryRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/history"
    db_key = req.db_key
    try:
        payload: dict[str, Any] = {}
        if isinstance(req.target, dict):
            payload["target"] = req.target
        job = create_job("historical_trends", db_key=db_key, payload=payload)
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


@app.post("/history/metric")
def history_metric(req: HistoryMetricRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/history/metric"
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
        job = create_job("history_metric_question", db_key=db_key, payload=payload)
        _schedule_job(background_tasks=background_tasks, job_id=job["job_id"])
        response_payload = {
            "ok": True,
            "job_id": job["job_id"],
            "status": job["status"],
            "db_key": job["db_key"],
            "job_type": job["job_type"],
        }
        _log_request(endpoint=endpoint, db_key=job.get("db_key"), start=start, ok=True)
        return response_payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/sessions")
def sessions(req: SessionsRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/sessions"
    db_key = req.db_key
    try:
        payload: dict[str, Any] = {}
        if isinstance(req.target, dict):
            payload["target"] = req.target
        job = create_job("active_sessions", db_key=db_key, payload=payload)
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


@app.post("/blocking/analyze")
def blocking_analyze(req: BlockingAnalyzeRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/blocking/analyze"
    db_key = req.db_key
    try:
        payload: dict[str, Any] = {}
        if isinstance(req.target, dict):
            payload["target"] = req.target
        job = create_job("blocking_analysis", db_key=db_key, payload=payload)
        _schedule_job(background_tasks=background_tasks, job_id=job["job_id"])
        response_payload = {
            "ok": True,
            "job_id": job["job_id"],
            "status": job["status"],
            "db_key": job["db_key"],
            "job_type": job["job_type"],
        }
        _log_request(endpoint=endpoint, db_key=job.get("db_key"), start=start, ok=True)
        return response_payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/investigate")
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


@app.post("/awr/analyze")
def awr_analyze(req: AwrAnalyzeRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/awr/analyze"
    db_key = req.db_key
    question = (req.question or "").strip()
    try:
        payload: dict[str, Any] = {}
        if question:
            payload["question"] = question
        if isinstance(req.target, dict):
            payload["target"] = req.target
        job = create_job("awr_analysis", db_key=db_key, payload=payload)
        _schedule_job(background_tasks=background_tasks, job_id=job["job_id"])
        response_payload = {
            "ok": True,
            "job_id": job["job_id"],
            "status": job["status"],
            "db_key": job["db_key"],
            "job_type": job["job_type"],
        }
        _log_request(endpoint=endpoint, db_key=job.get("db_key"), start=start, ok=True)
        return response_payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/sql-id/analyze")
def sql_id_analyze(req: SqlIdAnalyzeRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/sql-id/analyze"
    db_key = req.db_key
    sql_id = (req.sql_id or "").strip()
    try:
        if not sql_id:
            _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
            return {
                "ok": False,
                "error": "sql_id is required",
                "error_type": "ValidationError",
                "endpoint": endpoint,
            }
        payload: dict[str, Any] = {"sql_id": sql_id}
        if isinstance(req.target, dict):
            payload["target"] = req.target
        job = create_job("sql_id_analysis", db_key=db_key, payload=payload)
        _schedule_job(background_tasks=background_tasks, job_id=job["job_id"])
        response_payload = {
            "ok": True,
            "job_id": job["job_id"],
            "status": job["status"],
            "db_key": job["db_key"],
            "job_type": job["job_type"],
        }
        _log_request(endpoint=endpoint, db_key=job.get("db_key"), start=start, ok=True)
        return response_payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.get("/job/{job_id}")
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


@app.get("/jobs")
def jobs(
    limit: int = 20,
    status: str | None = None,
    db_key: str | None = None,
    job_type: str | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/jobs"
    try:
        payload = list_jobs(
            limit=limit,
            status=status,
            db_key=db_key,
            job_type=job_type,
            created_after=created_after,
            created_before=created_before,
        )
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=True)
        return {"ok": True, "jobs": payload}
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/health/sync")
def health_sync(req: HealthRequest) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/health/sync"
    try:
        payload = run_health_check(db_key=req.db_key)
        payload.setdefault("ok", True)
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/history/sync")
def history_sync(req: HistoryRequest) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/history/sync"
    try:
        payload = get_historical_trends(db_key=req.db_key)
        payload.setdefault("ok", True)
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/history/metric/sync")
def history_metric_sync(req: HistoryMetricRequest) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/history/metric/sync"
    try:
        question = (req.question or "").strip()
        if not question:
            _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
            return {
                "ok": False,
                "error": "question is required",
                "error_type": "ValidationError",
                "endpoint": endpoint,
            }
        payload = answer_history_metric_question(question, db_key=req.db_key)
        payload.setdefault("ok", True)
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/sessions/sync")
def sessions_sync(req: SessionsRequest) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/sessions/sync"
    try:
        payload = get_active_sessions(db_key=req.db_key)
        payload.setdefault("ok", True)
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/blocking/analyze/sync")
def blocking_analyze_sync(req: BlockingAnalyzeRequest) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/blocking/analyze/sync"
    try:
        payload = analyze_blocking_sessions(db_key=req.db_key)
        payload.setdefault("ok", True)
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/investigate/sync")
def investigate_sync(req: InvestigateRequest) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/investigate/sync"
    try:
        question = (req.question or "").strip()
        if not question:
            _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
            return {
                "ok": False,
                "error": "question is required",
                "error_type": "ValidationError",
                "endpoint": endpoint,
            }
        payload = run_ai_investigation(question, db_key=req.db_key)
        payload.setdefault("ok", True)
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/awr/analyze/sync")
def awr_analyze_sync(req: AwrAnalyzeRequest) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/awr/analyze/sync"
    try:
        payload = analyze_awr((req.question or "").strip() or None, db_key=req.db_key)
        payload.setdefault("ok", True)
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.post("/sql-id/analyze/sync")
def sql_id_analyze_sync(req: SqlIdAnalyzeRequest) -> dict[str, Any]:
    start = perf_counter()
    endpoint = "/sql-id/analyze/sync"
    try:
        sql_id = (req.sql_id or "").strip()
        if not sql_id:
            _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
            return {
                "ok": False,
                "error": "sql_id is required",
                "error_type": "ValidationError",
                "endpoint": endpoint,
            }
        payload = analyze_sql_id(sql_id, db_key=req.db_key)
        payload.setdefault("ok", True)
        _log_request(endpoint=endpoint, db_key=payload.get("db_key"), start=start, ok=True)
        return payload
    except Exception as exc:
        _log_request(endpoint=endpoint, db_key=req.db_key, start=start, ok=False)
        return _error_payload(endpoint=endpoint, exc=exc)


@app.get("/report/latest")
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


def _schedule_job(*, background_tasks: BackgroundTasks | None, job_id: str) -> None:
    if background_tasks is None:
        run_job(job_id)
        return
    background_tasks.add_task(run_job, job_id)


def _normalize_report_type(report_type: str | None) -> str:
    lowered = str(report_type or "health").strip().lower()
    if lowered in {"health", "health_check"}:
        return "health"
    if lowered in {"history", "historical", "historical_trends"}:
        return "history"
    if lowered in {"history_metric", "history_metric_question", "metric"}:
        return "history_metric"
    if lowered in {"sessions", "active_sessions"}:
        return "sessions"
    if lowered in {"blocking", "blocking_analysis"}:
        return "blocking"
    if lowered in {"sql", "sql_id", "sql_id_analysis"}:
        return "sql_id"
    if lowered in {"awr", "awr_analysis"}:
        return "awr"
    if lowered in {"investigation", "investigate"}:
        return "investigation"
    return "health"


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


def _write_latest_export_if_needed(*, rendered_report: str, db_key: str | None, prefix: str, current_path: Any) -> str:
    existing = str(current_path or "").strip()
    if existing and Path(existing).exists():
        return existing
    safe_prefix = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(prefix or "report")).strip("_") or "report"
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = get_exports_dir(db_key=db_key) / f"{safe_prefix}_{stamp}.md"
    path.write_text(rendered_report, encoding="utf-8")
    return str(path)


def _error_payload(*, endpoint: str, exc: Exception) -> dict[str, Any]:
    return {
        "ok": False,
        "error": _sanitize_error_message(str(exc)),
        "error_type": type(exc).__name__,
        "endpoint": endpoint,
    }


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


def _log_request(*, endpoint: str, db_key: str | None, start: float, ok: bool) -> None:
    elapsed_ms = round((perf_counter() - start) * 1000.0, 2)
    LOGGER.info(
        "mcp_request endpoint=%s db_key=%s elapsed_ms=%s status=%s",
        endpoint,
        db_key or "",
        elapsed_ms,
        "ok" if ok else "error",
    )


def create_app() -> FastAPI:
    return app


def main() -> None:
    import uvicorn

    host = os.getenv("ODB_AUTODBA_MCP_HOST", "127.0.0.1")
    port_raw = os.getenv("ODB_AUTODBA_MCP_PORT", "8000")
    try:
        port = int(port_raw)
    except ValueError:
        port = 8000

    logging.basicConfig(level=logging.INFO)
    uvicorn.run("odb_autodba.mcp.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
