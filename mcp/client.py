from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from odb_autodba.utils.env_loader import load_project_dotenv


def use_mcp_enabled() -> bool:
    load_project_dotenv()
    return _env_bool("ODB_AUTODBA_USE_MCP", alias="PGAUTODBA_USE_MCP", default=False)


def get_mcp_base_url() -> str:
    load_project_dotenv()
    raw = (
        os.getenv("ODB_AUTODBA_MCP_BASE_URL")
        or os.getenv("PGAUTODBA_MCP_BASE_URL")
        or "http://127.0.0.1:8000"
    ).strip()
    return raw.rstrip("/")


def mcp_fallback_local_enabled() -> bool:
    load_project_dotenv()
    return _env_bool("ODB_AUTODBA_MCP_FALLBACK_LOCAL", alias="PGAUTODBA_MCP_FALLBACK_LOCAL", default=True)


def get_mcp_poll_seconds() -> float:
    load_project_dotenv()
    raw = (os.getenv("ODB_AUTODBA_MCP_POLL_SECONDS") or "1").strip()
    try:
        value = float(raw)
    except ValueError:
        value = 1.0
    return max(0.1, value)


def get_mcp_poll_timeout_seconds() -> float:
    load_project_dotenv()
    raw = (os.getenv("ODB_AUTODBA_MCP_POLL_TIMEOUT_SECONDS") or "300").strip()
    try:
        value = float(raw)
    except ValueError:
        value = 300.0
    return max(1.0, value)


def submit_health_job(db_key: str | None = None, target: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"db_key": db_key}
    if target is not None:
        payload["target"] = target
    return _post_json("/health", payload)


def submit_history_job(db_key: str | None = None, target: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"db_key": db_key}
    if target is not None:
        payload["target"] = target
    return _post_json("/history", payload)


def submit_history_metric_job(
    question: str,
    db_key: str | None = None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"db_key": db_key, "question": question}
    if target is not None:
        payload["target"] = target
    return _post_json("/history/metric", payload)


def submit_sessions_job(db_key: str | None = None, target: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"db_key": db_key}
    if target is not None:
        payload["target"] = target
    return _post_json("/sessions", payload)


def submit_blocking_analysis_job(db_key: str | None = None, target: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"db_key": db_key}
    if target is not None:
        payload["target"] = target
    return _post_json("/blocking/analyze", payload)


def submit_investigation_job(
    question: str,
    db_key: str | None = None,
    target: dict[str, Any] | None = None,
    thread_id: str | None = None,
    continue_context: bool | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    normalized = str(question or "").strip()
    payload: dict[str, Any] = {
        "db_key": db_key,
        "problem_statement": normalized,
        "question": normalized,  # backward-compatible alias
    }
    if target is not None:
        payload["target"] = target
    if (thread_id or "").strip():
        payload["thread_id"] = str(thread_id).strip()
    if continue_context is not None:
        payload["continue_context"] = bool(continue_context)
    if (user_id or "").strip():
        payload["user_id"] = str(user_id).strip()
    if (session_id or "").strip():
        payload["session_id"] = str(session_id).strip()
    return _post_json("/investigate", payload)


def submit_awr_analysis_job(
    question: str | None = None,
    db_key: str | None = None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"db_key": db_key}
    if (question or "").strip():
        payload["question"] = str(question).strip()
    if target is not None:
        payload["target"] = target
    return _post_json("/awr/analyze", payload)


def submit_sql_id_analysis_job(
    sql_id: str,
    db_key: str | None = None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"db_key": db_key, "sql_id": sql_id}
    if target is not None:
        payload["target"] = target
    return _post_json("/sql-id/analyze", payload)


def submit_sql_id_job(
    sql_id: str,
    db_key: str | None = None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return submit_sql_id_analysis_job(sql_id=sql_id, db_key=db_key, target=target)


def get_latest_report(report_type: str = "health", db_key: str | None = None) -> dict[str, Any]:
    params = {"report_type": report_type}
    if (db_key or "").strip():
        params["db_key"] = str(db_key).strip()
    qs = urllib.parse.urlencode(params)
    return _get_json(f"/report/latest?{qs}")


def get_job(job_id: str) -> dict[str, Any]:
    return _get_json(f"/job/{job_id}")


def list_jobs(
    *,
    limit: int = 20,
    status: str | None = None,
    db_key: str | None = None,
    job_type: str | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
) -> dict[str, Any]:
    params: dict[str, str] = {"limit": str(max(int(limit or 1), 1))}
    if (status or "").strip():
        params["status"] = str(status).strip()
    if (db_key or "").strip():
        params["db_key"] = str(db_key).strip()
    if (job_type or "").strip():
        params["job_type"] = str(job_type).strip()
    if (created_after or "").strip():
        params["created_after"] = str(created_after).strip()
    if (created_before or "").strip():
        params["created_before"] = str(created_before).strip()
    return _get_json(f"/jobs?{urllib.parse.urlencode(params)}")


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


def _post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"{get_mcp_base_url()}{path}"
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    return _read_json_response(req)


def _get_json(path: str) -> dict[str, Any]:
    url = f"{get_mcp_base_url()}{path}"
    req = urllib.request.Request(url, method="GET")
    return _read_json_response(req)


def _read_json_response(req: urllib.request.Request) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            payload = json.loads(text) if text else {}
            if isinstance(payload, dict):
                return payload
            return {"ok": False, "error": "invalid response payload", "error_type": "ValueError"}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
            payload = json.loads(body) if body else {}
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass
        return {
            "ok": False,
            "error": _sanitize_error_message(body or str(exc)),
            "error_type": "HTTPError",
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": _sanitize_error_message(str(exc)),
            "error_type": type(exc).__name__,
        }


def _env_bool(primary: str, *, alias: str, default: bool) -> bool:
    raw = os.getenv(primary)
    if raw is None:
        raw = os.getenv(alias)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _sanitize_error_message(message: str) -> str:
    text = message or ""
    key_value_patterns = [
        r"(?i)(password\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(pass\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(passphrase\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(token\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(secret\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(credential\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(api[_-]?key\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(private[_-]?key\s*[:=]\s*)([^,\s;]+)",
        r"(?i)(wallet[_\s-]*password\s*[:=]\s*)([^,\s;]+)",
    ]
    for pattern in key_value_patterns:
        text = re.sub(pattern, r"\1***REDACTED***", text)
    text = re.sub(r"(?i)([A-Za-z0-9_.-]+)/([^@\s/]+)@", r"\1/***REDACTED***@", text)
    text = re.sub(r"(?i)(//[^:/@\s]+:)([^@\s]+)@", r"\1***REDACTED***@", text)
    return text
