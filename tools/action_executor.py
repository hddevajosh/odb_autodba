from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from odb_autodba.db.connection import db_connection
from odb_autodba.db.remediation_sql import build_clear_blocking_lock_sql, build_extend_tablespace_sql
from odb_autodba.models.schemas import RemediationExecution, RemediationProposal


def execute_remediation_action(proposal: RemediationProposal) -> RemediationExecution:
    try:
        sql, notes = _resolve_action_sql(proposal)
    except Exception as exc:
        return RemediationExecution(
            status="failed",
            message=f"Unable to build safe SQL for action {proposal.action_type}: {exc}",
            executed_at=datetime.now(UTC).isoformat(),
        )

    if not sql:
        return RemediationExecution(
            status="failed",
            message="No executable SQL was generated for remediation proposal.",
            executed_at=datetime.now(UTC).isoformat(),
        )

    try:
        with db_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql)
            conn.commit()
        validation = _validation_summary(proposal, notes)
        return RemediationExecution(
            status="succeeded",
            message="Action executed successfully.",
            executed_at=datetime.now(UTC).isoformat(),
            validation_summary=validation,
        )
    except Exception as exc:
        return RemediationExecution(status="failed", message=str(exc), executed_at=datetime.now(UTC).isoformat())


def _resolve_action_sql(proposal: RemediationProposal) -> tuple[str, list[str]]:
    action_type = str(proposal.action_type or "").strip()
    target = proposal.target or {}
    if action_type in {"clear_blocking_lock", "kill_session"}:
        recommendation_mode = str(target.get("recommendation_mode") or "terminate").strip().lower()
        if recommendation_mode in {"monitor", "review_first"}:
            raise ValueError(f"Blocking action is in {recommendation_mode} mode and is not executable.")
        sid = _as_int(target.get("sid"))
        serial_num = _as_int(target.get("serial#"))
        inst_id = _as_int(target.get("inst_id"))
        sql = build_clear_blocking_lock_sql(sid=sid, serial_num=serial_num, inst_id=inst_id)
        return sql, []

    if action_type == "extend_tablespace":
        tablespace_name = str(target.get("tablespace_name") or "").strip()
        if not tablespace_name:
            raise ValueError("tablespace_name missing in remediation target.")
        initial_gb = _as_int(target.get("initial_gb")) or 1
        next_mb = _as_int(target.get("next_mb")) or 256
        max_gb = _as_int(target.get("max_gb")) or 32
        bigfile_hint = _as_bool(target.get("bigfile"))
        return build_extend_tablespace_sql(
            tablespace_name=tablespace_name,
            initial_gb=initial_gb,
            next_mb=next_mb,
            max_gb=max_gb,
            bigfile_hint=bigfile_hint,
        )

    sql = str(proposal.sql or "").strip()
    if not sql:
        raise ValueError(f"Unsupported action_type {action_type}.")
    return sql, []


def _validation_summary(proposal: RemediationProposal, notes: list[str]) -> str:
    action = str(proposal.action_type or "").strip()
    if action in {"clear_blocking_lock", "kill_session"}:
        base = "Re-run health check to validate blocker clearance and waiter recovery."
    elif action == "extend_tablespace":
        base = "Re-run health check to validate tablespace free space and growth policy."
    else:
        base = "Re-run health check to validate remediation impact."
    plan_checks = (proposal.post_action_validation.checks if proposal.post_action_validation else []) or []
    if plan_checks:
        base += " Plan: " + "; ".join(plan_checks[:4])
    if notes:
        return base + " Notes: " + "; ".join(notes[:3])
    return base


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None


def _as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if text in {"YES", "Y", "TRUE", "1"}:
        return True
    if text in {"NO", "N", "FALSE", "0"}:
        return False
    return None
