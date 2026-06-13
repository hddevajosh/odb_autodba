from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

import gradio as gr

from odb_autodba.agents.investigation_agent import InvestigationAgent
from odb_autodba.agents.planner_agent import PlannerAgent
from odb_autodba.guardrails.models import ExecutionContext
from odb_autodba.guardrails.policy_engine import evaluate_action
from odb_autodba.models.schemas import (
    HealthSnapshot,
    PlannerResponse,
    RemediationExecution,
    RemediationProposal,
    RemediationRecord,
    RemediationReview,
)
from odb_autodba.services.autodba_service import (
    analyze_awr,
    analyze_blocking_sessions,
    analyze_sql_id,
    answer_history_metric_question,
    get_active_sessions,
    get_historical_trends,
    run_health_check,
)
from odb_autodba.tools.action_executor import execute_remediation_action
from odb_autodba.tools.action_history import append_action_record, load_action_records, render_action_history_markdown
from odb_autodba.tools.action_proposals import build_remediation_proposal
from odb_autodba.tools.action_reviewer import build_guardrail_review
from odb_autodba.utils.formatter import (
    render_investigation_final_report,
    render_planner_response,
    render_remediation_card_markdown,
)
from odb_autodba.utils.sql_analysis import (
    detect_awr_analysis_intent,
    detect_blocking_analysis_intent,
    detect_history_metric_question,
    detect_sql_id_analysis_intent,
    looks_like_active_sessions_request,
    looks_like_history_request,
)
from odb_autodba.mcp.client import (
    get_latest_report,
    list_jobs as list_mcp_jobs,
    get_mcp_poll_seconds,
    get_mcp_poll_timeout_seconds,
    mcp_fallback_local_enabled,
    poll_job,
    submit_awr_analysis_job,
    submit_blocking_analysis_job,
    submit_health_job,
    submit_history_metric_job,
    submit_history_job,
    submit_investigation_job,
    submit_sql_id_analysis_job,
    submit_sessions_job,
    use_mcp_enabled,
)
from odb_autodba.config import get_default_oracle_target
from odb_autodba.db.connection import ConnectionSettings, db_connection
from odb_autodba.target_registry import (
    build_transient_target,
    is_transient_target,
    list_oracle_targets_safe,
    register_transient_target,
    transient_target_mcp_payload,
    transient_target_requires_local_mode,
)

LOGGER = logging.getLogger(__name__)

WORKFLOW_PROMPTS = (
    ("Check Health", "Check health of my Oracle database"),
    ("Show Active Sessions", "show active sessions"),
    ("Historical Trends", "Show historical trends for this Oracle database"),
)

APP_CSS = """
#app-shell {
  max-width: 1440px;
  margin: 0 auto;
}
#action-rail {
  position: sticky;
  top: 16px;
  align-self: flex-start;
  padding-right: 20px;
}
#action-rail .rail-title {
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #5d6878;
  margin-bottom: 10px;
}
#action-rail .workflow-button {
  border-radius: 16px;
  min-height: 54px;
  font-weight: 700;
  font-size: 1rem;
}
#action-rail .workflow-button:hover {
  filter: none;
}
#center-panel {
  min-width: 0;
}
#recent-jobs-panel .gradio-button {
  min-height: 40px;
  border-radius: 12px;
}
#recent-jobs-panel .prose {
  max-height: 300px;
  overflow: auto;
}
@media (min-width: 1280px) {
  #action-rail {
    position: fixed;
    top: 88px;
    width: 210px;
  }
  #center-panel {
    margin-left: 252px;
  }
}
#remediation-card { border: 1px solid #d6dee8; border-radius: 20px; padding: 18px; background: linear-gradient(180deg, #f9fbfd 0%, #eef4f8 100%); }
#center-panel button[variant="stop"] {
  margin-top: 10px;
  min-height: 48px;
  border-radius: 14px;
  font-weight: 700;
}
"""


def _planner() -> PlannerAgent:
    return PlannerAgent()


def _investigator() -> InvestigationAgent:
    return InvestigationAgent()


def get_execution_mode() -> str:
    return "mcp" if use_mcp_enabled() else "local"


def _execution_mode_label() -> str:
    if get_execution_mode() == "mcp":
        return "Execution mode: MCP backend"
    return "Execution mode: Local direct"


def _process_user_message_with_response(message: str, db_key: str | None = None) -> PlannerResponse:
    return _planner().handle_message(message, db_key=db_key)


def _service_report_text(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    for key in ("rendered_report", "report_markdown", "body_markdown"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    fallback = str(payload.get("summary") or payload.get("error") or "").strip()
    return fallback or "No rendered report or summary was provided."


def _local_service_response(
    *,
    message: str,
    payload: dict[str, Any],
    chat_state: list[dict],
    selected_db_key: str | None,
    route: str | None,
    target_label: str | None,
):
    assistant_content = _service_report_text(payload)
    if route == "health" and target_label:
        assistant_content = _with_target_notice(assistant_content, target_label)
    if "active session" in (message or "").lower():
        assistant_content += "\n\nIf you want deep SQL analysis, use command: `Analyze SQL_ID <sql_id>` to analyze."
    chat_state = chat_state + [
        {"role": "user", "content": message},
        {"role": "assistant", "content": assistant_content},
    ]
    response_payload = _ensure_guardrail_review_payload(dict(payload))
    response_state = {"response": response_payload}
    review_data = (response_payload.get("supporting_data") or {}).get("review")
    proposal = _proposal_from_response_payload(response_payload)
    review = _review_from_response_payload(response_payload)
    LOGGER.info(
        "local_service_state db_key=%s route=%s action_id=%s action_type=%s guardrail_decision=%s guardrail_passed=%s guardrail_failed=%s",
        (selected_db_key or "").strip(),
        route or "unknown",
        _proposal_action_id(proposal),
        proposal.action_type if proposal else "",
        str(review.status).lower() if review else "unknown",
        len(review.guardrail_checks_passed) if review else 0,
        len(review.guardrail_checks_failed) if review else 0,
    )
    remediation_md = render_remediation_card_markdown(proposal, review_data)
    execute_interactive = _execute_enabled_for_payload(response_payload, confirmed=False)
    return (
        chat_state,
        chat_state,
        response_state,
        remediation_md,
        False,
        gr.update(interactive=execute_interactive),
        "",
        _action_history_markdown(selected_db_key),
    )


def _dynamic_target_defaults() -> dict[str, str]:
    target = get_default_oracle_target()
    return {
        "environment": target.environment or "default",
        "host": target.host or "localhost",
        "port": str(target.port or 1521),
        "service_name": target.service_name or "",
        "sid": target.sid or "",
        "pdb_name": target.pdb_name or "",
        "username": target.username or "system",
        "password_env": target.password_env or "",
        "connection_mode": "sysdba" if target.sysdba else "normal",
        "display_name": target.display_name or "",
    }


def _target_selector_context() -> dict[str, object]:
    try:
        targets = list_oracle_targets_safe()
        warning = ""
    except Exception as exc:
        fallback = get_default_oracle_target()
        targets = [fallback.safe_dict()]
        warning = f"Target registry unavailable; using default target. Details: {_safe_error_message(str(exc))}"

    choices: list[tuple[str, str]] = []
    labels_by_key: dict[str, str] = {}
    default_key: str | None = None
    for idx, target in enumerate(targets):
        key = str(target.get("db_key") or "").strip()
        if not key:
            continue
        display = str(target.get("display_name") or "").strip() or key
        friendly = f"{display} — {key}"
        choices.append((friendly, key))
        labels_by_key[key] = friendly
        if idx == 0:
            default_key = key

    if not choices:
        fallback = get_default_oracle_target()
        key = fallback.db_key
        friendly = f"{fallback.display_name or key} — {key}"
        choices = [(friendly, key)]
        labels_by_key[key] = friendly
        default_key = key

    return {
        "choices": choices,
        "default_key": default_key,
        "labels_by_key": labels_by_key,
        "warning": warning,
    }


def _target_label_for_key(selected_db_key: str | None, labels_by_key: dict[str, str]) -> str:
    key = (selected_db_key or "").strip()
    if key and key in labels_by_key:
        return labels_by_key[key]
    if labels_by_key:
        first_key = next(iter(labels_by_key.keys()))
        return labels_by_key[first_key]
    return key or "unknown target"


def _target_info_markdown(selected_db_key: str | None, labels_by_key: dict[str, str]) -> str:
    return f"Selected target: {_target_label_for_key(selected_db_key, labels_by_key)}"


def _upsert_target_choice(
    choices: list[tuple[str, str]],
    labels_by_key: dict[str, str],
    *,
    db_key: str,
    label: str,
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    next_choices: list[tuple[str, str]] = []
    replaced = False
    for friendly, key in choices:
        if key == db_key:
            next_choices.append((label, db_key))
            replaced = True
        else:
            next_choices.append((friendly, key))
    if not replaced:
        next_choices.append((label, db_key))
    next_labels = dict(labels_by_key)
    next_labels[db_key] = label
    return next_choices, next_labels


def _resolve_password_for_test(
    explicit_password: str | None,
    password_env: str | None,
) -> str | None:
    if (explicit_password or "").strip():
        return str(explicit_password)
    env_name = (password_env or "").strip()
    if env_name:
        env_value = os.getenv(env_name)
        if env_value:
            return env_value
        raise RuntimeError(f"Password environment variable '{env_name}' is not set.")
    for fallback_env in ("ORACLE_PASSWORD", "ORACLE_PASS", "DB_PASSWORD"):
        value = os.getenv(fallback_env)
        if value:
            return value
    return None


def _test_connection_for_target(target, *, password: str | None) -> tuple[str, str]:
    resolved_password = _resolve_password_for_test(password, target.password_env)
    if not resolved_password:
        raise RuntimeError("Password is required. Provide Password or password_env.")
    service = target.service_name or target.sid or "FREEPDB1"
    settings = ConnectionSettings(
        host=target.host,
        port=int(target.port),
        service_name=service,
        user=target.username,
        password=resolved_password,
        dsn=target.connect_descriptor,
        sysdba=target.sysdba,
    )
    with db_connection(settings) as conn:
        cur = conn.cursor()
        cur.execute("select name, open_mode from v$database")
        row = cur.fetchone()
    name = str(row[0]) if row and len(row) > 0 else "unknown"
    open_mode = str(row[1]) if row and len(row) > 1 else "unknown"
    return name, open_mode


def _with_target_notice(content: str, target_label: str) -> str:
    text = content or ""
    notice = f"Target database: {target_label}"
    if notice in text:
        return text
    return f"{notice}\n\n{text}".strip()


def _mcp_target_payload_or_limitation(selected_db_key: str | None) -> tuple[dict | None, str | None]:
    key = (selected_db_key or "").strip()
    if not key:
        return None, None
    if not is_transient_target(key):
        return None, None
    if transient_target_requires_local_mode(key):
        return None, (
            "MCP limitation: this ad-hoc target uses runtime UI password and can run only in local direct mode. "
            "For MCP mode, use password_env or register target in registry."
        )
    payload = transient_target_mcp_payload(key)
    if payload is None:
        return None, (
            "MCP limitation: unable to forward ad-hoc target metadata safely. "
            "Use local direct mode or configure a registry target."
        )
    return payload, None


def _test_and_use_target_ui(
    choices_state: list[tuple[str, str]],
    labels_by_key: dict[str, str],
    environment: str,
    host: str,
    port: str,
    service_name: str,
    sid: str,
    pdb_name: str,
    username: str,
    password: str,
    password_env: str,
    connection_mode: str,
    display_name: str,
):
    current_choices = list(choices_state or [])
    current_labels = dict(labels_by_key or {})
    try:
        target = build_transient_target(
            environment=environment,
            host=host,
            port=port,
            username=username,
            service_name=service_name,
            sid=sid,
            pdb_name=pdb_name,
            display_name=display_name,
            password_env=password_env,
            sysdba=(connection_mode or "").strip().lower() == "sysdba",
        )
        db_name, open_mode = _test_connection_for_target(target, password=password)
        runtime_password = (password or "").strip() or None
        saved_target = register_transient_target(target, password=runtime_password, replace=True)
        friendly = f"{saved_target.display_name or saved_target.db_key} — {saved_target.db_key}"
        next_choices, next_labels = _upsert_target_choice(
            current_choices,
            current_labels,
            db_key=saved_target.db_key,
            label=friendly,
        )
        selected_info = _target_info_markdown(saved_target.db_key, next_labels)
        if runtime_password:
            mode_note = "Stored in memory for this app session only; MCP mode will use local fallback."
        else:
            mode_note = "No runtime password stored; password_env/standard env lookup will be used."
        status = (
            f"Target ready: {friendly}. Connection test succeeded ({db_name}, {open_mode}). "
            f"{mode_note}"
        )
        return (
            gr.update(choices=next_choices, value=saved_target.db_key),
            next_labels,
            next_choices,
            selected_info,
            status,
        )
    except Exception as exc:
        message = f"Target test failed: {_safe_error_message(str(exc))}"
        selected_key = current_choices[0][1] if current_choices else None
        return (
            gr.update(choices=current_choices, value=selected_key),
            current_labels,
            current_choices,
            _target_info_markdown(selected_key, current_labels),
            message,
        )


def _submit_message(message: str, chat_state: list[dict], response_state: dict, selected_db_key: str | None = None):
    label = (selected_db_key or "").strip() or "default target"
    return _submit_message_with_target(message, chat_state, response_state, selected_db_key, label)


def _submit_message_local(
    message: str,
    chat_state: list[dict],
    response_state: dict,
    selected_db_key: str | None = None,
    *,
    target_label: str | None = None,
):
    LOGGER.info("execution_mode=local action=send db_key=%s", (selected_db_key or "").strip())
    if not message.strip():
        return chat_state, chat_state, response_state, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", _action_history_markdown(selected_db_key)
    sql_id = detect_sql_id_analysis_intent(message)
    route = _message_route_for_mcp(message)
    LOGGER.info("execution_mode=local action=%s db_key=%s", route or "send", (selected_db_key or "").strip())
    if sql_id:
        try:
            payload = analyze_sql_id(sql_id, db_key=selected_db_key)
            assistant_content = _service_report_text(payload)
        except Exception as exc:
            assistant_content = (
                f"# SQL_ID Analysis\n\n"
                f"SQL_ID analysis failed for `{sql_id}`.\n\n"
                f"Details: {_safe_error_message(str(exc))}"
            )
        chat_state = chat_state + [
            {"role": "user", "content": message},
            {"role": "assistant", "content": assistant_content},
        ]
        return (
            chat_state,
            chat_state,
            {},
            "No remediation proposed for the current analysis.",
            False,
            gr.update(interactive=False),
            "",
            _action_history_markdown(selected_db_key),
        )
    if route == "history_metric_question":
        payload = answer_history_metric_question(message, db_key=selected_db_key)
        return _local_service_response(
            message=message,
            payload=payload,
            chat_state=chat_state,
            selected_db_key=selected_db_key,
            route=route,
            target_label=target_label,
        )
    if route == "awr_analysis":
        payload = analyze_awr(message, db_key=selected_db_key)
        return _local_service_response(
            message=message,
            payload=payload,
            chat_state=chat_state,
            selected_db_key=selected_db_key,
            route=route,
            target_label=target_label,
        )
    if route == "blocking_analysis":
        payload = analyze_blocking_sessions(db_key=selected_db_key)
        return _local_service_response(
            message=message,
            payload=payload,
            chat_state=chat_state,
            selected_db_key=selected_db_key,
            route=route,
            target_label=target_label,
        )
    if route == "health":
        payload = run_health_check(db_key=selected_db_key)
        return _local_service_response(
            message=message,
            payload=payload,
            chat_state=chat_state,
            selected_db_key=selected_db_key,
            route=route,
            target_label=target_label,
        )
    if route == "sessions":
        payload = get_active_sessions(db_key=selected_db_key)
        return _local_service_response(
            message=message,
            payload=payload,
            chat_state=chat_state,
            selected_db_key=selected_db_key,
            route=route,
            target_label=target_label,
        )
    if route == "history":
        payload = get_historical_trends(db_key=selected_db_key)
        return _local_service_response(
            message=message,
            payload=payload,
            chat_state=chat_state,
            selected_db_key=selected_db_key,
            route=route,
            target_label=target_label,
        )
    response = _process_user_message_with_response(message, db_key=selected_db_key)
    assistant_content = render_planner_response(response)
    lowered_message = message.lower()
    if route == "health" and target_label:
        assistant_content = _with_target_notice(assistant_content, target_label)
    if "active session" in lowered_message:
        assistant_content += "\n\nIf you want deep SQL analysis, use command: `Analyze SQL_ID <sql_id>` to analyze."
    chat_state = chat_state + [
        {"role": "user", "content": message},
        {"role": "assistant", "content": assistant_content},
    ]
    payload = _ensure_guardrail_review_payload(response.model_dump(mode="json"))
    response_state = {"response": payload}
    review_data = (payload.get("supporting_data") or {}).get("review")
    review = _review_from_response_payload(payload)
    proposal_action_id = _proposal_action_id(response.remediation_proposal)
    LOGGER.info(
        "local_remediation_state db_key=%s action_id=%s action_type=%s guardrail_decision=%s guardrail_passed=%s guardrail_failed=%s",
        (selected_db_key or "").strip(),
        proposal_action_id,
        response.remediation_proposal.action_type if response.remediation_proposal else "",
        str(review.status).lower() if review else "unknown",
        len(review.guardrail_checks_passed) if review else 0,
        len(review.guardrail_checks_failed) if review else 0,
    )
    remediation_md = render_remediation_card_markdown(response.remediation_proposal, review_data)
    execute_interactive = _execute_enabled_for_payload(response_state.get("response") or {}, confirmed=False)
    return chat_state, chat_state, response_state, remediation_md, False, gr.update(interactive=execute_interactive), "", _action_history_markdown(selected_db_key)


def _submit_investigation(message: str, chat_state: list[dict], selected_db_key: str | None = None, target_label: str | None = None):
    if not message.strip():
        return chat_state, chat_state
    mode = get_execution_mode()
    if mode == "mcp":
        target_payload, mcp_limitation = _mcp_target_payload_or_limitation(selected_db_key)
        if mcp_limitation:
            if not mcp_fallback_local_enabled():
                chat_state = chat_state + [
                    {"role": "user", "content": f"Investigate: {message}"},
                    {"role": "assistant", "content": mcp_limitation},
                ]
                return chat_state, chat_state
            LOGGER.info("execution_mode=mcp action=investigate fallback_used=true fallback_target=local db_key=%s", (selected_db_key or "").strip())
            report = _investigator().investigate(message, db_key=selected_db_key)
            chat_state = chat_state + [
                {"role": "user", "content": f"Investigate: {message}"},
                {
                    "role": "assistant",
                    "content": (
                        f"{render_investigation_final_report(report)}\n\n"
                        "Execution mode: local fallback because MCP could not use the selected target.\n\n"
                        f"{mcp_limitation}"
                    ),
                },
            ]
            return chat_state, chat_state
        LOGGER.info("execution_mode=mcp action=investigate db_key=%s", (selected_db_key or "").strip())
        try:
            if target_payload is not None:
                submit = submit_investigation_job(message, db_key=selected_db_key, target=target_payload)
            else:
                submit = submit_investigation_job(message, db_key=selected_db_key)
            if not submit.get("ok"):
                raise RuntimeError(submit.get("error") or "investigation submit failed")
            job_id = str(submit.get("job_id") or "").strip()
            if not job_id:
                raise RuntimeError("missing job_id from MCP investigation submit")
            polled = poll_job(job_id, timeout_seconds=get_mcp_poll_timeout_seconds(), poll_seconds=get_mcp_poll_seconds())
            lines = [f"Queued MCP job: {job_id}", "Status: running"]
            status = str(polled.get("status") or "").lower()
            if status == "completed":
                lines.append("Status: completed")
                lines.append(f"MCP job {job_id} completed.")
                lines.append("")
                render_payload = dict(polled or {})
                render_payload.setdefault("job_id", job_id)
                render_payload.setdefault("status", status)
                lines.append(_render_mcp_result(render_payload, fallback_title="Oracle Investigation"))
            elif status == "failed":
                raise RuntimeError(polled.get("error") or "investigation job failed")
            else:
                raise RuntimeError(polled.get("error") or "investigation job polling timed out")
            chat_state = chat_state + [
                {"role": "user", "content": f"Investigate: {message}"},
                {"role": "assistant", "content": "\n".join(lines)},
            ]
            return chat_state, chat_state
        except Exception as exc:
            if not mcp_fallback_local_enabled():
                chat_state = chat_state + [
                    {"role": "user", "content": f"Investigate: {message}"},
                    {"role": "assistant", "content": f"MCP job failed/unavailable: {_safe_error_message(str(exc))}"},
                ]
                return chat_state, chat_state
            LOGGER.info("execution_mode=mcp action=investigate fallback_used=true fallback_target=local db_key=%s", (selected_db_key or "").strip())
            report = _investigator().investigate(message, db_key=selected_db_key)
            chat_state = chat_state + [
                {"role": "user", "content": f"Investigate: {message}"},
                {
                    "role": "assistant",
                    "content": (
                        f"{render_investigation_final_report(report)}\n\n"
                        "Execution mode: local fallback after MCP failure.\n\n"
                        "MCP job failed/unavailable; used local direct mode fallback."
                    ),
                },
            ]
            return chat_state, chat_state
    LOGGER.info("execution_mode=local action=investigate db_key=%s", (selected_db_key or "").strip())
    report = _investigator().investigate(message, db_key=selected_db_key)
    chat_state = chat_state + [
        {"role": "user", "content": f"Investigate: {message}"},
        {"role": "assistant", "content": render_investigation_final_report(report)},
    ]
    return chat_state, chat_state


def _submit_message_via_mcp(
    message: str,
    chat_state: list[dict],
    response_state: dict,
    *,
    route: str,
    db_key: str | None = None,
    target_label: str | None = None,
    target_payload: dict | None = None,
):
    LOGGER.info(
        "execution_mode=mcp action=%s job_type=%s fallback_used=false db_key=%s",
        route,
        route,
        (db_key or "").strip(),
    )
    if route == "health":
        if target_payload is not None:
            submit = submit_health_job(db_key=db_key, target=target_payload)
        else:
            submit = submit_health_job(db_key=db_key)
        fallback_title = "Oracle AutoDBA Report"
    elif route == "history_metric_question":
        if target_payload is not None:
            submit = submit_history_metric_job(message, db_key=db_key, target=target_payload)
        else:
            submit = submit_history_metric_job(message, db_key=db_key)
        fallback_title = "Oracle History Metric Analysis"
    elif route == "history":
        if target_payload is not None:
            submit = submit_history_job(db_key=db_key, target=target_payload)
        else:
            submit = submit_history_job(db_key=db_key)
        fallback_title = "Oracle Historical Trends"
    elif route == "sessions":
        if target_payload is not None:
            submit = submit_sessions_job(db_key=db_key, target=target_payload)
        else:
            submit = submit_sessions_job(db_key=db_key)
        fallback_title = "Oracle Active Sessions"
    elif route == "blocking_analysis":
        if target_payload is not None:
            submit = submit_blocking_analysis_job(db_key=db_key, target=target_payload)
        else:
            submit = submit_blocking_analysis_job(db_key=db_key)
        fallback_title = "Oracle Blocking Analysis"
    elif route == "awr_analysis":
        if target_payload is not None:
            submit = submit_awr_analysis_job(message, db_key=db_key, target=target_payload)
        else:
            submit = submit_awr_analysis_job(message, db_key=db_key)
        fallback_title = "Oracle AWR Analysis"
    elif route == "investigate":
        if target_payload is not None:
            submit = submit_investigation_job(message, db_key=db_key, target=target_payload)
        else:
            submit = submit_investigation_job(message, db_key=db_key)
        fallback_title = "Oracle Investigation"
    elif route == "sql_id_analysis":
        sql_id = detect_sql_id_analysis_intent(message)
        if not sql_id:
            raise RuntimeError("Unable to extract SQL_ID from message.")
        if target_payload is not None:
            submit = submit_sql_id_analysis_job(sql_id, db_key=db_key, target=target_payload)
        else:
            submit = submit_sql_id_analysis_job(sql_id, db_key=db_key)
        fallback_title = f"SQL_ID Deep Dive — {sql_id}"
    else:
        raise RuntimeError(f"Unsupported MCP route: {route}")
    if not submit.get("ok"):
        raise RuntimeError(submit.get("error") or f"{route} submit failed")
    job_id = str(submit.get("job_id") or "").strip()
    if not job_id:
        raise RuntimeError("missing job_id from MCP submit")

    polled = poll_job(job_id, timeout_seconds=get_mcp_poll_timeout_seconds(), poll_seconds=get_mcp_poll_seconds())
    lines = [f"Queued MCP job: {job_id}", "Status: running"]
    status = str(polled.get("status") or "").lower()
    if status == "completed":
        lines.append("Status: completed")
        lines.append(f"MCP job {job_id} completed.")
        lines.append("")
        render_payload = dict(polled or {})
        render_payload.setdefault("job_id", job_id)
        render_payload.setdefault("status", status)
        assistant_content = _render_mcp_result(render_payload, fallback_title=fallback_title)
        if route == "health" and target_label:
            assistant_content = _with_target_notice(assistant_content, target_label)
    elif status == "failed":
        raise RuntimeError(polled.get("error") or f"{route} job failed")
    else:
        raise RuntimeError(polled.get("error") or f"{route} job polling timed out")

    chat_state = chat_state + [
        {"role": "user", "content": message},
        {"role": "assistant", "content": "\n".join(lines) + "\n" + assistant_content},
    ]
    response_state = {}
    remediation_md = "No remediation proposed for the current analysis."
    execute_update = gr.update(interactive=False)
    if route == "health":
        hydrated_payload, no_proposal_reason = _hydrate_mcp_remediation_payload(
            route=route,
            polled=polled,
            db_key=db_key,
            job_id=job_id,
        )
        if hydrated_payload is not None:
            response_state = {"response": hydrated_payload}
            review = _review_from_response_payload(hydrated_payload)
            proposal = _proposal_from_response_payload(hydrated_payload)
            remediation_md = render_remediation_card_markdown(proposal, review.model_dump(mode="json") if review else None)
            execute_update = gr.update(interactive=_execute_enabled_for_payload(hydrated_payload, confirmed=False))
        elif no_proposal_reason:
            LOGGER.info(
                "mcp_remediation_hydration_no_proposal db_key=%s job_id=%s reason=%s",
                (db_key or "").strip(),
                job_id,
                no_proposal_reason,
            )
    return (
        chat_state,
        chat_state,
        response_state,
        remediation_md,
        False,
        execute_update,
        "",
        _action_history_markdown(db_key),
    )


def _message_route_for_mcp(message: str) -> str | None:
    lowered = (message or "").strip().lower()
    # Deterministic priority order:
    # 1) SQL_ID analysis
    # 2) generalized history metric question
    # 3) AWR analysis
    # 4) blocking live analysis
    # 5) active sessions
    # 6) full historical trends
    # 7) health check
    # 8) generic investigation
    if detect_sql_id_analysis_intent(lowered):
        return "sql_id_analysis"
    if detect_history_metric_question(lowered):
        return "history_metric_question"
    if detect_awr_analysis_intent(lowered):
        return "awr_analysis"
    if detect_blocking_analysis_intent(lowered):
        return "blocking_analysis"
    if looks_like_active_sessions_request(lowered):
        return "sessions"
    if looks_like_history_request(lowered):
        return "history"
    if any(token in lowered for token in ("check health", "health check", "database health", "check health of my oracle")):
        return "health"
    return "investigate"


def _latest_report_message(*, db_key: str | None, report_type: str = "health") -> str:
    mode = get_execution_mode()
    if mode == "mcp":
        LOGGER.info("execution_mode=mcp action=latest_report db_key=%s", (db_key or "").strip())
        payload = get_latest_report(report_type=report_type, db_key=db_key)
        if payload.get("ok"):
            rendered = str(payload.get("rendered_report") or "").strip()
            if rendered:
                return rendered
            return str(payload.get("summary") or "Latest report retrieved from MCP.")
        message = str(payload.get("message") or payload.get("error") or "").strip()
        if "not implemented yet" in message.lower():
            return "MCP limitation: latest report endpoint is not implemented yet."
        return f"MCP latest report failed: {_safe_error_message(message or 'unknown error')}"
    LOGGER.info("execution_mode=local action=latest_report db_key=%s", (db_key or "").strip())
    return "Local latest-report retrieval is not wired in this UI action."


def _render_mcp_result(job_payload: dict, *, fallback_title: str) -> str:
    result = job_payload.get("result") if isinstance(job_payload.get("result"), dict) else {}
    report_text = str(result.get("report_text") or "").strip()
    rendered_report = str(result.get("rendered_report") or "").strip()
    is_investigation = fallback_title.strip().lower() == "oracle investigation"
    status = str(job_payload.get("status") or "unknown").strip()
    completed = status.lower() == "completed"
    report_path = str(result.get("report_path") or "").strip()
    trace_path = str(result.get("trace_path") or "").strip()

    if is_investigation and completed:
        if report_text:
            return report_text
        if rendered_report:
            return rendered_report
        if report_path and Path(report_path).exists():
            try:
                from_file = Path(report_path).read_text(encoding="utf-8").strip()
            except Exception:
                from_file = ""
            if from_file:
                return from_file
        lines = [
            f"# {fallback_title}",
            "",
            "Investigation completed but inline report_text was missing.",
            f"Status: `{status}`",
            f"Trace path: `{trace_path or 'n/a'}`",
            f"Report path: `{report_path or 'n/a'}`",
        ]
        return "\n".join(lines)

    if rendered_report:
        return rendered_report

    summary_raw = result.get("summary") or job_payload.get("summary")
    summary = str(summary_raw).strip() if summary_raw is not None else ""
    if summary:
        lines = [f"# {fallback_title}", "", summary]
    else:
        if _debug_payloads_enabled():
            fallback_obj = result if result else job_payload
            compact_json = json.dumps(fallback_obj, ensure_ascii=True, indent=2, default=str)
            lines = [f"# {fallback_title}", "", "Debug payload:", "```json", compact_json, "```"]
        else:
            status = str(job_payload.get("status") or "unknown")
            error = _safe_error_message(str(job_payload.get("error") or result.get("error") or ""))
            lines = [
                f"# {fallback_title}",
                "",
                "No rendered report or summary was provided by the MCP job.",
                f"Status: `{status}`",
            ]
            if error:
                lines.append(f"Error: {error}")
    supporting = result.get("supporting_data")
    if isinstance(supporting, dict):
        history_sources = supporting.get("history_data_sources")
        if isinstance(history_sources, dict) and history_sources:
            lines.extend(
                [
                    "",
                    f"History source: {history_sources.get('history_source_used') or 'unknown'}",
                    f"Index status: {history_sources.get('history_index_status') or 'unknown'}",
                ]
            )
    return "\n".join(lines)


def _safe_error_message(text: str) -> str:
    raw = text or ""
    patterns = [
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
    for pattern in patterns:
        raw = re.sub(pattern, r"\1***REDACTED***", raw)
    raw = re.sub(r"(?i)([A-Za-z0-9_.-]+)/([^@\s/]+)@", r"\1/***REDACTED***@", raw)
    raw = re.sub(r"(?i)(//[^:/@\s]+:)([^@\s]+)@", r"\1***REDACTED***@", raw)
    raw = raw.replace("\n", " ").strip()
    return raw[:400]


def _debug_payloads_enabled() -> bool:
    raw = (os.getenv("ODB_AUTODBA_UI_DEBUG_PAYLOADS") or os.getenv("PLANNER_DEBUG_MODE") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _truncate_inline(text: str, limit: int = 80) -> str:
    compact = " ".join(str(text or "").split())
    if len(compact) <= max(limit, 8):
        return compact
    return compact[: max(limit - 3, 5)] + "..."


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


def _action_history_markdown(db_key: str | None = None) -> str:
    return render_action_history_markdown(load_action_records(db_key=db_key))


def _review_from_response_payload(payload: dict[str, Any]) -> RemediationReview | None:
    if not isinstance(payload, dict):
        return None
    supporting = payload.get("supporting_data") if isinstance(payload.get("supporting_data"), dict) else {}
    review_data = payload.get("remediation_review")
    if not isinstance(review_data, dict):
        review_data = supporting.get("review")
    if not isinstance(review_data, dict):
        return None
    try:
        return RemediationReview.model_validate(review_data)
    except Exception:
        return None


def _ensure_guardrail_review_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return payload
    next_payload = dict(payload)
    supporting = next_payload.get("supporting_data") if isinstance(next_payload.get("supporting_data"), dict) else {}
    next_supporting = dict(supporting)
    proposal = _proposal_from_response_payload(next_payload)
    review = _review_from_response_payload(next_payload)
    if proposal is not None and review is None:
        review = build_guardrail_review(proposal)
    if review is not None:
        next_supporting["review"] = review.model_dump(mode="json")
    next_payload["supporting_data"] = next_supporting
    return next_payload


def _proposal_requires_approval(proposal: RemediationProposal) -> bool:
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        mode = str(target.get("recommendation_mode") or "").strip().lower()
        return mode == "terminate"
    return False


def _proposal_from_response_payload(payload: dict[str, Any]) -> RemediationProposal | None:
    proposal_data = payload.get("remediation_proposal")
    if not isinstance(proposal_data, dict):
        return None
    try:
        return RemediationProposal.model_validate(proposal_data)
    except Exception:
        return None


def _execute_enabled_for_payload(payload: dict[str, Any], *, confirmed: bool) -> bool:
    proposal = _proposal_from_response_payload(payload)
    if proposal is None:
        return False
    review = _review_from_response_payload(payload)
    if review is None or str(review.status).lower() != "approved":
        return False
    requires_approval = _proposal_requires_approval(proposal)
    if requires_approval and not bool(confirmed):
        return False
    decision = evaluate_action(proposal, ExecutionContext(confirmed=(bool(confirmed) if requires_approval else True)))
    return bool(decision.allowed)


def _execute_button_update(confirmed: bool, response_state: dict) -> Any:
    payload = (response_state or {}).get("response") or {}
    interactive = _execute_enabled_for_payload(payload, confirmed=bool(confirmed))
    return gr.update(interactive=interactive)


def _proposal_action_id(proposal: RemediationProposal | None) -> str:
    if proposal is None:
        return ""
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        return f"{proposal.action_type}:{target.get('inst_id')}:{target.get('sid')}:{target.get('serial#')}"
    if proposal.action_type == "extend_tablespace":
        return f"{proposal.action_type}:{target.get('tablespace_name')}"
    return proposal.action_type


def _hydrate_mcp_remediation_payload(
    *,
    route: str,
    polled: dict[str, Any],
    db_key: str | None,
    job_id: str,
) -> tuple[dict[str, Any] | None, str | None]:
    result = polled.get("result") if isinstance(polled.get("result"), dict) else {}
    supporting = result.get("supporting_data") if isinstance(result.get("supporting_data"), dict) else {}
    summary = str(result.get("summary") or polled.get("summary") or "Oracle health check completed.").strip()
    rendered_report = str(result.get("rendered_report") or "").strip()
    issues_data = result.get("issues") if isinstance(result.get("issues"), list) else []
    proposal = None
    proposal_data = result.get("remediation_proposal")
    if not isinstance(proposal_data, dict):
        proposal_data = supporting.get("remediation_proposal")
    if isinstance(proposal_data, dict):
        try:
            proposal = RemediationProposal.model_validate(proposal_data)
        except Exception:
            proposal = None

    reason_no_proposal: str | None = None
    if proposal is None:
        if route == "health":
            snapshot_data = result.get("health_snapshot")
            if not isinstance(snapshot_data, dict):
                snapshot_data = supporting.get("health_snapshot")
            if isinstance(snapshot_data, dict):
                try:
                    snapshot = HealthSnapshot.model_validate(snapshot_data)
                    proposal = build_remediation_proposal(snapshot)
                except Exception as exc:
                    reason_no_proposal = f"Deterministic remediation proposal build failed: {_safe_error_message(str(exc))}"
            else:
                reason_no_proposal = "No deterministic action proposal generated because MCP result did not include structured health evidence."
        else:
            reason_no_proposal = "No deterministic action proposal generated for non-health MCP route."

    review = build_guardrail_review(proposal) if proposal is not None else None
    proposal_count = 1 if proposal is not None else 0
    selected_action_id = _proposal_action_id(proposal)
    structured_findings = len(issues_data)
    guardrail_decision = str(review.status).lower() if review is not None else "unknown"
    reason_not_executable = ""
    if proposal is not None and review is not None and guardrail_decision != "approved":
        reason_not_executable = review.rationale or f"guardrail_decision={guardrail_decision}"
    action_type = proposal.action_type if proposal is not None else ""

    LOGGER.info(
        "mcp_remediation_hydration db_key=%s job_id=%s findings=%s deterministic_proposals=%s selected_action_id=%s action_type=%s guardrail_decision=%s guardrail_passed=%s guardrail_failed=%s reason_no_proposal=%s reason_not_executable=%s",
        (db_key or "").strip(),
        job_id,
        structured_findings,
        proposal_count,
        selected_action_id,
        action_type,
        guardrail_decision,
        len(review.guardrail_checks_passed) if review else 0,
        len(review.guardrail_checks_failed) if review else 0,
        reason_no_proposal or "",
        reason_not_executable,
    )

    if proposal is None:
        return None, reason_no_proposal

    next_supporting = dict(supporting)
    if review is not None:
        next_supporting["review"] = review.model_dump(mode="json")
    next_supporting["mcp_job_id"] = job_id
    next_supporting["mcp_route"] = route
    if reason_not_executable:
        next_supporting["remediation_not_executable_reason"] = reason_not_executable

    payload = {
        "mode": "full_health_report",
        "summary": summary or "Oracle health check completed.",
        "body_markdown": rendered_report or "# Oracle AutoDBA Report",
        "issues": issues_data,
        "recommendations": [],
        "remediation_proposal": proposal.model_dump(mode="json"),
        "supporting_data": next_supporting,
    }
    return _ensure_guardrail_review_payload(payload), reason_no_proposal


def _execute_remediation(confirmed: bool, response_state: dict, selected_db_key: str | None = None):
    payload = (response_state or {}).get("response") or {}
    proposal_data = payload.get("remediation_proposal")
    if not proposal_data:
        return "No remediation proposal is available.", _action_history_markdown(selected_db_key)
    proposal = PlannerResponse.model_validate(payload).remediation_proposal
    review = _review_from_response_payload(payload) or build_guardrail_review(proposal)
    review_text = _format_guardrail_summary(review)
    if str(review.status).lower() != "approved":
        return f"Execution blocked by guardrails.\n{review_text}", _action_history_markdown(selected_db_key)
    requires_approval = _proposal_requires_approval(proposal)
    if requires_approval and not bool(confirmed):
        return (
            f"{review_text}\nExecution blocked: user approval is required for high-risk actions.",
            _action_history_markdown(selected_db_key),
        )
    decision = evaluate_action(proposal, ExecutionContext(confirmed=(bool(confirmed) if requires_approval else True)))
    if not decision.allowed:
        reasons = "; ".join(v.message for v in decision.violations)
        return f"{review_text}\nExecution blocked by guardrails: {reasons}", _action_history_markdown(selected_db_key)
    execution = execute_remediation_action(proposal)
    record = RemediationRecord(created_at=datetime.now(UTC).isoformat(), proposal=proposal, review=review, execution=execution)
    append_action_record(record, db_key=selected_db_key)
    return f"{review_text}\nExecution status: {execution.status}. {execution.message}", _action_history_markdown(selected_db_key)


def _format_guardrail_summary(review: RemediationReview) -> str:
    rationale = review.rationale or "No guardrail rationale provided."
    passed = ", ".join(review.guardrail_checks_passed[:4]) if review.guardrail_checks_passed else "none"
    failed = ", ".join(review.guardrail_checks_failed[:4]) if review.guardrail_checks_failed else "none"
    status = str(review.status).lower()
    icon = "🟢" if status == "approved" else ("🔴" if status == "rejected" else "⚪")
    return f"Guardrail decision: {icon} {status}. {rationale} Checks passed: {passed}. Checks failed: {failed}."


def _clear_chat(selected_db_key: str | None = None):
    return [], [], {}, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", _action_history_markdown(selected_db_key)


def _submit_message_ui(
    message: str,
    chat_state: list[dict],
    response_state: dict,
    selected_db_key: str | None,
    labels_by_key: dict[str, str],
):
    target_label = _target_label_for_key(selected_db_key, labels_by_key)
    return _submit_message_with_target(message, chat_state, response_state, selected_db_key, target_label)


def _submit_message_with_target(
    message: str,
    chat_state: list[dict],
    response_state: dict,
    selected_db_key: str | None,
    target_label: str,
):
    mode = get_execution_mode()
    if not message.strip():
        return chat_state, chat_state, response_state, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", _action_history_markdown(selected_db_key)
    if mode == "mcp":
        route = _message_route_for_mcp(message)
        target_payload, mcp_limitation = _mcp_target_payload_or_limitation(selected_db_key)
        if mcp_limitation:
            if mcp_fallback_local_enabled():
                LOGGER.info(
                    "execution_mode=mcp action=%s fallback_used=true fallback_target=local reason=target_limitation db_key=%s",
                    route or "investigate",
                    (selected_db_key or "").strip(),
                )
                result = _submit_message_local(
                    message,
                    chat_state,
                    response_state,
                    selected_db_key=selected_db_key,
                    target_label=target_label,
                )
                chatbot = list(result[0] or [])
                if chatbot and isinstance(chatbot[-1], dict):
                    chatbot[-1] = {
                        **chatbot[-1],
                        "content": (
                            f"{chatbot[-1].get('content')}\n\n"
                            "Execution mode: local fallback because MCP could not use the selected target.\n\n"
                            f"{mcp_limitation}"
                        ),
                    }
                return (
                    chatbot,
                    chatbot,
                    result[2],
                    result[3],
                    result[4],
                    result[5],
                    result[6],
                    result[7],
                )
            assistant_content = mcp_limitation
            chat_state = chat_state + [
                {"role": "user", "content": message},
                {"role": "assistant", "content": assistant_content},
            ]
            return chat_state, chat_state, response_state, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", _action_history_markdown(selected_db_key)
        try:
            return _submit_message_via_mcp(
                message,
                chat_state,
                response_state,
                route=route or "investigate",
                db_key=selected_db_key,
                target_label=target_label,
                target_payload=target_payload,
            )
        except Exception as exc:
            if mcp_fallback_local_enabled():
                LOGGER.info(
                    "execution_mode=mcp action=%s fallback_used=true fallback_target=local reason=job_failure db_key=%s",
                    route or "investigate",
                    (selected_db_key or "").strip(),
                )
                result = _submit_message_local(message, chat_state, response_state, selected_db_key=selected_db_key, target_label=target_label)
                chatbot = list(result[0] or [])
                if chatbot and isinstance(chatbot[-1], dict):
                    chatbot[-1] = {
                        **chatbot[-1],
                        "content": (
                            f"{chatbot[-1].get('content')}\n\n"
                            "Execution mode: local fallback after MCP failure.\n\n"
                            "MCP job failed/unavailable; used local direct mode fallback."
                        ),
                    }
                return (
                    chatbot,
                    chatbot,
                    result[2],
                    result[3],
                    result[4],
                    result[5],
                    result[6],
                    result[7],
                )
            assistant_content = f"MCP job failed/unavailable: {_safe_error_message(str(exc))}"
            chat_state = chat_state + [
                {"role": "user", "content": message},
                {"role": "assistant", "content": assistant_content},
            ]
            return chat_state, chat_state, response_state, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", _action_history_markdown(selected_db_key)
    return _submit_message_local(message, chat_state, response_state, selected_db_key=selected_db_key, target_label=target_label)


def _submit_investigation_ui(message: str, chat_state: list[dict], selected_db_key: str | None, labels_by_key: dict[str, str]):
    _ = _target_label_for_key(selected_db_key, labels_by_key)
    return _submit_investigation(message, chat_state, selected_db_key=selected_db_key)


def build_app() -> gr.Blocks:
    selector = _target_selector_context()
    target_choices = list(selector.get("choices") or [])
    default_target = selector.get("default_key")
    labels_by_key = dict(selector.get("labels_by_key") or {})
    selector_warning = str(selector.get("warning") or "")
    dynamic_defaults = _dynamic_target_defaults()
    with gr.Blocks(css=APP_CSS, title="Oracle AutoDBA", elem_id="app-shell") as app:
        chat_state = gr.State([])
        response_state = gr.State({})
        labels_state = gr.State(labels_by_key)
        choices_state = gr.State(target_choices)
        shortcut_clicks: list[tuple[gr.Button, str]] = []

        gr.Markdown(
            "# Oracle AutoDBA\n"
            "Ask for live Oracle checks or trace-driven historical answers. "
            "The UI keeps workflow shortcuts separated from database target controls and chat operations.",
            elem_classes=["app-title"],
        )

        with gr.Row():
            with gr.Column(scale=0, min_width=190, elem_id="action-rail"):
                gr.Markdown("Workflow Shortcuts", elem_classes=["rail-title"])
                for label, prompt in WORKFLOW_PROMPTS:
                    btn = gr.Button(label, size="lg", variant="primary", elem_classes=["workflow-button"])
                    shortcut_clicks.append((btn, prompt))
            with gr.Column(scale=1, min_width=720, elem_id="center-panel"):
                with gr.Accordion("Oracle Target", open=False):
                    with gr.Group(elem_id="target-panel"):
                        mode_info = gr.Markdown(_execution_mode_label())
                        target_db = gr.Dropdown(
                            label="Target Database",
                            choices=target_choices,
                            value=default_target,
                            allow_custom_value=False,
                            interactive=True,
                        )
                        target_info = gr.Markdown(_target_info_markdown(default_target, labels_by_key))
                        if selector_warning:
                            gr.Markdown(f"Note: {selector_warning}")
                    with gr.Row():
                        input_environment = gr.Textbox(label="Environment", value=dynamic_defaults.get("environment", "default"))
                        input_host = gr.Textbox(label="Host", value=dynamic_defaults.get("host", "localhost"))
                        input_port = gr.Textbox(label="Port", value=dynamic_defaults.get("port", "1521"))
                    with gr.Row():
                        input_service_name = gr.Textbox(label="Service Name", value=dynamic_defaults.get("service_name", ""))
                        input_sid = gr.Textbox(label="SID (optional)", value=dynamic_defaults.get("sid", ""))
                        input_pdb_name = gr.Textbox(label="PDB (optional)", value=dynamic_defaults.get("pdb_name", ""))
                    with gr.Row():
                        input_username = gr.Textbox(label="Username", value=dynamic_defaults.get("username", "system"))
                        input_password = gr.Textbox(label="Password", type="password", value="")
                        input_password_env = gr.Textbox(label="Password Env (optional)", value=dynamic_defaults.get("password_env", ""))
                    with gr.Row():
                        input_connection_mode = gr.Dropdown(
                            label="Connection Mode",
                            choices=[("normal", "normal"), ("sysdba", "sysdba")],
                            value=dynamic_defaults.get("connection_mode", "normal"),
                            allow_custom_value=False,
                            interactive=True,
                        )
                        input_display_name = gr.Textbox(label="Display Name (optional)", value=dynamic_defaults.get("display_name", ""))
                    use_target_btn = gr.Button("Test & Use Target", variant="secondary")
                    dynamic_target_status = gr.Markdown("Enter target details, then click **Test & Use Target**.")
                    with gr.Accordion("Recent Jobs", open=False, elem_id="recent-jobs-panel"):
                        refresh_jobs_btn = gr.Button("Refresh Jobs", variant="secondary")
                        recent_jobs_md = gr.Markdown(_recent_jobs_markdown(default_target, limit=10))
                chatbot = gr.Chatbot(type="messages", label="Planner Chat", height=620, show_copy_button=True)
                message = gr.Textbox(
                    label="Ask Oracle AutoDBA",
                    placeholder="Ask a question about current health, history, blocking, SQL, AWR, or trends...",
                    lines=3,
                )
                with gr.Row():
                    send_btn = gr.Button("Send", variant="primary")
                    investigate_btn = gr.Button("Investigate with AI", variant="primary")
                    clear_btn = gr.Button("Clear")
                gr.Examples(
                    examples=[prompt for _, prompt in WORKFLOW_PROMPTS],
                    inputs=message,
                )
                with gr.Group(elem_id="remediation-card"):
                    remediation_md = gr.Markdown("No remediation proposed for the current analysis.")
                    confirm_checkbox = gr.Checkbox(label="I have reviewed the target session and want to allow this action.", value=False)
                    execute_btn = gr.Button("Execute Action", interactive=False)
                    validation_md = gr.Markdown("")
                with gr.Accordion("Action History", open=False):
                    action_history_md = gr.Markdown(_action_history_markdown(default_target))

        for btn, prompt in shortcut_clicks:
            btn.click(
                fn=lambda cs, rs, dbk, labels, p=prompt: _submit_message_ui(p, cs, rs, dbk, labels),
                inputs=[chat_state, response_state, target_db, labels_state],
                outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md],
            )
        use_target_btn.click(
            _test_and_use_target_ui,
            inputs=[
                choices_state,
                labels_state,
                input_environment,
                input_host,
                input_port,
                input_service_name,
                input_sid,
                input_pdb_name,
                input_username,
                input_password,
                input_password_env,
                input_connection_mode,
                input_display_name,
            ],
            outputs=[target_db, labels_state, choices_state, target_info, dynamic_target_status],
        )
        target_db.change(_target_info_markdown, inputs=[target_db, labels_state], outputs=[target_info])
        send_btn.click(
            _submit_message_ui,
            inputs=[message, chat_state, response_state, target_db, labels_state],
            outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md],
        )
        investigate_btn.click(_submit_investigation_ui, inputs=[message, chat_state, target_db, labels_state], outputs=[chatbot, chat_state])
        clear_btn.click(_clear_chat, inputs=[target_db], outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md])
        execute_btn.click(_execute_remediation, inputs=[confirm_checkbox, response_state, target_db], outputs=[validation_md, action_history_md])
        confirm_checkbox.change(_execute_button_update, inputs=[confirm_checkbox, response_state], outputs=[execute_btn])
        target_db.change(_action_history_markdown, inputs=[target_db], outputs=[action_history_md])
        refresh_jobs_btn.click(_recent_jobs_markdown, inputs=[target_db], outputs=[recent_jobs_md])
        target_db.change(_recent_jobs_markdown, inputs=[target_db], outputs=[recent_jobs_md])
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = build_app()
    app.launch()


if __name__ == "__main__":
    main()
