from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from time import perf_counter
from typing import Any

from odb_autodba.guardrails import policy_engine
from odb_autodba.guardrails.models import ActionDecision, ExecutionContext
from odb_autodba.models.schemas import BlockingActionReview, RemediationProposal, RemediationReview, ReviewConfidence
from odb_autodba.utils.env_loader import load_project_dotenv

LOGGER = logging.getLogger(__name__)

OPENAI_REVIEWER_NAME = "ChatGPT Action Reviewer"
DETERMINISTIC_REVIEWER_NAME = "Deterministic Guardrail Reviewer"


def build_guardrail_review(
    proposal: RemediationProposal | None,
    *,
    guardrail_decision: ActionDecision | None = None,
) -> RemediationReview:
    if proposal is None:
        return RemediationReview(
            status="not_needed",
            confidence="LOW",
            rationale="No action proposal generated.",
            notes=["source=existing_guardrails_policy_engine"],
        )
    decision = guardrail_decision or policy_engine.evaluate_action(proposal, ExecutionContext(confirmed=True))
    passed, failed = _guardrail_lists(decision)
    passed_details, failed_details = _guardrail_detail_rows(decision)
    detail_notes = _guardrail_detail_notes(passed_details, failed_details)
    if decision.allowed:
        rationale = f"Guardrail policy approved action_type={proposal.action_type}."
        status: str = "approved"
    else:
        status = "rejected"
        failed_reasons = "; ".join(f"{row['check']}: {row['message']}" for row in failed_details[:3])
        rationale = f"Guardrail policy rejected action_type={proposal.action_type}."
        if failed_reasons:
            rationale = f"{rationale} Failed checks: {failed_reasons}."
    review = RemediationReview(
        status=status,  # type: ignore[arg-type]
        confidence=_review_confidence(proposal=proposal, preview=decision, approved=decision.allowed),
        rationale=rationale,
        reviewer_notes=[],
        guardrail_checks_passed=passed,
        guardrail_checks_failed=failed,
        notes=[
            "source=existing_guardrails_policy_engine",
            *detail_notes,
        ][:64],
    )
    review.blocking_review = _blocking_review_payload(review)
    return review


def review_remediation_proposal(
    proposal: RemediationProposal | None,
    *,
    guardrail_decision: ActionDecision | None = None,
) -> RemediationReview:
    load_project_dotenv()
    if proposal is None:
        return RemediationReview(
            status="not_needed",
            confidence="LOW",
            rationale="No action proposal generated.",
            reviewer_notes=["Reviewer provider=disabled"],
            notes=["Reviewer skipped because no remediation proposal was available."],
        )

    preview = guardrail_decision or policy_engine.evaluate_action(proposal, ExecutionContext(confirmed=True))
    passed, failed = _guardrail_lists(preview)
    passed_details, failed_details = _guardrail_detail_rows(preview)
    guardrail_detail_notes = _guardrail_detail_notes(passed_details, failed_details)
    selection = _select_reviewer_config()
    selection_notes = _selection_notes(selection)

    if not preview.allowed:
        source = "existing_guardrails_policy_engine"
        failed_reasons = "; ".join(f"{row['check']}: {row['message']}" for row in failed_details[:3])
        rationale = f"Guardrail policy rejected action_type={proposal.action_type} using source={source}."
        if failed_reasons:
            rationale = f"{rationale} Failed checks: {failed_reasons}."
        review = RemediationReview(
            status="rejected",
            confidence="LOW",
            rationale=rationale,
            reviewer_notes=[
                "Reviewer provider=deterministic",
                *selection_notes,
                *_reviewer_trace_notes(
                    primary_provider=DETERMINISTIC_REVIEWER_NAME,
                    primary_model="deterministic",
                    primary_status="rejected",
                    fallback_used=True,
                    fallback_reason="guardrail_precheck_rejected",
                    fallback_provider=DETERMINISTIC_REVIEWER_NAME,
                    fallback_status="rejected",
                    effective_provider=DETERMINISTIC_REVIEWER_NAME,
                    effective_status="rejected",
                ),
                *guardrail_detail_notes,
                "review_source=existing_guardrails_policy_engine",
            ],
            guardrail_checks_passed=passed,
            guardrail_checks_failed=failed,
            notes=[
                "Deterministic guardrail evaluation rejected proposal before AI review.",
                "source=existing_guardrails_policy_engine",
                *guardrail_detail_notes,
            ],
        )
        _log_selection(
            selection,
            action_type=proposal.action_type,
            decision="rejected",
            fallback_used=True,
            fallback_reason="guardrail_precheck_rejected",
            openai_elapsed_ms=0,
        )
        review.blocking_review = _blocking_review_payload(review)
        return review

    kind = str(selection.get("selected_reviewer_kind") or "")
    if kind != "openai":
        fallback_reason = str(selection.get("fallback_reason") or "provider_forced_deterministic")
        if kind == "unavailable":
            review = _unavailable_rejection(
                proposal=proposal,
                preview=preview,
                selection_notes=selection_notes,
                fallback_reason=fallback_reason,
            )
            _log_selection(
                selection,
                action_type=proposal.action_type,
                decision="rejected",
                fallback_used=False,
                fallback_reason=fallback_reason,
                openai_elapsed_ms=0,
            )
            review.blocking_review = _blocking_review_payload(review)
            return review

        review = _deterministic_approval(
            proposal=proposal,
            preview=preview,
            provider_note=_deterministic_provider_note(fallback_reason),
            source="existing_guardrails_policy_engine",
            provider_label="deterministic_fallback" if fallback_reason != "provider_forced_deterministic" else "deterministic",
            extra_reviewer_notes=[
                *selection_notes,
                *_reviewer_trace_notes(
                    primary_provider=DETERMINISTIC_REVIEWER_NAME,
                    primary_model="deterministic",
                    primary_status="approved",
                    fallback_used=True,
                    fallback_reason=fallback_reason,
                    fallback_provider=DETERMINISTIC_REVIEWER_NAME,
                    fallback_status="approved",
                    effective_provider=DETERMINISTIC_REVIEWER_NAME,
                    effective_status="approved",
                ),
                *guardrail_detail_notes,
                "review_source=existing_guardrails_policy_engine",
            ],
        )
        _log_selection(
            selection,
            action_type=proposal.action_type,
            decision="approved",
            fallback_used=True,
            fallback_reason=fallback_reason,
            openai_elapsed_ms=0,
        )
        review.blocking_review = _blocking_review_payload(review)
        return review

    reviewed, review_error, openai_elapsed_ms = _review_with_openai(
        proposal=proposal,
        preview=preview,
        model=str(selection.get("model") or "gpt-5.5"),
        timeout_s=float(selection.get("timeout_sec") or 30.0),
    )
    if reviewed is not None:
        reviewed.reviewer_notes = [
            *[str(note).strip() for note in reviewed.reviewer_notes if str(note).strip()],
            *selection_notes,
            *_reviewer_trace_notes(
                primary_provider=OPENAI_REVIEWER_NAME,
                primary_model=str(selection.get("model") or "gpt-5.5"),
                primary_status=str(reviewed.status).lower(),
                fallback_used=False,
                fallback_reason="",
                fallback_provider="",
                fallback_status="",
                effective_provider=OPENAI_REVIEWER_NAME,
                effective_status=str(reviewed.status).lower(),
                openai_elapsed_ms=openai_elapsed_ms,
                openai_timeout_sec=float(selection.get("timeout_sec") or 30.0),
            ),
            *guardrail_detail_notes,
            "review_source=existing_guardrails_policy_engine+reviewer",
        ][:64]
        reviewed.notes = [*list(reviewed.notes or []), "source=existing_guardrails_policy_engine+reviewer", *guardrail_detail_notes][:64]
        _log_selection(
            selection,
            action_type=proposal.action_type,
            decision="approved" if reviewed.status == "approved" else "rejected",
            fallback_used=False,
            fallback_reason="",
            openai_elapsed_ms=openai_elapsed_ms,
        )
        reviewed.blocking_review = _blocking_review_payload(reviewed)
        return reviewed

    fallback_reason = str(review_error or "openai_error")
    if not bool(selection.get("allow_deterministic_fallback")):
        review = _unavailable_rejection(
            proposal=proposal,
            preview=preview,
            selection_notes=[
                *selection_notes,
                *_reviewer_trace_notes(
                    primary_provider=OPENAI_REVIEWER_NAME,
                    primary_model=str(selection.get("model") or "gpt-5.5"),
                    primary_status="error" if fallback_reason != "openai_timeout" else "timeout",
                    fallback_used=False,
                    fallback_reason=fallback_reason,
                    fallback_provider="",
                    fallback_status="",
                    effective_provider=OPENAI_REVIEWER_NAME,
                    effective_status="review_unavailable",
                    openai_elapsed_ms=openai_elapsed_ms,
                    openai_timeout_sec=float(selection.get("timeout_sec") or 30.0),
                ),
                *guardrail_detail_notes,
                "review_source=existing_guardrails_policy_engine+reviewer_unavailable",
            ],
            fallback_reason=fallback_reason,
        )
        _log_selection(
            selection,
            action_type=proposal.action_type,
            decision="rejected",
            fallback_used=False,
            fallback_reason=fallback_reason,
            openai_elapsed_ms=openai_elapsed_ms,
        )
        review.blocking_review = _blocking_review_payload(review)
        return review

    review = _deterministic_approval(
        proposal=proposal,
        preview=preview,
        provider_note="ChatGPT reviewer unavailable; deterministic guardrail fallback approved proposal.",
        source="existing_guardrails_policy_engine+reviewer_fallback",
        provider_label="deterministic_fallback",
        extra_reviewer_notes=[
            *selection_notes,
            *_reviewer_trace_notes(
                primary_provider=OPENAI_REVIEWER_NAME,
                primary_model=str(selection.get("model") or "gpt-5.5"),
                primary_status="error" if fallback_reason != "openai_timeout" else "timeout",
                fallback_used=True,
                fallback_reason=fallback_reason,
                fallback_provider=DETERMINISTIC_REVIEWER_NAME,
                fallback_status="approved",
                effective_provider=DETERMINISTIC_REVIEWER_NAME,
                effective_status="approved",
                openai_elapsed_ms=openai_elapsed_ms,
                openai_timeout_sec=float(selection.get("timeout_sec") or 30.0),
            ),
            *guardrail_detail_notes,
            "review_source=existing_guardrails_policy_engine+reviewer_fallback",
        ],
    )
    _log_selection(
        selection,
        action_type=proposal.action_type,
        decision="approved",
        fallback_used=True,
        fallback_reason=fallback_reason,
        openai_elapsed_ms=openai_elapsed_ms,
    )
    review.blocking_review = _blocking_review_payload(review)
    return review


def _deterministic_approval(
    *,
    proposal: RemediationProposal,
    preview: ActionDecision,
    provider_note: str,
    source: str,
    provider_label: str,
    extra_reviewer_notes: list[str] | None = None,
) -> RemediationReview:
    passed, failed = _guardrail_lists(preview)
    confidence = _review_confidence(proposal=proposal, preview=preview, approved=True)
    rationale = _build_detailed_rationale(proposal, preview, approved=True, source=source)
    notes = [f"Reviewer provider={provider_label}", provider_note]
    if extra_reviewer_notes:
        notes.extend(str(item).strip() for item in extra_reviewer_notes if str(item).strip())
    return RemediationReview(
        status="approved",
        confidence=confidence,
        rationale=rationale,
        reviewer_notes=notes[:64],
        guardrail_checks_passed=passed,
        guardrail_checks_failed=failed,
        notes=[provider_note, f"source={source}"],
    )


def _unavailable_rejection(
    *,
    proposal: RemediationProposal,
    preview: ActionDecision,
    selection_notes: list[str],
    fallback_reason: str,
) -> RemediationReview:
    passed, failed = _guardrail_lists(preview)
    reason = _openai_unavailable_reason(fallback_reason)
    return RemediationReview(
        status="rejected",
        confidence="LOW",
        rationale=(
            f"Reviewer rejected action_type={proposal.action_type}: {reason} "
            "Execution remains disabled because deterministic fallback is disabled."
        ),
        reviewer_notes=[
            "Reviewer provider=openai",
            *selection_notes,
            f"fallback_reason={fallback_reason}",
        ][:64],
        guardrail_checks_passed=passed,
        guardrail_checks_failed=failed + [fallback_reason],
        notes=[reason],
    )


def _review_with_openai(
    *,
    proposal: RemediationProposal,
    preview: ActionDecision,
    model: str,
    timeout_s: float,
) -> tuple[RemediationReview | None, str | None, int]:
    api_key = str(os.getenv("OPENAI_API_KEY") or "").strip()
    if not api_key:
        return None, "openai_api_key_missing", 0

    payload = _openai_reviewer_payload(proposal, preview)
    prompt = json.dumps(payload, ensure_ascii=True)
    started = perf_counter()
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(_openai_generate_text, api_key, model, _reviewer_system_prompt(), prompt)
        raw_text = future.result(timeout=max(timeout_s, 1.0))
    except TimeoutError:
        pool.shutdown(wait=False, cancel_futures=True)
        return None, "openai_timeout", int((perf_counter() - started) * 1000)
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        return None, "openai_error", int((perf_counter() - started) * 1000)
    pool.shutdown(wait=False, cancel_futures=True)
    elapsed_ms = int((perf_counter() - started) * 1000)

    parsed = _parse_reviewer_json(raw_text)
    if parsed is None:
        return None, "openai_invalid_json", elapsed_ms
    approved = bool(parsed.get("approved"))
    decision = str(parsed.get("decision") or "").strip().lower()
    if decision not in {"approved", "rejected"}:
        decision = "approved" if approved else "rejected"
    if decision == "rejected":
        approved = False
    risk_level = str(parsed.get("risk_level") or "").strip().lower()
    if risk_level not in {"low", "medium", "high"}:
        risk_level = "medium" if approved else "high"
    reason = str(parsed.get("reason") or "").strip() or "No reviewer reason provided."
    failed_conditions = parsed.get("failed_conditions")
    if not isinstance(failed_conditions, list):
        failed_conditions = []
    required_user_ack = bool(parsed.get("required_user_ack"))
    confidence = _normalize_confidence(parsed.get("confidence"), fallback=("MEDIUM" if approved else "LOW"))

    passed, failed = _guardrail_lists(preview)
    reviewer_notes = [
        f"Reviewer provider={model}",
        f"Reviewer decision={decision}",
        f"Reviewer risk_level={risk_level}",
        f"Reviewer required_user_ack={str(required_user_ack).lower()}",
    ]
    if failed_conditions:
        reviewer_notes.append(f"Reviewer failed_conditions={'; '.join(str(item) for item in failed_conditions)}")
    return (
        RemediationReview(
            status="approved" if approved else "rejected",
            confidence=confidence,
            rationale=reason,
            reviewer_notes=reviewer_notes[:12],
            guardrail_checks_passed=passed,
            guardrail_checks_failed=failed,
            notes=[f"risk_level={risk_level}", f"required_user_ack={str(required_user_ack).lower()}"],
        ),
        None,
        elapsed_ms,
    )


def _openai_reviewer_payload(proposal: RemediationProposal, preview: ActionDecision) -> dict[str, Any]:
    target = proposal.target or {}
    passed, failed = _guardrail_lists(preview)
    safety_level = _proposal_safety_level(proposal)
    payload: dict[str, Any] = {
        "action_id": _proposal_action_id(proposal),
        "action_type": proposal.action_type,
        "target": target,
        "proposed_sql": str(proposal.execution_sql or proposal.sql or "").strip(),
        "severity": _proposal_severity(proposal),
        "safety_level": safety_level,
        "approval_required": safety_level == "high_risk",
        "deterministic_guardrail_results": {
            "allowed": preview.allowed,
            "passed_checks": passed,
            "failed_checks": failed,
            "violations": [f"{v.rule}: {v.message}" for v in preview.violations],
            "rationale": preview.rationale,
        },
        "evidence_fields": _evidence_fields(proposal),
        "risk_summary": list(proposal.risks or []),
        "protected_users_session_facts": _protected_session_facts(target),
        "dba_approval_criteria": _dba_approval_criteria(),
    }
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        blocked_details = target.get("blocked_session_details")
        blocked_sample = blocked_details[0] if isinstance(blocked_details, list) and blocked_details else {}
        payload.update(
            {
                "blocker_sid": target.get("sid"),
                "blocker_serial": target.get("serial#"),
                "blocker_inst_id": target.get("inst_id"),
                "blocker_user": target.get("username"),
                "blocker_program": target.get("program"),
                "blocker_module": target.get("module"),
                "blocker_status": target.get("status"),
                "blocker_classification": target.get("blocker_classification"),
                "idle_in_transaction": bool(target.get("blocker_idle_in_transaction")),
                "blocked_sessions": target.get("blocked_session_count"),
                "max_wait_seconds": target.get("max_blocked_wait_seconds"),
                "wait_event": blocked_sample.get("event") or target.get("wait_event"),
                "wait_class": blocked_sample.get("wait_class") or target.get("wait_class"),
                "object_owner": target.get("object_owner"),
                "object_name": target.get("object_name"),
                "evidence_complete": bool(target.get("evidence_complete")),
                "guardrails_passed": len(passed),
                "guardrails_failed": len(failed),
            }
        )
    elif proposal.action_type == "extend_tablespace":
        used_pct = _as_float(target.get("used_pct"))
        payload.update(
            {
                "tablespace_name": target.get("tablespace_name"),
                "pct_used": used_pct,
                "pct_free": _pct_free(target, used_pct),
                "tablespace_type": "temp" if str(target.get("contents") or "").upper() == "TEMPORARY" else "permanent",
                "autoextend_status": target.get("autoextensible"),
                "allocated_gb": _mb_to_gb(target.get("total_mb") or target.get("allocated_mb")),
                "max_gb": _mb_to_gb(target.get("max_mb")) or target.get("max_gb"),
                "free_allocated_gb": _mb_to_gb(target.get("free_mb") or target.get("free_allocated_mb")),
                "proposed_size_change": {
                    "initial_gb": target.get("initial_gb"),
                    "next_mb": target.get("next_mb"),
                    "max_gb": target.get("max_gb"),
                },
                "guardrails_passed": len(passed),
                "guardrails_failed": len(failed),
            }
        )
    return payload


def _evidence_fields(proposal: RemediationProposal) -> dict[str, Any]:
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        return {
            "blocked_session_count": target.get("blocked_session_count"),
            "max_blocked_wait_seconds": target.get("max_blocked_wait_seconds"),
            "blocker_classification": target.get("blocker_classification"),
            "blocker_idle_in_transaction": target.get("blocker_idle_in_transaction"),
            "evidence_complete": target.get("evidence_complete"),
            "object_owner": target.get("object_owner"),
            "object_name": target.get("object_name"),
        }
    if proposal.action_type == "extend_tablespace":
        return {
            "tablespace_name": target.get("tablespace_name"),
            "used_pct": target.get("used_pct"),
            "total_mb": target.get("total_mb"),
            "free_mb": target.get("free_mb"),
            "bigfile": target.get("bigfile"),
            "generation_notes": target.get("generation_notes"),
        }
    return {"target": target}


def _protected_session_facts(target: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": target.get("username"),
        "program": target.get("program"),
        "module": target.get("module"),
        "status": target.get("status"),
        "blocker_classification": target.get("blocker_classification"),
        "recommendation_mode": target.get("recommendation_mode"),
    }


def _dba_approval_criteria() -> list[str]:
    return [
        "Approve only when deterministic guardrails pass.",
        "Reject if evidence is incomplete or target appears protected/internal.",
        "Reject if action risk cannot be clearly justified from supplied evidence.",
        "Reject if blocker ownership or workload impact is unclear.",
    ]


def _reviewer_system_prompt() -> str:
    return (
        "You are an Oracle DBA action reviewer. Approve or reject only based on provided deterministic evidence and "
        "guardrails. Do not invent evidence. If guardrails failed, evidence is incomplete, target is protected, blocker "
        "is not clearly safe to terminate, or action risk is unclear, reject. Return strict JSON only.\n\n"
        "Return exactly this JSON schema:\n"
        "{\n"
        '  "approved": true/false,\n'
        '  "decision": "approved" | "rejected",\n'
        '  "reason": "...",\n'
        '  "risk_level": "low" | "medium" | "high",\n'
        '  "required_user_ack": true/false,\n'
        '  "failed_conditions": [],\n'
        '  "confidence": "low" | "medium" | "high"\n'
        "}"
    )


def _select_reviewer_config() -> dict[str, Any]:
    provider_raw = str(
        os.getenv("ODB_AUTODBA_ACTION_REVIEWER_PROVIDER")
        or os.getenv("ODB_AUTODBA_REVIEWER_PROVIDER")
        or "auto"
    ).strip().lower()
    if provider_raw not in {"auto", "openai", "deterministic", "gemini"}:
        provider_raw = "auto"
    openai_api_key_present = bool((os.getenv("OPENAI_API_KEY") or "").strip())
    model = _resolve_openai_model()
    timeout_sec = _openai_timeout_seconds()
    allow_fallback = _allow_deterministic_fallback_on_openai_error()

    if provider_raw in {"deterministic", "gemini"}:
        return {
            "reviewer_selection_requested": True,
            "provider_requested": provider_raw,
            "selected_reviewer_kind": "deterministic",
            "selected_reviewer_name": DETERMINISTIC_REVIEWER_NAME,
            "openai_api_key_present": openai_api_key_present,
            "model": model,
            "timeout_sec": timeout_sec,
            "allow_deterministic_fallback": allow_fallback,
            "fallback_reason": "provider_forced_deterministic" if provider_raw == "deterministic" else "gemini_disabled_by_config",
        }
    if not openai_api_key_present:
        if allow_fallback:
            return {
                "reviewer_selection_requested": True,
                "provider_requested": provider_raw,
                "selected_reviewer_kind": "deterministic",
                "selected_reviewer_name": DETERMINISTIC_REVIEWER_NAME,
                "openai_api_key_present": False,
                "model": model,
                "timeout_sec": timeout_sec,
                "allow_deterministic_fallback": True,
                "fallback_reason": "openai_api_key_missing",
            }
        return {
            "reviewer_selection_requested": True,
            "provider_requested": provider_raw,
            "selected_reviewer_kind": "unavailable",
            "selected_reviewer_name": OPENAI_REVIEWER_NAME,
            "openai_api_key_present": False,
            "model": model,
            "timeout_sec": timeout_sec,
            "allow_deterministic_fallback": False,
            "fallback_reason": "openai_api_key_missing",
        }
    return {
        "reviewer_selection_requested": True,
        "provider_requested": provider_raw,
        "selected_reviewer_kind": "openai",
        "selected_reviewer_name": OPENAI_REVIEWER_NAME,
        "openai_api_key_present": True,
        "model": model,
        "timeout_sec": timeout_sec,
        "allow_deterministic_fallback": allow_fallback,
        "fallback_reason": "",
    }


def _selection_notes(selection: dict[str, Any]) -> list[str]:
    return [
        f"reviewer_selection_requested={str(bool(selection.get('reviewer_selection_requested'))).lower()}",
        f"openai_api_key_present={str(bool(selection.get('openai_api_key_present'))).lower()}",
        f"selected_reviewer={selection.get('selected_reviewer_name')}",
        f"openai_model={selection.get('model')}",
        f"openai_timeout_sec={selection.get('timeout_sec')}",
    ]


def _reviewer_trace_notes(
    *,
    primary_provider: str,
    primary_model: str,
    primary_status: str,
    fallback_used: bool,
    fallback_reason: str,
    fallback_provider: str,
    fallback_status: str,
    effective_provider: str,
    effective_status: str,
    openai_elapsed_ms: int | None = None,
    openai_timeout_sec: float | None = None,
) -> list[str]:
    lines = [
        f"primary_reviewer_provider={primary_provider}",
        f"primary_reviewer_model={primary_model}",
        f"primary_reviewer_status={primary_status}",
        f"fallback_used={str(bool(fallback_used)).lower()}",
        f"fallback_reason={fallback_reason}",
        f"fallback_reviewer_provider={fallback_provider}",
        f"fallback_reviewer_status={fallback_status}",
        f"effective_reviewer_provider={effective_provider}",
        f"effective_reviewer_status={effective_status}",
    ]
    if openai_elapsed_ms is not None:
        lines.append(f"openai_elapsed_ms={openai_elapsed_ms}")
    if openai_timeout_sec is not None:
        lines.append(f"openai_timeout_sec={openai_timeout_sec}")
    return lines


def _log_selection(
    selection: dict[str, Any],
    *,
    action_type: str,
    decision: str,
    fallback_used: bool,
    fallback_reason: str,
    openai_elapsed_ms: int | None,
) -> None:
    LOGGER.info(
        "reviewer_selection_requested=%s action_type=%s selected_reviewer=%s openai_api_key_present=%s openai_model=%s "
        "openai_timeout_sec=%s openai_elapsed_ms=%s fallback_used=%s fallback_reason=%s decision=%s",
        str(bool(selection.get("reviewer_selection_requested"))).lower(),
        action_type,
        str(selection.get("selected_reviewer_name") or OPENAI_REVIEWER_NAME),
        str(bool(selection.get("openai_api_key_present"))).lower(),
        str(selection.get("model") or "gpt-5.5"),
        str(selection.get("timeout_sec") or 30.0),
        "" if openai_elapsed_ms is None else str(openai_elapsed_ms),
        str(bool(fallback_used)).lower(),
        str(fallback_reason or ""),
        decision,
    )


def _deterministic_provider_note(fallback_reason: str) -> str:
    if fallback_reason == "openai_api_key_missing":
        return "ChatGPT reviewer unavailable because OPENAI_API_KEY is missing; deterministic guardrail fallback approved proposal."
    if fallback_reason == "provider_forced_deterministic":
        return "Reviewer provider is deterministic by configuration."
    if fallback_reason == "gemini_disabled_by_config":
        return "Gemini reviewer selection is disabled; deterministic guardrail reviewer applied."
    return "ChatGPT reviewer unavailable; deterministic guardrail fallback approved proposal."


def _openai_unavailable_reason(fallback_reason: str) -> str:
    if fallback_reason == "openai_api_key_missing":
        return "ChatGPT reviewer unavailable because OPENAI_API_KEY is missing."
    if fallback_reason == "openai_timeout":
        return "ChatGPT reviewer timed out before returning a decision."
    if fallback_reason == "openai_invalid_json":
        return "ChatGPT reviewer returned malformed JSON."
    return "ChatGPT reviewer is unavailable."


def _build_detailed_rationale(
    proposal: RemediationProposal,
    preview: ActionDecision,
    *,
    approved: bool,
    source: str,
) -> str:
    status_text = "approved" if approved else "rejected"
    passed, failed = _guardrail_lists(preview)
    return (
        f"Reviewer {status_text} action_type={proposal.action_type} using source={source}. "
        f"Guardrail checks passed={len(passed)}, failed={len(failed)}."
    )


def _review_confidence(*, proposal: RemediationProposal, preview: ActionDecision, approved: bool) -> ReviewConfidence:
    if not approved:
        return "LOW"
    if proposal.action_type not in {"clear_blocking_lock", "kill_session"}:
        return "MEDIUM"
    target = proposal.target or {}
    classification = str(target.get("blocker_classification") or "unknown")
    blocked_count = _as_int(target.get("blocked_session_count")) or 0
    max_wait = _as_int(target.get("max_blocked_wait_seconds")) or 0
    evidence_complete = bool(target.get("evidence_complete"))
    if evidence_complete and classification in {"application_session", "idle_in_transaction_blocker"} and (blocked_count >= 2 or max_wait >= 300):
        return "HIGH"
    if evidence_complete and classification not in {"unknown"} and not preview.violations:
        return "MEDIUM"
    return "LOW"


def _blocking_review_payload(review: RemediationReview) -> BlockingActionReview:
    return BlockingActionReview(
        status=review.status,
        confidence=review.confidence,
        rationale=review.rationale,
        guardrail_checks_passed=list(review.guardrail_checks_passed),
        guardrail_checks_failed=list(review.guardrail_checks_failed),
        notes=list(review.notes or review.reviewer_notes),
    )


def _guardrail_lists(preview: ActionDecision) -> tuple[list[str], list[str]]:
    if preview.checks:
        passed = [check.check for check in preview.checks if check.passed]
        failed = [check.check for check in preview.checks if not check.passed]
    else:
        passed = []
        failed = [violation.rule for violation in preview.violations]
    return passed, failed


def _guardrail_detail_rows(preview: ActionDecision) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    passed_rows: list[dict[str, str]] = []
    failed_rows: list[dict[str, str]] = []
    if preview.checks:
        for check in preview.checks:
            row = {"check": str(check.check), "message": str(check.message)}
            if check.passed:
                passed_rows.append(row)
            else:
                failed_rows.append(row)
        return passed_rows, failed_rows
    for violation in preview.violations:
        failed_rows.append({"check": str(violation.rule), "message": str(violation.message)})
    return passed_rows, failed_rows


def _guardrail_detail_notes(passed_rows: list[dict[str, str]], failed_rows: list[dict[str, str]]) -> list[str]:
    notes: list[str] = []
    for row in passed_rows:
        notes.append(f"guardrail_passed={row['check']}|{row['message']}")
    for row in failed_rows:
        notes.append(f"guardrail_failed={row['check']}|{row['message']}")
    return notes[:64]


def _openai_generate_text(api_key: str, model: str, system_prompt: str, user_prompt: str) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.0,
    )
    return str(resp.choices[0].message.content or "").strip()


def _parse_reviewer_json(text: str) -> dict[str, Any] | None:
    source = (text or "").strip()
    if not source:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", source, flags=re.S | re.I)
    if fenced:
        source = fenced.group(1).strip()
    else:
        bracket = re.search(r"(\{.*\})", source, flags=re.S)
        if bracket:
            source = bracket.group(1).strip()
    try:
        out = json.loads(source)
        return out if isinstance(out, dict) else None
    except Exception:
        return None


def _normalize_confidence(value: Any, *, fallback: str = "LOW") -> ReviewConfidence:
    text = str(value or fallback).strip().upper()
    if text in {"LOW", "MEDIUM", "HIGH"}:
        return text  # type: ignore[return-value]
    return "LOW" if fallback.upper() not in {"LOW", "MEDIUM", "HIGH"} else fallback.upper()  # type: ignore[return-value]


def _resolve_openai_model() -> str:
    configured = str(
        os.getenv("ODB_AUTODBA_OPENAI_REVIEW_MODEL")
        or os.getenv("REVIEWER_MODEL")
        or os.getenv("OPENAI_MODEL")
        or "gpt-5.5"
    ).strip()
    if "gemini" in configured.lower():
        return "gpt-5.5"
    return configured or "gpt-5.5"


def _allow_deterministic_fallback_on_openai_error() -> bool:
    raw = os.getenv("ODB_AUTODBA_ALLOW_DETERMINISTIC_FALLBACK_ON_OPENAI_ERROR")
    if raw is None:
        return True
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _openai_timeout_seconds() -> float:
    raw = os.getenv("ODB_AUTODBA_OPENAI_REVIEW_TIMEOUT_SEC")
    if raw is None:
        return 30.0
    try:
        return max(float(raw), 1.0)
    except Exception:
        return 30.0


def _proposal_action_id(proposal: RemediationProposal) -> str:
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        return f"{proposal.action_type}:{target.get('inst_id')}:{target.get('sid')}:{target.get('serial#')}"
    if proposal.action_type == "extend_tablespace":
        return f"{proposal.action_type}:{target.get('tablespace_name')}"
    return proposal.action_type


def _proposal_safety_level(proposal: RemediationProposal) -> str:
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        mode = str(target.get("recommendation_mode") or "").strip().lower()
        return "high_risk" if mode == "terminate" else "medium_risk"
    return "low_risk"


def _proposal_severity(proposal: RemediationProposal) -> str:
    target = proposal.target or {}
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        blocked = _as_int(target.get("blocked_session_count")) or 0
        wait_s = _as_int(target.get("max_blocked_wait_seconds")) or 0
        if blocked >= 2 or wait_s >= 300:
            return "CRITICAL"
        return "WARNING"
    if proposal.action_type == "extend_tablespace":
        pct = _as_float(target.get("used_pct")) or 0.0
        return "CRITICAL" if pct >= 90.0 else "WARNING"
    return "INFO"


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _mb_to_gb(value: Any) -> float | None:
    mb = _as_float(value)
    if mb is None:
        return None
    return round(mb / 1024.0, 4)


def _pct_free(target: dict[str, Any], used_pct: float | None) -> float | None:
    explicit = _as_float(target.get("pct_free"))
    if explicit is not None:
        return explicit
    if used_pct is not None:
        return round(max(0.0, 100.0 - used_pct), 4)
    return None
