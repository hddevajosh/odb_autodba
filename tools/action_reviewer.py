from __future__ import annotations

import json
import os
import re
import warnings
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Any

from odb_autodba.guardrails.models import ActionDecision, ExecutionContext
from odb_autodba.guardrails.policy_engine import evaluate_action
from odb_autodba.models.schemas import BlockingActionReview, RemediationProposal, RemediationReview, ReviewConfidence


warnings.filterwarnings("ignore", category=FutureWarning, module=r"google\\.generativeai")
os.environ.setdefault("GRPC_ENABLE_FORK_SUPPORT", "0")


def review_remediation_proposal(
    proposal: RemediationProposal | None,
    *,
    guardrail_decision: ActionDecision | None = None,
) -> RemediationReview:
    if proposal is None:
        return RemediationReview(
            status="not_needed",
            confidence="LOW",
            rationale="No action proposal generated.",
            notes=["Reviewer skipped because no remediation proposal was available."],
        )

    preview = guardrail_decision or evaluate_action(proposal, ExecutionContext(confirmed=True))
    passed, failed = _guardrail_lists(preview)

    if not preview.allowed:
        rationale = _build_detailed_rationale(proposal, preview, approved=False, source="deterministic")
        review = RemediationReview(
            status="rejected",
            confidence="LOW",
            rationale=rationale,
            reviewer_notes=failed or ["Unknown guardrail violation."],
            guardrail_checks_passed=passed,
            guardrail_checks_failed=failed,
            notes=["Deterministic reviewer rejected proposal because one or more guardrails failed."],
        )
        review.blocking_review = _blocking_review_payload(review)
        return review

    provider = str(os.getenv("ODB_AUTODBA_REVIEWER_PROVIDER", "deterministic") or "deterministic").strip().lower()
    if provider != "gemini":
        review = _deterministic_approval(
            proposal=proposal,
            preview=preview,
            provider_note="Reviewer provider is deterministic (Gemini disabled by configuration).",
            source="deterministic",
        )
        review.blocking_review = _blocking_review_payload(review)
        return review

    if not _env_bool("ODB_AUTODBA_REVIEWER_GEMINI_ENABLED", False):
        review = _deterministic_approval(
            proposal=proposal,
            preview=preview,
            provider_note="Gemini reviewer is configured but disabled; deterministic guardrail fallback approved proposal.",
            source="deterministic_fallback",
        )
        review.blocking_review = _blocking_review_payload(review)
        return review

    reviewed = _review_with_gemini(proposal=proposal, preview=preview)
    if reviewed is not None:
        reviewed.blocking_review = _blocking_review_payload(reviewed)
        return reviewed

    strict = _env_bool("ODB_AUTODBA_REVIEWER_STRICT", False)
    if strict:
        review = RemediationReview(
            status="rejected",
            confidence="LOW",
            rationale=_build_detailed_rationale(proposal, preview, approved=False, source="gemini_unavailable_strict"),
            reviewer_notes=["Gemini reviewer unavailable while strict mode is enabled."],
            guardrail_checks_passed=passed,
            guardrail_checks_failed=failed + ["gemini_unavailable"],
            notes=["Set GOOGLE_API_KEY and Google SDK dependencies to enable Gemini reviewer."],
        )
        review.blocking_review = _blocking_review_payload(review)
        return review

    review = _deterministic_approval(
        proposal=proposal,
        preview=preview,
        provider_note="Gemini reviewer unavailable; deterministic guardrail fallback approved proposal.",
        source="gemini_unavailable_fallback",
    )
    review.blocking_review = _blocking_review_payload(review)
    return review


def _deterministic_approval(
    *,
    proposal: RemediationProposal,
    preview: ActionDecision,
    provider_note: str,
    source: str,
) -> RemediationReview:
    passed, failed = _guardrail_lists(preview)
    confidence = _review_confidence(proposal=proposal, preview=preview, approved=True)
    rationale = _build_detailed_rationale(proposal, preview, approved=True, source=source)
    return RemediationReview(
        status="approved",
        confidence=confidence,
        rationale=rationale,
        reviewer_notes=[provider_note],
        guardrail_checks_passed=passed,
        guardrail_checks_failed=failed,
        notes=[provider_note],
    )


def _review_with_gemini(*, proposal: RemediationProposal, preview: ActionDecision) -> RemediationReview | None:
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return None
    model = os.getenv("REVIEWER_MODEL", "gemini-2.5-flash")
    system = (
        "You are a strict Oracle DBA remediation safety reviewer. "
        "Only approve actions that are safe, targeted, and justified by evidence. "
        "Return JSON only with keys: approved(boolean), confidence(LOW|MEDIUM|HIGH), "
        "reason(string), reviewer_notes(array of short strings), notes(array of short strings)."
    )
    user = json.dumps(
        {
            "proposal": proposal.model_dump(mode="json"),
            "guardrail_preview": preview.model_dump(mode="json"),
            "instructions": [
                "If guardrail_preview.allowed is false, approved must be false.",
                "Be conservative. Reject if target metadata is weak or risky.",
                "Mention blocked session count, max wait, blocker classification, and object-evidence availability if this is a blocking action.",
            ],
        },
        ensure_ascii=True,
    )
    timeout_s = _env_float("ODB_AUTODBA_REVIEWER_GEMINI_TIMEOUT_S", 8.0)
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(_gemini_generate_text, api_key, model, f"{system}\n\n{user}")
        raw_text = future.result(timeout=max(timeout_s, 1.0))
    except TimeoutError:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    pool.shutdown(wait=False, cancel_futures=True)

    payload = _parse_reviewer_json(raw_text)
    if payload is None:
        return None

    approved = bool(payload.get("approved"))
    reason = str(payload.get("reason", "")).strip() or "Gemini reviewer returned empty reason."
    confidence = _normalize_confidence(payload.get("confidence"), fallback=("MEDIUM" if approved else "LOW"))
    notes = payload.get("notes")
    if not isinstance(notes, list):
        notes = []
    reviewer_notes = payload.get("reviewer_notes")
    if not isinstance(reviewer_notes, list):
        reviewer_notes = []
    clean_notes = [str(note).strip() for note in notes if str(note).strip()]
    clean_reviewer_notes = [str(note).strip() for note in reviewer_notes if str(note).strip()]
    clean_reviewer_notes.append(f"Gemini model={model}")
    passed, failed = _guardrail_lists(preview)
    return RemediationReview(
        status="approved" if approved else "rejected",
        confidence=confidence,
        rationale=reason,
        reviewer_notes=clean_reviewer_notes[:8],
        guardrail_checks_passed=passed,
        guardrail_checks_failed=failed,
        notes=clean_notes[:8],
    )


def _build_detailed_rationale(
    proposal: RemediationProposal,
    preview: ActionDecision,
    *,
    approved: bool,
    source: str,
) -> str:
    status_text = "approved" if approved else "rejected"
    base = [f"Reviewer {status_text} action_type={proposal.action_type} using source={source}."]
    if proposal.action_type in {"clear_blocking_lock", "kill_session"}:
        t = proposal.target or {}
        classification = str(t.get("blocker_classification") or "unknown")
        blocked_count = _as_int(t.get("blocked_session_count"))
        max_wait = _as_int(t.get("max_blocked_wait_seconds"))
        idle = bool(t.get("blocker_idle_in_transaction"))
        evidence_complete = bool(t.get("evidence_complete"))
        object_present = bool(t.get("object_name"))
        user = str(t.get("username") or "-")
        program = str(t.get("program") or "-")
        module = str(t.get("module") or "-")
        internal = classification in {"sys_or_background"} or user.upper() in {"SYS", "SYSTEM"}
        session_type = "internal/protected" if internal else "foreground/user"
        base.append(
            "Blocking facts: "
            f"session_type={session_type}, user={user}, classification={classification}, "
            f"blocked_sessions={blocked_count if blocked_count is not None else 'unknown'}, "
            f"max_wait_s={max_wait if max_wait is not None else 'unknown'}, "
            f"idle_in_transaction={idle}, object_info_available={object_present}, "
            f"evidence_complete={evidence_complete}."
        )
        base.append(f"Session context: program={program}, module={module}.")
    else:
        base.append("Non-blocking action reviewed with deterministic guardrail evidence.")
    if preview.checks:
        passed = [check.check for check in preview.checks if check.passed]
        failed = [check.check for check in preview.checks if not check.passed]
        base.append(f"Guardrail checks passed={len(passed)}, failed={len(failed)}.")
    return " ".join(base)


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


def _gemini_generate_text(api_key: str, model: str, prompt: str) -> str:
    try:
        from google import genai  # type: ignore

        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model=model,
            contents=prompt,
            config={"temperature": 0.1},
        )
        return str(getattr(resp, "text", "") or "").strip()
    except Exception:
        import google.generativeai as genai_old  # type: ignore

        genai_old.configure(api_key=api_key)
        client = genai_old.GenerativeModel(model)
        resp = client.generate_content(prompt, generation_config={"temperature": 0.1})
        return str(getattr(resp, "text", "") or "").strip()


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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None
