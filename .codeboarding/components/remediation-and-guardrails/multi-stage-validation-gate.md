---
component_id: 6.2
component_name: Multi-Stage Validation Gate
---

# Multi-Stage Validation Gate

## Component Description

Acts as the subsystem's primary safety barrier. It combines a deterministic Security Policy Engine (for SQL sanitization and constraint checking) with an AI-Driven Action Reviewer (using Gemini to evaluate the rationale and risk of the proposed change).

---

## Key References:

### /home/neha/projects/agents/odb_autodba/guardrails/policy_engine.py (lines 29-94)
```
def evaluate_action(proposal: RemediationProposal, execution_context: ExecutionContext) -> ActionDecision:
    violations: list[PolicyViolation] = []
    checks: list[GuardrailCheckResult] = []
    action_type = str(proposal.action_type or "").strip()

    _record_check(
        checks,
        violations,
        check="allowlisted_action",
        passed=action_type in ALLOWED_ACTIONS,
        rule="allowlist",
        fail_message=f"Action {action_type} is not allowlisted.",
        pass_message=f"Action {action_type} is allowlisted.",
    )

    _record_check(
        checks,
        violations,
        check="operator_confirmation",
        passed=bool(execution_context.confirmed),
        rule="confirmation",
        fail_message="Operator confirmation is required.",
        pass_message="Operator confirmation is present.",
    )

    target_user = str(proposal.target.get("username", "") or "").upper()
    _record_check(
        checks,
        violations,
        check="target_not_protected_user",
        passed=target_user not in PROTECTED_USERS,
        rule="protected_user",
        fail_message=f"Target user {target_user} is protected.",
        pass_message=(f"Target user {target_user or '-'} is not protected."),
    )

    program = str(proposal.target.get("program", "") or "").lower()
    module = str(proposal.target.get("module", "") or "").lower()
    _record_check(
        checks,
        violations,
        check="target_not_background_process",
        passed=not any(token in program for token in PROTECTED_PROGRAM_TOKENS),
        rule="background_process",
        fail_message="Background or critical Oracle process cannot be targeted.",
        pass_message="No Oracle background-process token found in target program.",
    )
    _record_check(
        checks,
        violations,
        check="target_not_protected_maintenance_session",
        passed=not any(token in f"{program} {module}" for token in PROTECTED_MAINTENANCE_TOKENS),
        rule="protected_maintenance_session",
        fail_message="Protected maintenance session patterns were detected in target program/module.",
        pass_message="No protected maintenance pattern found in target program/module.",
    )

    _validate_sql_payload(proposal, checks, violations)
    _validate_action_specific(proposal, checks, violations)

    return ActionDecision(
        allowed=not violations,
        violations=violations,
        checks=checks,
        rationale=("Allowed" if not violations else "Blocked by guardrails"),
    )
```

### /home/neha/projects/agents/odb_autodba/tools/action_reviewer.py (lines 19-96)
```
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
```

### /home/neha/projects/agents/odb_autodba/guardrails/policy_engine.py (lines 97-125)
```
def _validate_sql_payload(
    proposal: RemediationProposal,
    checks: list[GuardrailCheckResult],
    violations: list[PolicyViolation],
) -> None:
    sql = str(proposal.sql or "").strip()
    if not sql:
        checks.append(GuardrailCheckResult(check="sql_payload_present", passed=True, message="No SQL payload was provided for validation."))
        return
    up = sql.upper()
    _record_check(
        checks,
        violations,
        check="sql_not_dangerous",
        passed=not any(keyword in up for keyword in BLOCKED_SQL_KEYWORDS),
        rule="dangerous_sql",
        fail_message="Action SQL contains blocked keywords.",
        pass_message="Action SQL passed blocked-keyword scan.",
    )
    action_prefixes = SAFE_SQL_PREFIXES.get(proposal.action_type)
    _record_check(
        checks,
        violations,
        check="sql_prefix_valid",
        passed=(not action_prefixes or any(up.startswith(prefix) for prefix in action_prefixes)),
        rule="sql_prefix",
        fail_message=f"SQL prefix is not valid for action {proposal.action_type}.",
        pass_message=f"SQL prefix is valid for action {proposal.action_type}.",
    )
```

### /home/neha/projects/agents/odb_autodba/tools/action_reviewer.py (lines 120-181)
```
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
```


## Source Files:

- `guardrails/policy_engine.py`
- `tools/action_reviewer.py`

