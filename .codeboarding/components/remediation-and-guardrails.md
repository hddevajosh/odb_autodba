---
component_id: 6
component_name: Remediation & Guardrails
---

# Remediation & Guardrails

## Component Description

Governs the 'write' path of the application, proposing database fixes and ensuring they pass security policies and LLM-based reviews before execution.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/tools/action_proposals.py (lines 24-38)
```
def build_remediation_proposal(snapshot: HealthSnapshot) -> RemediationProposal | None:
    candidates: list[RemediationProposal] = []
    blocking = _blocking_lock_proposal(snapshot)
    if blocking is not None:
        candidates.append(blocking)

    tablespace = _tablespace_extend_proposal(snapshot)
    if tablespace is not None:
        candidates.append(tablespace)

    if not candidates:
        return None

    candidates.sort(key=_proposal_priority)
    return candidates[0]
```

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


## Source Files:

- `db/remediation_sql.py`
- `guardrails/policy_engine.py`
- `tools/action_executor.py`
- `tools/action_history.py`
- `tools/action_proposals.py`
- `tools/action_reviewer.py`

