---
component_id: 6.2.2
component_name: AI Action Reviewer
---

# AI Action Reviewer

## Component Description

Provides a high-level qualitative audit of proposed actions. It leverages LLMs to evaluate the sanity of a remediation plan, ensuring the proposed fix aligns with the identified root cause and evidence.

---

## Key References:

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

- `tools/action_reviewer.py`

