---
component_id: 6.1.4
component_name: Context & Safety Enrichment
---

# Context & Safety Enrichment

## Component Description

Responsible for generating the Human-in-the-loop metadata. It calculates confidence scores, describes risks, suggests safer alternatives, and defines the SQL queries needed to validate that the remediation worked.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/tools/action_proposals.py (lines 471-496)
```
def _reason_for_action(
    *,
    recommendation_mode: str,
    sid: int,
    blocker_user: str,
    blocker_classification: str,
    blocked_count: int,
    max_wait_seconds: int,
    warning_threshold: int,
    kill_threshold: int,
) -> str:
    if recommendation_mode == "terminate":
        return (
            f"Blocker SID {sid} ({blocker_user}) is classified as {blocker_classification} and is sustaining lock impact: "
            f"{blocked_count} blocked session(s), max wait {max_wait_seconds}s. Thresholds "
            f"warning={warning_threshold}s, kill={kill_threshold}s."
        )
    if recommendation_mode == "monitor":
        return (
            f"Blocking impact is currently short-lived (max wait {max_wait_seconds}s, blocked={blocked_count}). "
            "Monitor first and escalate only if the wait persists."
        )
    return (
        f"Evidence suggests blocker SID {sid} but confidence is limited (classification={blocker_classification}, "
        f"blocked={blocked_count}, max_wait={max_wait_seconds}s). Use review-first workflow before termination."
    )
```

### /home/neha/projects/agents/odb_autodba/tools/action_proposals.py (lines 499-513)
```
def _proposal_confidence(
    *,
    recommendation_mode: str,
    evidence_complete: bool,
    classification: str,
    max_wait_seconds: int,
    kill_threshold: int,
) -> str:
    if recommendation_mode == "terminate" and evidence_complete and classification in {"application_session", "idle_in_transaction_blocker"}:
        return "HIGH" if max_wait_seconds >= kill_threshold else "MEDIUM"
    if recommendation_mode == "monitor":
        return "MEDIUM"
    if evidence_complete and classification != "unknown":
        return "MEDIUM"
    return "LOW"
```

### /home/neha/projects/agents/odb_autodba/tools/action_proposals.py (lines 461-468)
```
def _blocking_action_title(mode: str, sid: int, classification: str) -> str:
    if mode == "terminate":
        if classification == "idle_in_transaction_blocker":
            return f"Kill idle-in-transaction blocker SID {sid}"
        return f"Terminate blocking user session SID {sid}"
    if mode == "monitor":
        return f"Monitor blocker SID {sid} before termination"
    return f"Review blocker ownership before terminating SID {sid}"
```


## Source Files:

- `tools/action_proposals.py`

