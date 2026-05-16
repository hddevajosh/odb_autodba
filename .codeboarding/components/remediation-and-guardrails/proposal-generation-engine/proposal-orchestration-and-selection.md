---
component_id: 6.1.1
component_name: Proposal Orchestration & Selection
---

# Proposal Orchestration & Selection

## Component Description

The entry point of the engine that evaluates the current database health snapshot to identify and prioritize remediation needs. It selects the most critical strategy to execute based on severity.

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


## Source Files:

- `db/remediation_sql.py`

