---
component_id: 6.3.1
component_name: Remediation Executor
---

# Remediation Executor

## Component Description

The physical interface to the Oracle database. It handles the lifecycle of a database session for a specific remediation task, executing SQL or PL/SQL blocks and capturing raw execution metadata (timing, row counts, and database-level errors).

---

## Key References:

### /home/neha/projects/agents/odb_autodba/tools/action_executor.py (lines 11-41)
```
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
```


## Source Files:

- `tools/action_executor.py`

