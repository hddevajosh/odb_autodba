---
component_id: 6.2.1
component_name: Deterministic Policy Engine
---

# Deterministic Policy Engine

## Component Description

Implements the primary safety barrier using rule-based logic. It performs SQL sanitization, keyword scanning, and schema protection to prevent unauthorized or destructive database operations.

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


## Source Files:

- `guardrails/policy_engine.py`
- `tools/action_reviewer.py`

