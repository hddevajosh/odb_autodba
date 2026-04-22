from __future__ import annotations

from typing import Any

from odb_autodba.guardrails.models import ActionDecision, ExecutionContext, PolicyViolation
from odb_autodba.models.schemas import GuardrailCheckResult
from odb_autodba.guardrails.rules import (
    ALLOWED_ACTIONS,
    BLOCKED_SESSION_COUNT_KILL_THRESHOLD,
    BLOCKING_WAIT_KILL_THRESHOLD_SECONDS,
    BLOCKING_WAIT_WARNING_SECONDS,
    BLOCKED_SQL_KEYWORDS,
    PROTECTED_MAINTENANCE_TOKENS,
    PROTECTED_PROGRAM_TOKENS,
    PROTECTED_TABLESPACES,
    PROTECTED_USERS,
    SAFE_SQL_PREFIXES,
    TABLESPACE_EXTEND_MAX_INITIAL_GB,
    TABLESPACE_EXTEND_MAX_MAX_GB,
    TABLESPACE_EXTEND_MAX_NEXT_MB,
    TABLESPACE_EXTEND_MIN_INITIAL_GB,
    TABLESPACE_EXTEND_MIN_MAX_GB,
    TABLESPACE_EXTEND_MIN_NEXT_MB,
    TABLESPACE_EXTEND_TRIGGER_PCT,
)
from odb_autodba.models.schemas import RemediationProposal


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


def _validate_action_specific(
    proposal: RemediationProposal,
    checks: list[GuardrailCheckResult],
    violations: list[PolicyViolation],
) -> None:
    action_type = proposal.action_type
    if action_type in {"clear_blocking_lock", "kill_session"}:
        sid = _as_int(proposal.target.get("sid"))
        serial_num = _as_int(proposal.target.get("serial#"))
        _record_check(
            checks,
            violations,
            check="blocking_target_identity",
            passed=(sid is not None and serial_num is not None),
            rule="target_identity",
            fail_message="SID and SERIAL# are required for blocking-lock actions.",
            pass_message=f"Blocking target identity resolved as SID={sid}, SERIAL#={serial_num}.",
        )
        _record_check(
            checks,
            violations,
            check="blocking_target_marked_as_blocker",
            passed=(proposal.target.get("is_blocker") is not False),
            rule="blocker_evidence",
            fail_message="Target session is not marked as a blocker.",
            pass_message="Target session is marked as blocker evidence.",
        )
        blocked_count = _as_int(proposal.target.get("blocked_session_count"))
        _record_check(
            checks,
            violations,
            check="blocked_session_count_present",
            passed=(blocked_count is not None and blocked_count > 0),
            rule="blocked_session_count",
            fail_message="Blocked session count is missing or zero; kill action cannot be approved.",
            pass_message=f"Blocked session count is {blocked_count}.",
        )
        max_wait_s = _as_int(proposal.target.get("max_blocked_wait_seconds"))
        _record_check(
            checks,
            violations,
            check="blocking_duration_above_warning_threshold",
            passed=(max_wait_s is not None and max_wait_s >= BLOCKING_WAIT_WARNING_SECONDS),
            rule="blocking_duration",
            fail_message=(
                f"Blocking duration is below threshold: need >= {BLOCKING_WAIT_WARNING_SECONDS}s, got "
                f"{max_wait_s if max_wait_s is not None else 'unknown'}."
            ),
            pass_message=f"Blocking duration {max_wait_s}s is above warning threshold.",
        )
        evidence_complete = bool(proposal.target.get("evidence_complete"))
        _record_check(
            checks,
            violations,
            check="blocking_evidence_complete",
            passed=evidence_complete,
            rule="incomplete_evidence",
            fail_message="Blocker evidence is incomplete; review-first workflow is required.",
            pass_message="Blocker evidence is marked complete.",
        )
        classification = str(proposal.target.get("blocker_classification") or "").strip().lower()
        _record_check(
            checks,
            violations,
            check="blocker_classification_known",
            passed=classification not in {"", "unknown"},
            rule="uncertain_classification",
            fail_message="Blocker classification is unknown; review-first workflow is required.",
            pass_message=f"Blocker classification is {classification}.",
        )
        _record_check(
            checks,
            violations,
            check="blocker_not_internal_or_background",
            passed=classification not in {"sys_or_background"},
            rule="protected_blocker_class",
            fail_message="Blocker classification indicates SYS/background context; kill action blocked.",
            pass_message="Blocker classification is not SYS/background.",
        )
        is_idle_in_tx = bool(proposal.target.get("blocker_idle_in_transaction"))
        sustained = bool(max_wait_s is not None and max_wait_s >= BLOCKING_WAIT_KILL_THRESHOLD_SECONDS)
        widespread = bool(blocked_count is not None and blocked_count >= BLOCKED_SESSION_COUNT_KILL_THRESHOLD)
        impact_ok = sustained or widespread or (is_idle_in_tx and max_wait_s is not None and max_wait_s >= BLOCKING_WAIT_WARNING_SECONDS)
        _record_check(
            checks,
            violations,
            check="blocking_impact_threshold_met",
            passed=impact_ok,
            rule="insufficient_impact",
            fail_message=(
                "Blocking impact does not meet kill threshold: require sustained wait, multiple blocked sessions, "
                "or idle-in-transaction above warning threshold."
            ),
            pass_message="Blocking impact threshold met for kill workflow.",
        )
        return

    if action_type == "extend_tablespace":
        tablespace_name = str(proposal.target.get("tablespace_name", "") or "").upper()
        _record_check(
            checks,
            violations,
            check="tablespace_name_present",
            passed=bool(tablespace_name),
            rule="target_tablespace",
            fail_message="tablespace_name is required for extend_tablespace action.",
            pass_message=f"tablespace_name is {tablespace_name}.",
        )
        if not tablespace_name:
            return
        _record_check(
            checks,
            violations,
            check="tablespace_not_protected",
            passed=tablespace_name not in PROTECTED_TABLESPACES,
            rule="protected_tablespace",
            fail_message=f"Tablespace {tablespace_name} is protected.",
            pass_message=f"Tablespace {tablespace_name} is not protected.",
        )

        used_pct = _as_float(proposal.target.get("used_pct"))
        _record_check(
            checks,
            violations,
            check="tablespace_utilization_threshold",
            passed=not (used_pct is not None and used_pct < TABLESPACE_EXTEND_TRIGGER_PCT),
            rule="utilization_threshold",
            fail_message=(
                f"Tablespace utilization {used_pct:.1f}% is below extend threshold "
                f"{TABLESPACE_EXTEND_TRIGGER_PCT:.1f}%."
            )
            if used_pct is not None
            else "Tablespace utilization was not provided.",
            pass_message=(
                f"Tablespace utilization {used_pct:.1f}% meets threshold {TABLESPACE_EXTEND_TRIGGER_PCT:.1f}%."
                if used_pct is not None
                else "Tablespace utilization not provided; threshold check skipped."
            ),
        )

        initial_gb = _as_int(proposal.target.get("initial_gb"))
        next_mb = _as_int(proposal.target.get("next_mb"))
        max_gb = _as_int(proposal.target.get("max_gb"))
        _record_check(
            checks,
            violations,
            check="extend_initial_range",
            passed=(initial_gb is None or TABLESPACE_EXTEND_MIN_INITIAL_GB <= initial_gb <= TABLESPACE_EXTEND_MAX_INITIAL_GB),
            rule="extend_initial_range",
            fail_message=(
                f"initial_gb={initial_gb} is outside allowed range "
                f"{TABLESPACE_EXTEND_MIN_INITIAL_GB}-{TABLESPACE_EXTEND_MAX_INITIAL_GB}."
            ),
            pass_message=f"initial_gb is within allowed range ({initial_gb}).",
        )
        _record_check(
            checks,
            violations,
            check="extend_next_range",
            passed=(next_mb is None or TABLESPACE_EXTEND_MIN_NEXT_MB <= next_mb <= TABLESPACE_EXTEND_MAX_NEXT_MB),
            rule="extend_next_range",
            fail_message=(
                f"next_mb={next_mb} is outside allowed range "
                f"{TABLESPACE_EXTEND_MIN_NEXT_MB}-{TABLESPACE_EXTEND_MAX_NEXT_MB}."
            ),
            pass_message=f"next_mb is within allowed range ({next_mb}).",
        )
        _record_check(
            checks,
            violations,
            check="extend_max_range",
            passed=(max_gb is None or TABLESPACE_EXTEND_MIN_MAX_GB <= max_gb <= TABLESPACE_EXTEND_MAX_MAX_GB),
            rule="extend_max_range",
            fail_message=(
                f"max_gb={max_gb} is outside allowed range "
                f"{TABLESPACE_EXTEND_MIN_MAX_GB}-{TABLESPACE_EXTEND_MAX_MAX_GB}."
            ),
            pass_message=f"max_gb is within allowed range ({max_gb}).",
        )


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


def _record_check(
    checks: list[GuardrailCheckResult],
    violations: list[PolicyViolation],
    *,
    check: str,
    passed: bool,
    rule: str,
    fail_message: str,
    pass_message: str,
) -> None:
    checks.append(GuardrailCheckResult(check=check, passed=passed, message=(pass_message if passed else fail_message)))
    if not passed:
        violations.append(PolicyViolation(rule=rule, message=fail_message))
