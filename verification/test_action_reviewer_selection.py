from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from odb_autodba.guardrails.models import ActionDecision, PolicyViolation
from odb_autodba.models.schemas import RemediationProposal
from odb_autodba.tools.action_reviewer import review_remediation_proposal


def _tablespace_proposal() -> RemediationProposal:
    return RemediationProposal(
        action_type="extend_tablespace",
        title="Extend tablespace USERS",
        description="Tablespace utilization is high.",
        rationale="Tablespace USERS usage is 93.0%.",
        target={
            "tablespace_name": "USERS",
            "used_pct": 93.0,
            "used_mb": 9300.0,
            "free_mb": 700.0,
            "total_mb": 10000.0,
            "bigfile": "NO",
            "initial_gb": 1,
            "next_mb": 256,
            "max_gb": 32,
            "autoextensible": "YES",
        },
        sql="ALTER TABLESPACE USERS ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G",
    )


def _blocking_proposal(
    *,
    blocker_user: str = "DEVA1",
    idle_in_transaction: bool = True,
    wait_seconds: int = 420,
    blocked_sessions: int = 1,
    evidence_complete: bool = True,
) -> RemediationProposal:
    return RemediationProposal(
        action_type="clear_blocking_lock",
        title="Kill idle-in-transaction blocker SID 218" if idle_in_transaction else "Terminate blocking session SID 218 after validation",
        description="Blocking lock remediation candidate.",
        rationale="Sustained blocking impact.",
        target={
            "sid": 218,
            "serial#": 22311,
            "inst_id": 1,
            "username": blocker_user,
            "program": "sqlplus@Devarshi (TNS V1-V3)",
            "module": "SQL*Plus",
            "status": "INACTIVE",
            "is_blocker": True,
            "blocked_session_count": blocked_sessions,
            "max_blocked_wait_seconds": wait_seconds,
            "blocker_classification": "idle_in_transaction_blocker" if idle_in_transaction else "foreground_session",
            "blocker_idle_in_transaction": idle_in_transaction,
            "evidence_complete": evidence_complete,
            "recommendation_mode": "terminate",
            "object_owner": "DEVA1",
            "object_name": "LOCK_TEST",
            "blocked_session_details": [
                {
                    "sid": 215,
                    "serial#": 12345,
                    "event": "enq: TX - row lock contention",
                    "wait_class": "Application",
                }
            ],
        },
        sql="ALTER SYSTEM KILL SESSION '218,22311,@1' IMMEDIATE",
    )


class ActionReviewerSelectionTests(unittest.TestCase):
    def test_existing_guardrail_policy_engine_is_called(self) -> None:
        decision = ActionDecision(
            allowed=False,
            violations=[PolicyViolation(rule="protected_user", message="Target user SYS is protected.")],
            checks=[],
            rationale="Blocked by guardrails",
        )
        with patch("odb_autodba.tools.action_reviewer.policy_engine.evaluate_action", return_value=decision) as mock_eval:
            review = review_remediation_proposal(_blocking_proposal(blocker_user="SYS"))
        mock_eval.assert_called_once()
        self.assertEqual(review.status, "rejected")
        self.assertIn("source=existing_guardrails_policy_engine", " ".join(review.notes))

    def test_selector_prefers_openai_when_key_present_provider_auto(self) -> None:
        captured: dict[str, str] = {}

        def _fake_openai(_api_key: str, _model: str, _system: str, user_prompt: str) -> str:
            captured["user_prompt"] = user_prompt
            return json.dumps(
                {
                    "approved": True,
                    "decision": "approved",
                    "reason": "Evidence supports extension.",
                    "risk_level": "low",
                    "required_user_ack": False,
                    "failed_conditions": [],
                    "confidence": "high",
                }
            )

        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "redacted_openai_key",
                "ODB_AUTODBA_ACTION_REVIEWER_PROVIDER": "auto",
                "ODB_AUTODBA_OPENAI_REVIEW_MODEL": "gpt-5.5",
                "ODB_AUTODBA_ALLOW_DETERMINISTIC_FALLBACK_ON_OPENAI_ERROR": "true",
            },
            clear=False,
        ), patch("odb_autodba.tools.action_reviewer._openai_generate_text", side_effect=_fake_openai):
            review = review_remediation_proposal(_tablespace_proposal())

        self.assertEqual(review.status, "approved")
        notes = " ".join(review.reviewer_notes)
        self.assertIn("selected_reviewer=ChatGPT Action Reviewer", notes)
        self.assertIn("openai_api_key_present=true", notes)
        self.assertIn("fallback_used=false", notes)
        self.assertIn("primary_reviewer_provider=ChatGPT Action Reviewer", notes)
        payload_text = captured.get("user_prompt", "")
        self.assertIn('"action_id"', payload_text)
        self.assertIn('"action_type"', payload_text)
        self.assertIn('"deterministic_guardrail_results"', payload_text)
        self.assertIn('"risk_summary"', payload_text)
        self.assertNotIn("# Oracle AutoDBA Report", payload_text)

    def test_selector_does_not_choose_gemini_when_google_key_present(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "",
                "GOOGLE_API_KEY": "present",
                "ODB_AUTODBA_ACTION_REVIEWER_PROVIDER": "auto",
                "ODB_AUTODBA_ALLOW_DETERMINISTIC_FALLBACK_ON_OPENAI_ERROR": "true",
            },
            clear=False,
        ):
            review = review_remediation_proposal(_tablespace_proposal())
        notes = " ".join(review.reviewer_notes)
        self.assertIn("selected_reviewer=Deterministic Guardrail Reviewer", notes)
        self.assertIn("fallback_reason=openai_api_key_missing", notes)
        self.assertNotIn("Gemini 2.5 Flash Agent", notes)

    def test_missing_openai_key_uses_deterministic_fallback_when_allowed(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "",
                "ODB_AUTODBA_ACTION_REVIEWER_PROVIDER": "openai",
                "ODB_AUTODBA_ALLOW_DETERMINISTIC_FALLBACK_ON_OPENAI_ERROR": "true",
            },
            clear=False,
        ):
            review = review_remediation_proposal(_tablespace_proposal())
        self.assertEqual(review.status, "approved")
        self.assertIn("fallback_reason=openai_api_key_missing", review.reviewer_notes)

    def test_openai_error_uses_deterministic_fallback_when_enabled(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "present",
                "ODB_AUTODBA_ACTION_REVIEWER_PROVIDER": "openai",
                "ODB_AUTODBA_ALLOW_DETERMINISTIC_FALLBACK_ON_OPENAI_ERROR": "true",
            },
            clear=False,
        ), patch("odb_autodba.tools.action_reviewer._openai_generate_text", side_effect=RuntimeError("boom")):
            review = review_remediation_proposal(_tablespace_proposal())
        self.assertEqual(review.status, "approved")
        self.assertIn("fallback_reason=openai_error", review.reviewer_notes)
        self.assertIn("fallback_reviewer_provider=Deterministic Guardrail Reviewer", review.reviewer_notes)

    def test_openai_error_without_fallback_rejects(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "present",
                "ODB_AUTODBA_ACTION_REVIEWER_PROVIDER": "openai",
                "ODB_AUTODBA_ALLOW_DETERMINISTIC_FALLBACK_ON_OPENAI_ERROR": "false",
            },
            clear=False,
        ), patch("odb_autodba.tools.action_reviewer._openai_generate_text", side_effect=RuntimeError("boom")):
            review = review_remediation_proposal(_tablespace_proposal())
        self.assertEqual(review.status, "rejected")
        self.assertIn("fallback_reason=openai_error", review.reviewer_notes)

    def test_malformed_openai_json_does_not_auto_enable_execution(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "present",
                "ODB_AUTODBA_ACTION_REVIEWER_PROVIDER": "openai",
                "ODB_AUTODBA_ALLOW_DETERMINISTIC_FALLBACK_ON_OPENAI_ERROR": "false",
            },
            clear=False,
        ), patch("odb_autodba.tools.action_reviewer._openai_generate_text", return_value="not json"):
            review = review_remediation_proposal(_tablespace_proposal())
        self.assertEqual(review.status, "rejected")
        self.assertIn("fallback_reason=openai_invalid_json", review.reviewer_notes)

    def test_provider_gemini_is_disabled_and_never_selected(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "present",
                "ODB_AUTODBA_ACTION_REVIEWER_PROVIDER": "gemini",
            },
            clear=False,
        ):
            review = review_remediation_proposal(_tablespace_proposal())
        self.assertEqual(review.status, "approved")
        self.assertIn("selected_reviewer=Deterministic Guardrail Reviewer", review.reviewer_notes)
        self.assertIn("fallback_reason=gemini_disabled_by_config", review.reviewer_notes)

    def test_sys_user_blocker_is_rejected_and_execute_must_stay_disabled(self) -> None:
        review = review_remediation_proposal(_blocking_proposal(blocker_user="SYS"))
        self.assertEqual(review.status, "rejected")
        self.assertIn("target_not_protected_user", review.guardrail_checks_failed)

    def test_system_user_blocker_is_rejected(self) -> None:
        review = review_remediation_proposal(_blocking_proposal(blocker_user="SYSTEM"))
        self.assertEqual(review.status, "rejected")
        self.assertIn("target_not_protected_user", review.guardrail_checks_failed)

    def test_custom_user_can_be_approved_when_existing_guardrails_pass(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "",
                "ODB_AUTODBA_ACTION_REVIEWER_PROVIDER": "auto",
                "ODB_AUTODBA_ALLOW_DETERMINISTIC_FALLBACK_ON_OPENAI_ERROR": "true",
            },
            clear=False,
        ):
            review = review_remediation_proposal(_blocking_proposal(blocker_user="DEVA1", idle_in_transaction=True, wait_seconds=420))
        self.assertEqual(review.status, "approved")
        self.assertEqual(len(review.guardrail_checks_failed), 0)

    def test_custom_user_rejected_when_evidence_fails_policy(self) -> None:
        review = review_remediation_proposal(
            _blocking_proposal(blocker_user="DEVA1", idle_in_transaction=False, wait_seconds=38, blocked_sessions=1, evidence_complete=True)
        )
        self.assertEqual(review.status, "rejected")
        self.assertTrue(any(name in {"blocking_impact_threshold_met", "blocking_duration_above_warning_threshold"} for name in review.guardrail_checks_failed))


if __name__ == "__main__":
    unittest.main()
