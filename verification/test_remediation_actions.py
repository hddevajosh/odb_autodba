from __future__ import annotations

import unittest
from contextlib import contextmanager
from unittest.mock import patch

from odb_autodba.guardrails.models import ExecutionContext
from odb_autodba.guardrails.policy_engine import evaluate_action
from odb_autodba.models.schemas import BlockingChain, HealthSnapshot, RemediationProposal, TablespaceUsageRow
from odb_autodba.tools.action_executor import execute_remediation_action
from odb_autodba.tools.action_proposals import build_remediation_proposal
from odb_autodba.tools.action_reviewer import review_remediation_proposal
from odb_autodba.utils.formatter import render_remediation_card_markdown


class RemediationActionTests(unittest.TestCase):
    def test_build_blocking_lock_proposal(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-21T00:00:00Z",
            blocking_chains=[
                BlockingChain(
                    blocker_inst_id=1,
                    blocker_sid=101,
                    blocker_serial=77,
                    blocker_user="APP",
                    blocker_sql_id="abc123xyz9",
                    blocked_sid=202,
                    blocked_sql_id="pqr987xyz1",
                    wait_class="Application",
                    event="enq: TX - row lock contention",
                    seconds_in_wait=240,
                )
            ],
        )
        proposal = build_remediation_proposal(snapshot)
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.action_type, "clear_blocking_lock")
        self.assertIn("KILL SESSION", str(proposal.sql or ""))

    def test_build_tablespace_extend_proposal(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-21T00:00:00Z",
            tablespaces=[
                TablespaceUsageRow(
                    tablespace_name="USERS",
                    used_pct=93.5,
                    used_mb=9350,
                    total_mb=10000,
                    free_mb=650,
                    bigfile="NO",
                )
            ],
        )
        with patch(
            "odb_autodba.tools.action_proposals.build_extend_tablespace_sql",
            return_value=("ALTER TABLESPACE USERS ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G", []),
        ):
            proposal = build_remediation_proposal(snapshot)
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.action_type, "extend_tablespace")
        self.assertEqual(proposal.target.get("tablespace_name"), "USERS")

    def test_build_tablespace_extend_proposal_at_warning_threshold(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-21T00:00:00Z",
            tablespaces=[
                TablespaceUsageRow(
                    tablespace_name="USERS",
                    used_pct=85.0,
                    used_mb=8500,
                    total_mb=10000,
                    free_mb=1500,
                    bigfile="NO",
                )
            ],
        )
        with patch(
            "odb_autodba.tools.action_proposals.build_extend_tablespace_sql",
            return_value=("ALTER TABLESPACE USERS ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G", []),
        ):
            proposal = build_remediation_proposal(snapshot)
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.action_type, "extend_tablespace")

    def test_guardrails_block_protected_tablespace(self) -> None:
        proposal = RemediationProposal(
            action_type="extend_tablespace",
            title="Extend SYSTEM",
            description="test",
            rationale="test",
            sql="ALTER TABLESPACE SYSTEM ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G",
            target={"tablespace_name": "SYSTEM", "used_pct": 99.0, "initial_gb": 1, "next_mb": 256, "max_gb": 32},
        )
        decision = evaluate_action(proposal, ExecutionContext(confirmed=True))
        self.assertFalse(decision.allowed)
        self.assertTrue(any(v.rule == "protected_tablespace" for v in decision.violations))

    def test_guardrails_block_missing_blocker_identity(self) -> None:
        proposal = RemediationProposal(
            action_type="clear_blocking_lock",
            title="Clear blocker",
            description="test",
            rationale="test",
            sql="ALTER SYSTEM KILL SESSION '10,20' IMMEDIATE",
            target={"is_blocker": True},
        )
        decision = evaluate_action(proposal, ExecutionContext(confirmed=True))
        self.assertFalse(decision.allowed)
        self.assertTrue(any(v.rule == "target_identity" for v in decision.violations))

    def test_reviewer_rejects_guardrail_failure(self) -> None:
        proposal = RemediationProposal(
            action_type="extend_tablespace",
            title="Extend SYSTEM",
            description="test",
            rationale="test",
            sql="ALTER TABLESPACE SYSTEM ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G",
            target={"tablespace_name": "SYSTEM", "used_pct": 95.0, "initial_gb": 1, "next_mb": 256, "max_gb": 32},
        )
        review = review_remediation_proposal(proposal)
        self.assertEqual(review.status, "rejected")
        self.assertIn("guardrail", review.rationale.lower())

    def test_execute_extend_tablespace_resolves_sql(self) -> None:
        proposal = RemediationProposal(
            action_type="extend_tablespace",
            title="Extend USERS",
            description="test",
            rationale="test",
            target={"tablespace_name": "USERS", "initial_gb": 1, "next_mb": 256, "max_gb": 32},
        )

        class _Cursor:
            def __init__(self) -> None:
                self.executed: list[str] = []

            def execute(self, sql: str) -> None:
                self.executed.append(sql)

        class _Conn:
            def __init__(self) -> None:
                self.cursor_obj = _Cursor()

            def cursor(self) -> _Cursor:
                return self.cursor_obj

            def commit(self) -> None:
                return None

        @contextmanager
        def _fake_db_connection():
            yield _Conn()

        with (
            patch(
                "odb_autodba.tools.action_executor.build_extend_tablespace_sql",
                return_value=("ALTER TABLESPACE USERS ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G", []),
            ),
            patch("odb_autodba.tools.action_executor.db_connection", _fake_db_connection),
        ):
            execution = execute_remediation_action(proposal)
        self.assertEqual(execution.status, "succeeded")

    def test_short_lived_block_prefers_monitor_recommendation(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-21T00:00:00Z",
            blocking_chains=[
                BlockingChain(
                    blocker_inst_id=1,
                    blocker_sid=64,
                    blocker_serial=101,
                    blocker_user="APPUSR",
                    blocker_program="python",
                    blocker_module="api",
                    blocker_machine="app-host-1",
                    blocker_classification="application_session",
                    evidence_complete=True,
                    blocked_sid=49,
                    blocked_serial=222,
                    blocked_user="APPUSR",
                    blocked_sql_id="abc123xyz9",
                    blocked_session_count=1,
                    max_blocked_wait_seconds=30,
                    seconds_in_wait=30,
                )
            ],
        )
        proposal = build_remediation_proposal(snapshot)
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.action_type, "clear_blocking_lock")
        self.assertEqual(proposal.target.get("recommendation_mode"), "monitor")
        self.assertIn("Monitor blocker", proposal.title)

    def test_long_idle_in_transaction_block_gets_stronger_title(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-21T00:00:00Z",
            blocking_chains=[
                BlockingChain(
                    blocker_inst_id=1,
                    blocker_sid=88,
                    blocker_serial=606,
                    blocker_user="APPUSR",
                    blocker_program="python",
                    blocker_module="order_api",
                    blocker_machine="app-host-2",
                    blocker_classification="idle_in_transaction_blocker",
                    blocker_has_transaction=True,
                    blocker_idle_in_transaction=True,
                    evidence_complete=True,
                    blocked_sid=91,
                    blocked_serial=333,
                    blocked_user="APPUSR",
                    blocked_sql_id="def456xyz9",
                    blocked_session_count=3,
                    max_blocked_wait_seconds=450,
                    seconds_in_wait=450,
                )
            ],
        )
        proposal = build_remediation_proposal(snapshot)
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.target.get("recommendation_mode"), "terminate")
        self.assertIn("idle-in-transaction", proposal.title.lower())
        self.assertIsNotNone(proposal.post_action_validation)
        self.assertGreaterEqual(len(proposal.post_action_validation.checks), 3)

    def test_sys_or_background_blocker_rejected_by_guardrails(self) -> None:
        proposal = RemediationProposal(
            action_type="clear_blocking_lock",
            title="Review protected blocker",
            description="test",
            rationale="test",
            target={
                "sid": 77,
                "serial#": 991,
                "inst_id": 1,
                "username": "SYS",
                "program": "ora_mmon_free",
                "module": "MMON",
                "is_blocker": True,
                "blocked_session_count": 4,
                "max_blocked_wait_seconds": 600,
                "evidence_complete": True,
                "blocker_classification": "sys_or_background",
            },
        )
        decision = evaluate_action(proposal, ExecutionContext(confirmed=True))
        self.assertFalse(decision.allowed)
        self.assertTrue(any(v.rule in {"protected_user", "protected_blocker_class", "background_process"} for v in decision.violations))

    def test_missing_blocking_evidence_forces_review_first(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-21T00:00:00Z",
            blocking_chains=[
                BlockingChain(
                    blocker_inst_id=1,
                    blocker_sid=55,
                    blocker_serial=155,
                    blocker_user="APPUSR",
                    blocker_program="python",
                    blocker_module="api",
                    blocker_machine="app-host-1",
                    blocker_classification="unknown",
                    evidence_complete=False,
                    blocked_sid=44,
                    blocked_serial=444,
                    blocked_user="APPUSR",
                    blocked_sql_id="abc123xyz9",
                    blocked_session_count=1,
                    max_blocked_wait_seconds=120,
                    seconds_in_wait=120,
                )
            ],
        )
        proposal = build_remediation_proposal(snapshot)
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.target.get("recommendation_mode"), "review_first")
        self.assertEqual(proposal.confidence, "LOW")

    def test_formatter_shows_concise_blocking_card(self) -> None:
        proposal = RemediationProposal(
            action_type="clear_blocking_lock",
            title="Terminate blocking user session SID 64",
            description="Blocking-lock remediation candidate generated from live evidence.",
            rationale="Blocker evidence present.",
            reason_for_action="Sustained lock impact detected.",
            sql="ALTER SYSTEM KILL SESSION '64,100,@1' IMMEDIATE",
            target={
                "sid": 64,
                "serial#": 100,
                "inst_id": 1,
                "username": "APPUSR",
                "status": "INACTIVE",
                "program": "python",
                "module": "order_api",
                "machine": "app-host",
                "blocked_session_count": 3,
                "max_blocked_wait_seconds": 420,
                "blocker_classification": "idle_in_transaction_blocker",
                "blocker_has_transaction": True,
                "blocker_idle_in_transaction": True,
                "object_owner": "APP",
                "object_name": "ORDERS",
                "object_type": "TABLE",
                "blocked_session_details": [{"sid": 49, "username": "APPUSR", "sql_id": "abc", "event": "enq: TX - row lock contention", "seconds_in_wait": 420}],
                "evidence_complete": True,
            },
            risks=["Rollback risk."],
            safer_alternatives=["Monitor another minute."],
            validation_plan=["Re-check blockers."],
        )
        review = review_remediation_proposal(proposal)
        rendered = render_remediation_card_markdown(proposal, review)

        self.assertIn("## Proposed Action", rendered)
        self.assertIn("### Why it is suggested", rendered)
        self.assertIn("### Reviewer Decision", rendered)
        self.assertIn("### SQL", rendered)
        self.assertIn("ALTER SYSTEM KILL SESSION '64,100,@1' IMMEDIATE", rendered)
        self.assertIn("SID 64 (user APPUSR) is idle in transaction", rendered)
        self.assertIn("blocking 3 sessions for 420 seconds", rendered)
        self.assertIn("APP.ORDERS", rendered)

        self.assertNotIn("### Evidence", rendered)
        self.assertNotIn("### Safer Alternatives", rendered)
        self.assertNotIn("### Post-action validation", rendered)
        self.assertNotIn("### Risks", rendered)
        self.assertNotIn("Checks passed:", rendered)
        self.assertNotIn("Checks failed:", rendered)
        self.assertNotIn("Notes:", rendered)
        self.assertNotIn("Confidence:", rendered)
        self.assertNotIn("Rationale:", rendered)
        self.assertNotIn("Status:", rendered)

        lines = rendered.splitlines()
        decision_idx = lines.index("### Reviewer Decision")
        decision_line = lines[decision_idx + 1]
        self.assertTrue(decision_line.startswith(("Approved", "Denied", "Pending", "Not needed")))
        self.assertLessEqual(len([line for line in lines if line.startswith("Risk:")]), 1)

    def test_reviewer_rationale_includes_blocking_facts(self) -> None:
        proposal = RemediationProposal(
            action_type="clear_blocking_lock",
            title="Kill idle-in-transaction blocker SID 88",
            description="test",
            rationale="test",
            target={
                "sid": 88,
                "serial#": 606,
                "inst_id": 1,
                "username": "APPUSR",
                "program": "python",
                "module": "order_api",
                "is_blocker": True,
                "blocked_session_count": 3,
                "max_blocked_wait_seconds": 450,
                "blocker_classification": "idle_in_transaction_blocker",
                "blocker_idle_in_transaction": True,
                "evidence_complete": True,
                "object_name": "ORDERS",
            },
            sql="ALTER SYSTEM KILL SESSION '88,606,@1' IMMEDIATE",
        )
        review = review_remediation_proposal(proposal)
        self.assertIn("blocked_sessions", review.rationale)
        self.assertIn("classification", review.rationale)
        self.assertIn("Guardrail", review.rationale)
        self.assertTrue(len(review.guardrail_checks_passed) >= 1)


if __name__ == "__main__":
    unittest.main()
