from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.guardrails.models import ActionDecision, PolicyViolation
from odb_autodba.models.schemas import GuardrailCheckResult
from odb_autodba.models.schemas import RemediationExecution, RemediationReview


def _tablespace_proposal() -> dict:
    return {
        "action_type": "extend_tablespace",
        "title": "Extend tablespace USERS",
        "description": "Tablespace utilization is high.",
        "rationale": "Tablespace USERS usage is 93.0%.",
        "target": {
            "tablespace_name": "USERS",
            "used_pct": 93.0,
            "used_mb": 9300.0,
            "free_mb": 700.0,
            "total_mb": 10000.0,
            "bigfile": "NO",
            "initial_gb": 1,
            "next_mb": 256,
            "max_gb": 32,
        },
        "sql": "ALTER TABLESPACE USERS ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G",
        "execution_sql": "ALTER TABLESPACE USERS ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G",
    }


def _blocking_proposal() -> dict:
    return {
        "action_type": "clear_blocking_lock",
        "title": "Kill idle-in-transaction blocker SID 88",
        "description": "Blocking lock remediation candidate.",
        "rationale": "Sustained blocking impact.",
        "target": {
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
            "recommendation_mode": "terminate",
        },
        "sql": "ALTER SYSTEM KILL SESSION '88,606,@1' IMMEDIATE",
        "execution_sql": "ALTER SYSTEM KILL SESSION '88,606,@1' IMMEDIATE",
    }


def _review(status: str, rationale: str, extra_notes: list[str] | None = None) -> RemediationReview:
    notes = list(extra_notes or [])
    return RemediationReview(
        status=status,  # type: ignore[arg-type]
        confidence="HIGH" if status == "approved" else "LOW",
        rationale=rationale,
        reviewer_notes=notes,
        guardrail_checks_passed=["allowlisted_action"] if status == "approved" else [],
        guardrail_checks_failed=[] if status == "approved" else ["guardrail_failed"],
    )


class GradioMcpRemediationPipelineTests(unittest.TestCase):
    def _submit_health(self, result_payload: dict):
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch(
            "odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "jobh"}
        ), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": result_payload},
        ):
            out = gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")
        return out

    def test_mcp_health_tablespace_proposal_is_guardrail_only_and_enabled_without_checkbox(self) -> None:
        out = self._submit_health(
            {
                "summary": "Oracle health check completed.",
                "rendered_report": "# Oracle AutoDBA Report",
                "issues": [{"category": "storage", "title": "Tablespace high"}],
                "remediation_proposal": _tablespace_proposal(),
                "supporting_data": {},
            },
        )
        payload = out[2].get("response") or {}
        self.assertEqual((payload.get("remediation_proposal") or {}).get("action_type"), "extend_tablespace")
        self.assertIn("Extend tablespace USERS", out[3])
        self.assertIn("| guardrail_decision | 🟢 approved |", out[3])
        self.assertNotIn("## Reviewer Decision", out[3])
        disabled = gradio_app._execute_button_update(False, out[2])
        enabled = gradio_app._execute_button_update(True, out[2])
        self.assertTrue(bool(disabled.get("interactive")))
        self.assertTrue(bool(enabled.get("interactive")))

    def test_mcp_health_blocking_proposal_runs_guardrails(self) -> None:
        out = self._submit_health(
            {
                "summary": "Oracle health check completed.",
                "rendered_report": "# Oracle AutoDBA Report",
                "issues": [{"category": "blocking", "title": "Blocking chain"}],
                "remediation_proposal": _blocking_proposal(),
                "supporting_data": {},
            },
        )
        payload = out[2].get("response") or {}
        self.assertEqual((payload.get("remediation_proposal") or {}).get("action_type"), "clear_blocking_lock")

    def test_guardrail_approved_high_risk_still_requires_checkbox(self) -> None:
        out = self._submit_health(
            {
                "summary": "Oracle health check completed.",
                "rendered_report": "# Oracle AutoDBA Report",
                "issues": [{"category": "blocking", "title": "Blocking chain"}],
                "remediation_proposal": _blocking_proposal(),
                "supporting_data": {},
            },
        )
        disabled = gradio_app._execute_button_update(False, out[2])
        enabled = gradio_app._execute_button_update(True, out[2])
        self.assertFalse(bool(disabled.get("interactive")))
        self.assertTrue(bool(enabled.get("interactive")))

    def test_guardrail_denied_keeps_execute_disabled_and_shows_reason(self) -> None:
        out = self._submit_health(
            {
                "summary": "Oracle health check completed.",
                "rendered_report": "# Oracle AutoDBA Report",
                "issues": [{"category": "storage", "title": "Tablespace high"}],
                "remediation_proposal": (_tablespace_proposal() | {"target": (_tablespace_proposal()["target"] | {"tablespace_name": "SYSTEM"})}),
                "supporting_data": {},
            },
        )
        self.assertIn("| guardrail_decision | 🔴 rejected |", out[3])
        enabled = gradio_app._execute_button_update(True, out[2])
        self.assertFalse(bool(enabled.get("interactive")))

    def test_manual_non_approved_review_keeps_execute_disabled(self) -> None:
        response_state = {
            "response": {
                "mode": "full_health_report",
                "summary": "Oracle health check completed.",
                "body_markdown": "# Oracle AutoDBA Report",
                "issues": [],
                "recommendations": [],
                "remediation_proposal": _tablespace_proposal(),
                "supporting_data": {"review": _review("pending", "Awaiting approval.").model_dump(mode="json")},
            }
        }
        enabled = gradio_app._execute_button_update(True, response_state)
        self.assertFalse(bool(enabled.get("interactive")))

    def test_guardrail_rejected_keeps_execute_disabled_even_if_checkbox_checked(self) -> None:
        payload = {
            "mode": "full_health_report",
            "summary": "Oracle health check completed.",
            "body_markdown": "# Oracle AutoDBA Report",
            "issues": [],
            "recommendations": [],
            "remediation_proposal": _blocking_proposal() | {"target": (_blocking_proposal()["target"] | {"username": "SYS"})},
            "supporting_data": {"review": _review("approved", "Approved by guardrails.").model_dump(mode="json")},
        }
        enabled = gradio_app._execute_button_update(True, {"response": payload})
        self.assertFalse(bool(enabled.get("interactive")))

    def test_manual_rejected_review_keeps_execute_disabled_even_if_checkbox_checked(self) -> None:
        payload = {
            "response": {
                "mode": "full_health_report",
                "summary": "Oracle health check completed.",
                "body_markdown": "# Oracle AutoDBA Report",
                "issues": [],
                "recommendations": [],
                "remediation_proposal": _blocking_proposal(),
                "supporting_data": {"review": _review("rejected", "Denied by guardrails.").model_dump(mode="json")},
            }
        }
        enabled = gradio_app._execute_button_update(True, payload)
        self.assertFalse(bool(enabled.get("interactive")))

    def test_mcp_hydration_logs_guardrail_fields(self) -> None:
        with self.assertLogs("odb_autodba.frontend.gradio_app", level="INFO") as captured:
            self._submit_health(
                {
                    "summary": "Oracle health check completed.",
                    "rendered_report": "# Oracle AutoDBA Report",
                    "issues": [{"category": "storage", "title": "Tablespace high"}],
                    "remediation_proposal": _tablespace_proposal(),
                    "supporting_data": {},
                }
            )
        text = "\n".join(captured.output)
        self.assertIn("guardrail_decision=approved", text)
        self.assertIn("guardrail_passed=", text)

    def test_mcp_flow_uses_existing_guardrails_policy_engine(self) -> None:
        guardrail_decision = ActionDecision(
            allowed=False,
            violations=[PolicyViolation(rule="protected_user", message="Target user SYS is protected.")],
            checks=[
                GuardrailCheckResult(check="allowlisted_action", passed=True, message="Action clear_blocking_lock is allowlisted."),
                GuardrailCheckResult(check="target_not_protected_user", passed=False, message="Target user SYS is protected."),
            ],
            rationale="Blocked by guardrails",
        )
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch(
            "odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "jobh"}
        ), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={
                "status": "completed",
                "result": {
                    "summary": "Oracle health check completed.",
                    "rendered_report": "# Oracle AutoDBA Report",
                    "issues": [{"category": "blocking", "title": "Blocking chain"}],
                    "remediation_proposal": _blocking_proposal() | {"target": (_blocking_proposal()["target"] | {"username": "SYS"})},
                    "supporting_data": {},
                },
            },
        ), patch("odb_autodba.tools.action_reviewer.policy_engine.evaluate_action", return_value=guardrail_decision) as policy_mock:
            out = gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")

        policy_mock.assert_called()
        self.assertIn("| guardrail_decision | 🔴 rejected |", out[3])
        self.assertIn("target_not_protected_user", out[3])

    def test_mcp_health_without_actionable_finding_keeps_proposal_empty(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch(
            "odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "jobh"}
        ), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"summary": "No issues", "rendered_report": "# Oracle AutoDBA Report"}},
        ):
            out = gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")
        self.assertEqual(out[2], {})
        self.assertEqual(out[3], "No remediation proposed for the current analysis.")

    def test_execute_uses_existing_executor_with_current_payload(self) -> None:
        response_state = {
            "response": {
                "mode": "full_health_report",
                "summary": "Oracle health check completed.",
                "body_markdown": "# Oracle AutoDBA Report",
                "issues": [],
                "recommendations": [],
                "remediation_proposal": _tablespace_proposal(),
                "supporting_data": {"review": _review("approved", "Approved by guardrails.").model_dump(mode="json")},
            }
        }
        with patch(
            "odb_autodba.frontend.gradio_app.execute_remediation_action",
            return_value=RemediationExecution(status="succeeded", message="ok"),
        ) as exec_mock, patch(
            "odb_autodba.frontend.gradio_app.append_action_record"
        ) as append_mock, patch(
            "odb_autodba.frontend.gradio_app._action_history_markdown",
            return_value="history",
        ):
            message, _history = gradio_app._execute_remediation(True, response_state, "prod__db__1521__pdb1")
        exec_mock.assert_called_once()
        append_mock.assert_called_once()
        self.assertIn("Execution status: succeeded", message)
        self.assertIn("Guardrail decision: 🟢 approved", message)

    def test_formatter_style_sections_rendered_for_proposed_remediation(self) -> None:
        out = self._submit_health(
            {
                "summary": "Oracle health check completed.",
                "rendered_report": "# Oracle AutoDBA Report",
                "issues": [{"category": "blocking", "title": "Blocking chain"}],
                "remediation_proposal": _blocking_proposal(),
                "supporting_data": {},
            },
        )
        rendered = out[3]
        self.assertIn("## Proposed Remediation", rendered)
        self.assertIn("## Why suggested", rendered)
        self.assertIn("## Guardrails", rendered)
        self.assertIn("## Failed Checks", rendered)
        self.assertIn("## Key Evidence", rendered)
        self.assertIn("## Suggested Command", rendered)
        self.assertIn("## Safety Warning", rendered)


if __name__ == "__main__":
    unittest.main()
