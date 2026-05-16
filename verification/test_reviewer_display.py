from __future__ import annotations

import unittest

from odb_autodba.models.schemas import RemediationExecution, RemediationProposal, RemediationRecord, RemediationReview
from odb_autodba.utils.formatter import (
    render_action_history_markdown,
    render_remediation_card_markdown,
    reviewer_decision_icon,
    reviewer_display_name,
    reviewer_state_fields,
)


def _proposal() -> RemediationProposal:
    return RemediationProposal(
        action_type="extend_tablespace",
        title="Extend tablespace USERS",
        description="Tablespace utilization is high.",
        rationale="Tablespace USERS usage is 93.0%.",
        target={
            "tablespace_name": "USERS",
            "used_pct": 93.0,
            "free_mb": 700.0,
            "total_mb": 10000.0,
            "autoextensible": "YES",
            "initial_gb": 1,
            "next_mb": 256,
            "max_gb": 32,
        },
        sql="ALTER TABLESPACE USERS ADD DATAFILE SIZE 1G AUTOEXTEND ON NEXT 256M MAXSIZE 32G",
    )


class ReviewerDisplayTests(unittest.TestCase):
    def test_chatgpt_approved_name_and_icon(self) -> None:
        state = reviewer_state_fields(
            {
                "status": "approved",
                "reviewer_notes": ["Reviewer provider=gpt-5.5", "primary_reviewer_provider=ChatGPT Action Reviewer"],
            }
        )
        self.assertEqual(state["reviewer_display_name"], "ChatGPT Action Reviewer")
        self.assertEqual(state["reviewer_icon"], "🟢")

    def test_chatgpt_rejected_icon(self) -> None:
        state = reviewer_state_fields(
            {
                "status": "rejected",
                "reviewer_notes": ["Reviewer provider=gpt-5.5", "primary_reviewer_provider=ChatGPT Action Reviewer"],
            }
        )
        self.assertEqual(state["reviewer_icon"], "🔴")

    def test_deterministic_fallback_name_and_icon(self) -> None:
        state = reviewer_state_fields({"status": "approved", "reviewer_notes": ["Reviewer provider=deterministic"]})
        self.assertEqual(state["reviewer_display_name"], "Deterministic Guardrail Reviewer")
        self.assertEqual(state["reviewer_icon"], "🟢")

    def test_pending_icon(self) -> None:
        self.assertEqual(reviewer_decision_icon("pending", None), "🟡")

    def test_reviewer_error_icon(self) -> None:
        self.assertEqual(reviewer_decision_icon("error", None), "🔴")

    def test_proposed_action_panel_shows_guardrail_only_sections(self) -> None:
        review = {
            "status": "approved",
            "rationale": "Evidence supports extension.",
            "reviewer_notes": [
                "guardrail_passed=allowlisted_action|Action clear_blocking_lock is allowlisted.",
            ],
            "guardrail_checks_passed": ["allowlisted_action"],
            "guardrail_checks_failed": [],
        }
        rendered = render_remediation_card_markdown(_proposal(), review)
        self.assertIn("## Proposed Remediation", rendered)
        self.assertNotIn("## Reviewer Decision", rendered)
        self.assertIn("| guardrail_decision | 🟢 approved |", rendered)
        self.assertIn("## Guardrails", rendered)
        self.assertIn("## Failed Checks", rendered)
        self.assertIn("No failed guardrails.", rendered)
        self.assertIn("## Key Evidence", rendered)
        self.assertIn("## Suggested Command", rendered)

    def test_action_history_shows_compact_chatgpt_label(self) -> None:
        record = RemediationRecord(
            created_at="2026-05-01T00:00:00Z",
            proposal=_proposal(),
            review=RemediationReview(
                status="approved",
                confidence="HIGH",
                rationale="Approved by ChatGPT reviewer.",
                reviewer_notes=[
                    "Reviewer provider=gpt-5.5",
                    "primary_reviewer_provider=ChatGPT Action Reviewer",
                    "primary_reviewer_status=approved",
                    "fallback_used=false",
                ],
            ),
            execution=RemediationExecution(status="succeeded", message="ok"),
        )
        rendered = render_action_history_markdown([record])
        self.assertIn("guardrails=🟢 Guardrails approved (0 passed/0 failed)", rendered)

    def test_action_history_shows_compact_rejected_label(self) -> None:
        record = RemediationRecord(
            created_at="2026-05-01T00:00:00Z",
            proposal=_proposal(),
            review=RemediationReview(
                status="rejected",
                confidence="LOW",
                rationale="Denied by ChatGPT reviewer.",
                reviewer_notes=[
                    "Reviewer provider=gpt-5.5",
                    "primary_reviewer_provider=ChatGPT Action Reviewer",
                    "primary_reviewer_status=rejected",
                    "fallback_used=false",
                ],
            ),
            execution=RemediationExecution(status="skipped", message="blocked"),
        )
        rendered = render_action_history_markdown([record])
        self.assertIn("guardrails=🔴 Guardrails rejected (0 passed/0 failed)", rendered)

    def test_action_history_shows_openai_unavailable_fallback_label(self) -> None:
        record = RemediationRecord(
            created_at="2026-05-01T00:00:00Z",
            proposal=_proposal(),
            review=RemediationReview(
                status="approved",
                confidence="MEDIUM",
                rationale="ChatGPT unavailable; deterministic fallback approved.",
                reviewer_notes=[
                    "Reviewer provider=deterministic_fallback",
                    "primary_reviewer_provider=ChatGPT Action Reviewer",
                    "primary_reviewer_status=timeout",
                    "fallback_used=true",
                    "fallback_reason=openai_timeout",
                    "fallback_reviewer_provider=Deterministic Guardrail Reviewer",
                    "fallback_reviewer_status=approved",
                ],
            ),
            execution=RemediationExecution(status="succeeded", message="ok"),
        )
        rendered = render_action_history_markdown([record])
        self.assertIn("guardrails=🟢 Guardrails approved (0 passed/0 failed)", rendered)

    def test_old_gemini_history_entry_still_renders_readably(self) -> None:
        record = RemediationRecord(
            created_at="2026-05-01T00:00:00Z",
            proposal=_proposal(),
            review=RemediationReview(
                status="approved",
                confidence="MEDIUM",
                rationale="Legacy Gemini reviewer approved.",
                reviewer_notes=["Reviewer provider=gemini-2.5-flash"],
            ),
            execution=RemediationExecution(status="succeeded", message="ok"),
        )
        rendered = render_action_history_markdown([record])
        self.assertIn("guardrails=🟢 Guardrails approved", rendered)

    def test_reviewer_display_name_helper(self) -> None:
        self.assertEqual(reviewer_display_name("openai", "gpt-5.5"), "ChatGPT Action Reviewer")
        self.assertEqual(reviewer_display_name("deterministic", None), "Deterministic Guardrail Reviewer")


if __name__ == "__main__":
    unittest.main()
