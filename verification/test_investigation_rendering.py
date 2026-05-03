from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.models.schemas import InvestigationReport, InvestigationStep
from odb_autodba.services.autodba_service import run_ai_investigation


class InvestigationRenderingTests(unittest.TestCase):
    def _report(self, likely_cause: str) -> InvestigationReport:
        return InvestigationReport(
            problem_statement="x",
            summary="Ran 1 Oracle investigation step(s).",
            likely_cause=likely_cause,
            evidence=["e1"],
            recommended_next_actions=["n1"],
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="g1",
                    sql="select 1 from dual",
                    result_preview="ok",
                    row_count=1,
                    status="success",
                    result_columns=["X"],
                    result_rows=[{"X": 1}],
                )
            ],
        )

    def test_inventory_investigation_renders_conclusion_heading(self) -> None:
        with patch("odb_autodba.services.autodba_service.InvestigationAgent.investigate", return_value=self._report("Requested inventory metric was collected: database size estimate.")):
            payload = run_ai_investigation("What is the size of the database?")
        report = payload.get("rendered_report") or ""
        self.assertIn("## 🔵 Investigation Conclusion", report)

    def test_diagnostic_investigation_renders_root_cause_heading(self) -> None:
        with patch("odb_autodba.services.autodba_service.InvestigationAgent.investigate", return_value=self._report("One or more high-cost SQL statements appear to be contributing to the slowdown.")):
            payload = run_ai_investigation("Why is DB slow?")
        report = payload.get("rendered_report") or ""
        self.assertIn("## 🔴 Root Cause Analysis", report)

    def test_tables_prone_to_blocking_locks_defaults_to_conclusion_when_no_live_blockers(self) -> None:
        with patch("odb_autodba.services.autodba_service.InvestigationAgent.investigate", return_value=self._report("Investigation completed with read-only evidence collection based on your request.")):
            payload = run_ai_investigation("Which tables are prone to blocking locks?")
        report = payload.get("rendered_report") or ""
        self.assertIn("## 🔵 Investigation Conclusion", report)

    def test_tables_prone_to_blocking_locks_uses_root_cause_when_blockers_found(self) -> None:
        with patch("odb_autodba.services.autodba_service.InvestigationAgent.investigate", return_value=self._report("Blocking or lock contention is the leading cause candidate based on the investigation path.")):
            payload = run_ai_investigation("Which tables are prone to blocking locks?")
        report = payload.get("rendered_report") or ""
        self.assertIn("## 🔴 Root Cause Analysis", report)


if __name__ == "__main__":
    unittest.main()
