from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.agents.planner_agent import PlannerAgent
from odb_autodba.services.autodba_service import analyze_sql_id
from odb_autodba.utils.sql_analysis import detect_sql_id_analysis_intent


class SqlIdMcpRoutingTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    class _DeepDive:
        def __init__(self, sql_id: str) -> None:
            self.sql_id = sql_id

        def model_dump(self, mode: str = "json"):
            _ = mode
            return {
                "sql_id": self.sql_id,
                "notes": ["existing collector note"],
                "risk_summary": {"risk_level": "MEDIUM"},
            }

    def test_detect_sql_id_analysis_intent_extracts_sql_id(self) -> None:
        self.assertEqual(detect_sql_id_analysis_intent("analyze sql_id daxra005nhfz2"), "daxra005nhfz2")
        self.assertEqual(detect_sql_id_analysis_intent("sql_id daxra005nhfz2"), "daxra005nhfz2")
        self.assertEqual(detect_sql_id_analysis_intent("check sql id daxra005nhfz2"), "daxra005nhfz2")
        self.assertEqual(detect_sql_id_analysis_intent("investigate sql_id=daxra005nhfz2"), "daxra005nhfz2")

    def test_detect_sql_id_analysis_intent_does_not_false_match_normal_prompt(self) -> None:
        self.assertIsNone(detect_sql_id_analysis_intent("show historical trends for last 7 days"))
        self.assertIsNone(detect_sql_id_analysis_intent("what caused cpu spike yesterday"))

    def test_service_analyze_sql_id_uses_existing_analyzer_and_preserves_rendered_report(self) -> None:
        existing_rendered = "# SQL_ID Deep Dive — daxra005nhfz2\n\n## Execution Plan\n..."
        with patch("odb_autodba.services.autodba_service.get_oracle_target", return_value=self._Target("db1")), patch(
            "odb_autodba.services.autodba_service.build_sql_id_deep_dive_report",
            return_value=self._DeepDive("daxra005nhfz2"),
        ) as build_mock, patch(
            "odb_autodba.services.autodba_service.render_sql_id_deep_dive_report",
            return_value=existing_rendered,
        ) as render_mock:
            payload = analyze_sql_id("daxra005nhfz2", db_key="db1")

        build_mock.assert_called_once_with("daxra005nhfz2")
        render_mock.assert_called_once()
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("db_key"), "db1")
        self.assertEqual(payload.get("sql_id"), "daxra005nhfz2")
        self.assertEqual(payload.get("rendered_report"), existing_rendered)
        self.assertIn("SQL_ID Deep Dive", payload.get("rendered_report") or "")
        self.assertIsInstance(payload.get("supporting_data"), dict)

    def test_active_sessions_report_includes_sql_id_analysis_hint(self) -> None:
        report = PlannerAgent()._render_active_sessions_response(
            active_rows=[{"sid": 11, "sql_id": "daxra005nhfz2"}],
        )
        self.assertNotIn("## SQL_ID Analysis Hint", report)
        self.assertTrue(
            report.rstrip().endswith(
                "Tip: analyze SQL with `analyze sql_id <sql_id>` (sample: daxra005nhfz2)."
            )
        )


if __name__ == "__main__":
    unittest.main()
