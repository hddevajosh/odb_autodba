from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.utils.sql_analysis import detect_sql_id_analysis_intent


class SqlIdRoutingTests(unittest.TestCase):
    def test_detect_sql_id_analysis_intent_patterns(self) -> None:
        self.assertEqual(detect_sql_id_analysis_intent("analyze sql_id daxra005nhfz2"), "daxra005nhfz2")
        self.assertEqual(detect_sql_id_analysis_intent("sql_id daxra005nhfz2"), "daxra005nhfz2")
        self.assertEqual(detect_sql_id_analysis_intent("check sql id daxra005nhfz2"), "daxra005nhfz2")
        self.assertEqual(detect_sql_id_analysis_intent("investigate sql_id=daxra005nhfz2"), "daxra005nhfz2")

    def test_detect_sql_id_analysis_intent_no_false_match(self) -> None:
        self.assertIsNone(detect_sql_id_analysis_intent("show active sessions"))
        self.assertIsNone(detect_sql_id_analysis_intent("why is db slow"))

    def test_gradio_route_prefers_sql_id_over_investigation(self) -> None:
        self.assertEqual(gradio_app._message_route_for_mcp("analyze sql_id daxra005nhfz2"), "sql_id_analysis")

    def test_local_sql_id_failure_does_not_fallback_to_investigation(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False), patch(
            "odb_autodba.frontend.gradio_app.analyze_sql_id",
            side_effect=RuntimeError("sql collector failure"),
        ), patch("odb_autodba.frontend.gradio_app._investigator") as inv_factory:
            out = gradio_app._submit_message("analyze sql_id daxra005nhfz2", [], {}, "prod__db__1521__pdb1")
        inv_factory.assert_not_called()
        assistant = out[0][-1]["content"]
        self.assertIn("SQL_ID Analysis", assistant)
        self.assertIn("failed", assistant.lower())
        self.assertNotIn("AI Investigation Report", assistant)


if __name__ == "__main__":
    unittest.main()
