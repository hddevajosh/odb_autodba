from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.mcp import client as mcp_client
from odb_autodba.mcp import jobs as mcp_jobs
from odb_autodba.mcp.server import app as mcp_app
from odb_autodba.services import autodba_service


class McpIntegrationAuditTests(unittest.TestCase):
    def test_expected_service_wrappers_exist(self) -> None:
        for name in (
            "run_health_check",
            "get_active_sessions",
            "get_historical_trends",
            "run_ai_investigation",
            "analyze_sql_id",
            "answer_history_metric_question",
            "analyze_awr",
            "analyze_blocking_sessions",
        ):
            self.assertTrue(hasattr(autodba_service, name), f"missing service wrapper: {name}")

    def test_expected_job_types_registered(self) -> None:
        for job_type in (
            "health_check",
            "active_sessions",
            "historical_trends",
            "history_metric_question",
            "investigation",
            "sql_id_analysis",
            "awr_analysis",
            "blocking_analysis",
        ):
            self.assertIn(job_type, mcp_jobs.ALLOWED_JOB_TYPES)

    def test_expected_mcp_routes_registered(self) -> None:
        paths = {route.path for route in mcp_app.routes}
        for path in (
            "/health",
            "/sessions",
            "/history",
            "/history/metric",
            "/investigate",
            "/sql-id/analyze",
            "/awr/analyze",
            "/blocking/analyze",
            "/report/latest",
            "/jobs",
        ):
            self.assertIn(path, paths)

    def test_expected_mcp_client_methods_exist(self) -> None:
        for name in (
            "submit_health_job",
            "submit_sessions_job",
            "submit_history_job",
            "submit_history_metric_job",
            "submit_investigation_job",
            "submit_sql_id_analysis_job",
            "submit_awr_analysis_job",
            "submit_blocking_analysis_job",
            "get_latest_report",
            "list_jobs",
            "poll_job",
        ):
            self.assertTrue(hasattr(mcp_client, name), f"missing client method: {name}")

    def test_gradio_route_order_is_specific_first(self) -> None:
        self.assertEqual(gradio_app._message_route_for_mcp("analyze sql_id daxra005nhfz2"), "sql_id_analysis")
        self.assertEqual(
            gradio_app._message_route_for_mcp("average cpu consumption on all health check reports"),
            "history_metric_question",
        )
        self.assertEqual(gradio_app._message_route_for_mcp("analyze awr between snapshots"), "awr_analysis")
        self.assertEqual(gradio_app._message_route_for_mcp("check blocking locks"), "blocking_analysis")
        self.assertEqual(gradio_app._message_route_for_mcp("show active sessions"), "sessions")
        self.assertEqual(gradio_app._message_route_for_mcp("show historical trends"), "history")
        self.assertEqual(gradio_app._message_route_for_mcp("check health"), "health")
        self.assertEqual(gradio_app._message_route_for_mcp("why is db slow"), "investigate")

    def test_mcp_mode_routed_capability_does_not_use_local_planner(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_history_metric_job",
            return_value={"ok": True, "job_id": "jobhm"},
        ), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "HISTORY METRIC"}},
        ), patch(
            "odb_autodba.frontend.gradio_app._process_user_message_with_response"
        ) as planner_mock:
            gradio_app._submit_message("average cpu consumption on all health reports", [], {}, "prod__db__1521__pdb1")
        planner_mock.assert_not_called()

    def test_mcp_mode_fallback_disabled_does_not_call_direct_agents(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_investigation_job",
            return_value={"ok": False, "error": "backend down"},
        ), patch(
            "odb_autodba.frontend.gradio_app.mcp_fallback_local_enabled",
            return_value=False,
        ), patch(
            "odb_autodba.frontend.gradio_app._process_user_message_with_response"
        ) as planner_mock, patch(
            "odb_autodba.frontend.gradio_app._investigator"
        ) as investigator_factory:
            out = gradio_app._submit_message("why is db slow", [], {}, "prod__db__1521__pdb1")
        planner_mock.assert_not_called()
        investigator_factory.assert_not_called()
        self.assertIn("MCP job failed/unavailable", out[0][-1]["content"])

    def test_mcp_mode_investigate_button_fallback_disabled_does_not_call_direct_investigator(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_investigation_job",
            return_value={"ok": False, "error": "backend down"},
        ), patch(
            "odb_autodba.frontend.gradio_app.mcp_fallback_local_enabled",
            return_value=False,
        ), patch(
            "odb_autodba.frontend.gradio_app._investigator"
        ) as investigator_factory:
            out = gradio_app._submit_investigation("why is db slow", [], "prod__db__1521__pdb1")
        investigator_factory.assert_not_called()
        self.assertIn("MCP job failed/unavailable", out[0][-1]["content"])

    def test_live_and_historical_blocking_route_to_different_mcp_jobs(self) -> None:
        self.assertEqual(gradio_app._message_route_for_mcp("were there any blocking locks ever?"), "history_metric_question")
        self.assertEqual(gradio_app._message_route_for_mcp("show blocking sessions now"), "blocking_analysis")


if __name__ == "__main__":
    unittest.main()
