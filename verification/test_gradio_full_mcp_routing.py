from __future__ import annotations

import inspect
import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app


class GradioFullMcpRoutingTests(unittest.TestCase):
    def _component_id_by_label(self, config: dict, label: str) -> int:
        for component in config.get("components", []):
            props = component.get("props") or {}
            if props.get("label") == label:
                return int(component["id"])
        raise AssertionError(f"Component with label={label!r} not found")

    def _button_id(self, config: dict, label: str) -> int:
        for component in config.get("components", []):
            if component.get("type") != "button":
                continue
            props = component.get("props") or {}
            if props.get("value") == label:
                return int(component["id"])
        raise AssertionError(f"Button with label={label!r} not found")

    def test_ui_handler_signatures_keep_selected_db_key_input(self) -> None:
        message_sig = inspect.signature(gradio_app._submit_message_ui)
        message_params = list(message_sig.parameters.keys())
        self.assertEqual(message_params, ["message", "chat_state", "response_state", "selected_db_key", "labels_by_key"])

        investigation_sig = inspect.signature(gradio_app._submit_investigation_ui)
        investigation_params = list(investigation_sig.parameters.keys())
        self.assertEqual(investigation_params, ["message", "chat_state", "selected_db_key", "labels_by_key"])

    def test_ui_callbacks_include_target_dropdown_input(self) -> None:
        config = gradio_app.build_app().get_config_file()
        target_db_id = self._component_id_by_label(config, "Target Database")
        for button_label in ("Check Health", "Show Active Sessions", "Historical Trends", "Send", "Investigate with AI", "Clear"):
            button_id = self._button_id(config, button_label)
            matching = [
                dependency
                for dependency in config.get("dependencies", [])
                if (button_id, "click") in dependency.get("targets", [])
            ]
            self.assertTrue(matching, f"click dependency for {button_label!r} not found")
            self.assertIn(target_db_id, matching[0].get("inputs") or [])

    def test_execution_mode_helper(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True):
            self.assertEqual(gradio_app.get_execution_mode(), "mcp")
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False):
            self.assertEqual(gradio_app.get_execution_mode(), "local")

    def test_execution_mode_indicator_text_exists(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True):
            self.assertIn("Execution mode:", gradio_app._execution_mode_label())
            self.assertIn("MCP backend", gradio_app._execution_mode_label())
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False):
            self.assertIn("Execution mode:", gradio_app._execution_mode_label())
            self.assertIn("Local direct", gradio_app._execution_mode_label())

    def test_mcp_send_unknown_prompt_routes_to_investigate(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_investigation_job", return_value={"ok": True, "job_id": "jobi"}
        ) as submit_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "INV REPORT"}},
        ):
            out = gradio_app._submit_message("What parameters are set?", [], {}, "prod__db__1521__pdb1")
        submit_mock.assert_called_once_with("What parameters are set?", db_key="prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("Queued MCP job", assistant)

    def test_mcp_send_sql_id_prompt_routes_to_sql_id_analysis(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_sql_id_analysis_job", return_value={"ok": True, "job_id": "jobsql"}
        ) as sql_mock, patch(
            "odb_autodba.frontend.gradio_app.submit_investigation_job"
        ) as inv_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "# SQL_ID Deep Dive — daxra005nhfz2"}},
        ):
            gradio_app._submit_message("investigate sql_id=daxra005nhfz2", [], {}, "prod__db__1521__pdb1")
        sql_mock.assert_called_once_with("daxra005nhfz2", db_key="prod__db__1521__pdb1")
        inv_mock.assert_not_called()

    def test_mcp_send_health_uses_health_endpoint(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "jobh"}
        ) as health_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "HEALTH REPORT"}},
        ):
            gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")
        health_mock.assert_called_once_with(db_key="prod__db__1521__pdb1")

    def test_mcp_send_sessions_uses_sessions_endpoint(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_sessions_job", return_value={"ok": True, "job_id": "jobs"}
        ) as sessions_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "SESSIONS REPORT"}},
        ):
            gradio_app._submit_message("show active sessions", [], {}, "prod__db__1521__pdb1")
        sessions_mock.assert_called_once_with(db_key="prod__db__1521__pdb1")

    def test_mcp_send_history_uses_history_endpoint(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_history_job", return_value={"ok": True, "job_id": "jobx"}
        ) as history_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "HISTORY REPORT"}},
        ):
            gradio_app._submit_message("Show historical trends", [], {}, "prod__db__1521__pdb1")
        history_mock.assert_called_once_with(db_key="prod__db__1521__pdb1")

    def test_mcp_send_history_metric_prompt_uses_history_metric_endpoint(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_history_metric_job", return_value={"ok": True, "job_id": "jobhm"}
        ) as metric_mock, patch(
            "odb_autodba.frontend.gradio_app.submit_health_job"
        ) as health_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "HISTORY METRIC REPORT"}},
        ):
            gradio_app._submit_message(
                "what has been average cpu consumption on all health check reports?",
                [],
                {},
                "prod__db__1521__pdb1",
            )
        metric_mock.assert_called_once_with(
            "what has been average cpu consumption on all health check reports?",
            db_key="prod__db__1521__pdb1",
        )
        health_mock.assert_not_called()

    def test_route_helper_identifies_sql_id_analysis(self) -> None:
        self.assertEqual(gradio_app._message_route_for_mcp("analyze sql_id daxra005nhfz2"), "sql_id_analysis")
        self.assertEqual(
            gradio_app._message_route_for_mcp("what has been average cpu consumption on this database?"),
            "history_metric_question",
        )
        self.assertEqual(gradio_app._message_route_for_mcp("analyze awr between snapshots"), "awr_analysis")
        self.assertEqual(gradio_app._message_route_for_mcp("show blocking sessions now"), "blocking_analysis")
        self.assertEqual(gradio_app._message_route_for_mcp("show active sessions"), "sessions")
        self.assertEqual(gradio_app._message_route_for_mcp("show historical trends"), "history")
        self.assertEqual(gradio_app._message_route_for_mcp("check health"), "health")
        self.assertEqual(gradio_app._message_route_for_mcp("why is db slow"), "investigate")

    def test_mcp_mode_fallback_true_uses_local(self) -> None:
        local_tuple = ([{"role": "assistant", "content": "LOCAL"}], [{"role": "assistant", "content": "LOCAL"}], {}, "", False, object(), "", "")
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_health_job", side_effect=RuntimeError("connection refused")
        ), patch("odb_autodba.frontend.gradio_app.mcp_fallback_local_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._submit_message_local", return_value=local_tuple
        ):
            out = gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")
        self.assertIn("fallback", out[0][-1]["content"].lower())

    def test_mcp_mode_fallback_false_shows_friendly_error(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_health_job", side_effect=RuntimeError("password=abc")
        ), patch("odb_autodba.frontend.gradio_app.mcp_fallback_local_enabled", return_value=False):
            out = gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")
        text = out[0][-1]["content"]
        self.assertIn("MCP job failed/unavailable", text)
        self.assertNotIn("abc", text)

    def test_local_mode_uses_local_direct(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False), patch(
            "odb_autodba.frontend.gradio_app._submit_message_local", return_value=([], [], {}, "", False, object(), "", "")
        ) as local_mock:
            gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")
        local_mock.assert_called_once()

    def test_latest_report_in_mcp_mode_does_not_use_local_writer(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.get_latest_report",
            return_value={"ok": True, "rendered_report": "# Latest Health Report"},
        ) as latest_mock:
            text = gradio_app._latest_report_message(db_key="prod__db__1521__pdb1", report_type="health")
        latest_mock.assert_called_once_with(report_type="health", db_key="prod__db__1521__pdb1")
        self.assertIn("# Latest Health Report", text)


if __name__ == "__main__":
    unittest.main()
