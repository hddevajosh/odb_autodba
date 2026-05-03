from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.target_registry import build_transient_target, clear_transient_targets, register_transient_target


class GradioMcpModeTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_transient_targets()

    def tearDown(self) -> None:
        clear_transient_targets()

    def _local_tuple(self):
        chat = [{"role": "assistant", "content": "LOCAL REPORT"}]
        return (chat, chat, {"response": {}}, "md", False, object(), "", "history")

    def test_mcp_disabled_uses_local_submit_path(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False), patch(
            "odb_autodba.frontend.gradio_app._submit_message_local", return_value=self._local_tuple()
        ) as mocked:
            out = gradio_app._submit_message("Check health", [], {})
        mocked.assert_called_once()
        self.assertEqual(out[0][0]["content"], "LOCAL REPORT")

    def test_mcp_enabled_health_submits_and_polls(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch("odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "job1"}) as submit_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "FULL REPORT"}},
        ):
            out = gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")
        submit_mock.assert_called_once_with(db_key="prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("Queued MCP job: job1", assistant)
        self.assertIn("Status: completed", assistant)
        self.assertIn("FULL REPORT", assistant)

    def test_mcp_regular_registry_target_uses_db_key_without_inline_target_payload(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch("odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "job1"}) as submit_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "FULL REPORT"}},
        ):
            gradio_app._submit_message("Check health", [], {}, "prod__db__1521__pdb1")
        submit_mock.assert_called_once_with(db_key="prod__db__1521__pdb1")

    def test_mcp_enabled_history_submits_and_polls(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="history"
        ), patch("odb_autodba.frontend.gradio_app.submit_history_job", return_value={"ok": True, "job_id": "job2"}) as submit_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "HISTORY REPORT"}},
        ):
            out = gradio_app._submit_message("Show historical trends", [], {}, "prod__db__1521__pdb1")
        submit_mock.assert_called_once_with(db_key="prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("Queued MCP job: job2", assistant)
        self.assertIn("HISTORY REPORT", assistant)

    def test_mcp_enabled_active_sessions_submits_and_polls(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="sessions"
        ), patch(
            "odb_autodba.frontend.gradio_app.submit_sessions_job", return_value={"ok": True, "job_id": "jobS"}
        ) as submit_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "ACTIVE REPORT"}},
        ):
            out = gradio_app._submit_message("show active sessions", [], {}, "prod__db__1521__pdb1")
        submit_mock.assert_called_once_with(db_key="prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("Queued MCP job: jobS", assistant)
        self.assertIn("ACTIVE REPORT", assistant)

    def test_mcp_enabled_investigation_submits_and_polls(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_investigation_job", return_value={"ok": True, "job_id": "job3"}
        ) as submit_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "INV REPORT"}},
        ):
            out = gradio_app._submit_investigation("Show active sessions", [], "prod__db__1521__pdb1")
        submit_mock.assert_called_once_with("Show active sessions", db_key="prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("Queued MCP job: job3", assistant)
        self.assertIn("INV REPORT", assistant)

    def test_mcp_enabled_sql_id_prompt_uses_sql_id_analysis_endpoint(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_sql_id_analysis_job",
            return_value={"ok": True, "job_id": "jobsql"},
        ) as submit_mock, patch(
            "odb_autodba.frontend.gradio_app.submit_investigation_job"
        ) as investigation_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "# SQL_ID Deep Dive — daxra005nhfz2"}},
        ):
            out = gradio_app._submit_message("analyze sql_id daxra005nhfz2", [], {}, "prod__db__1521__pdb1")
        submit_mock.assert_called_once_with("daxra005nhfz2", db_key="prod__db__1521__pdb1")
        investigation_mock.assert_not_called()
        assistant = out[0][-1]["content"]
        self.assertIn("Queued MCP job: jobsql", assistant)
        self.assertIn("# SQL_ID Deep Dive — daxra005nhfz2", assistant)

    def test_local_sql_id_prompt_uses_service_analyzer(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False), patch(
            "odb_autodba.frontend.gradio_app.analyze_sql_id",
            return_value={
                "ok": True,
                "db_key": "prod__db__1521__pdb1",
                "sql_id": "daxra005nhfz2",
                "summary": "SQL_ID daxra005nhfz2 deep dive completed.",
                "rendered_report": "# SQL_ID Deep Dive — daxra005nhfz2",
                "supporting_data": {"sql_id": "daxra005nhfz2"},
            },
        ) as analyzer, patch(
            "odb_autodba.frontend.gradio_app._process_user_message_with_response"
        ) as planner_mock:
            out = gradio_app._submit_message("analyze sql_id daxra005nhfz2", [], {}, "prod__db__1521__pdb1")
        analyzer.assert_called_once_with("daxra005nhfz2", db_key="prod__db__1521__pdb1")
        planner_mock.assert_not_called()
        assistant = out[0][-1]["content"]
        self.assertIn("# SQL_ID Deep Dive — daxra005nhfz2", assistant)

    def test_local_history_metric_prompt_uses_history_metric_service(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False), patch(
            "odb_autodba.frontend.gradio_app.answer_history_metric_question",
            return_value={
                "ok": True,
                "db_key": "prod__db__1521__pdb1",
                "summary": "History source: raw JSONL only.",
                "rendered_report": "# Historical CPU Consumption",
                "supporting_data": {"domain": "cpu"},
            },
        ) as history_metric, patch(
            "odb_autodba.frontend.gradio_app._process_user_message_with_response"
        ) as planner_mock:
            out = gradio_app._submit_message("average cpu consumption on all health reports", [], {}, "prod__db__1521__pdb1")
        history_metric.assert_called_once_with("average cpu consumption on all health reports", db_key="prod__db__1521__pdb1")
        planner_mock.assert_not_called()
        self.assertIn("# Historical CPU Consumption", out[0][-1]["content"])

    def test_mcp_investigation_displays_hydrated_report_when_present(self) -> None:
        hydrated = (
            "# AI Investigation Result\n\n"
            "## SQL Executed\n```sql\nselect 1 from dual\n```\n\n"
            "## Result\nReturned 1 row(s).\n"
        )
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_investigation_job", return_value={"ok": True, "job_id": "jobhydr"}
        ), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": hydrated, "trace_path": "/tmp/inv.jsonl"}},
        ):
            out = gradio_app._submit_investigation("What is the size of the database?", [], "prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("## SQL Executed", assistant)
        self.assertNotIn("Compact job payload", assistant)
        self.assertNotIn("/tmp/inv.jsonl", assistant)

    def test_direct_mode_passes_db_key_to_planner(self) -> None:
        local = self._local_tuple()
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False), patch(
            "odb_autodba.frontend.gradio_app._submit_message_local", return_value=local
        ) as local_mock:
            gradio_app._submit_message("Check health", [], {}, "prod__db__1521__pdb1")
        local_mock.assert_called_once_with(
            "Check health",
            [],
            {},
            selected_db_key="prod__db__1521__pdb1",
            target_label="prod__db__1521__pdb1",
        )

    def test_mcp_unreachable_fallback_true_uses_local(self) -> None:
        local = self._local_tuple()
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch("odb_autodba.frontend.gradio_app.submit_health_job", side_effect=RuntimeError("connection refused")), patch(
            "odb_autodba.frontend.gradio_app.mcp_fallback_local_enabled", return_value=True
        ), patch("odb_autodba.frontend.gradio_app._submit_message_local", return_value=local):
            out = gradio_app._submit_message("Check health", [], {}, "prod__db__1521__pdb1")
        self.assertIn("fallback", out[0][-1]["content"].lower())

    def test_mcp_unreachable_fallback_false_returns_friendly_error(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch("odb_autodba.frontend.gradio_app.submit_health_job", side_effect=RuntimeError("password=abc")), patch(
            "odb_autodba.frontend.gradio_app.mcp_fallback_local_enabled", return_value=False
        ):
            out = gradio_app._submit_message("Check health", [], {}, "prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("MCP job failed/unavailable", assistant)
        self.assertNotIn("abc", assistant)

    def test_completed_job_prefers_rendered_report_not_raw_json(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="history"
        ), patch("odb_autodba.frontend.gradio_app.submit_history_job", return_value={"ok": True, "job_id": "jobx"}), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "RICH REPORT", "summary": "compact"}},
        ):
            out = gradio_app._submit_message("history", [], {}, "prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("RICH REPORT", assistant)
        self.assertNotIn("{'summary'", assistant)

    def test_completed_job_falls_back_to_summary_when_rendered_report_missing(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="history"
        ), patch("odb_autodba.frontend.gradio_app.submit_history_job", return_value={"ok": True, "job_id": "jobsum"}), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"summary": "Compact summary only"}},
        ):
            out = gradio_app._submit_message("history", [], {}, "prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("Compact summary only", assistant)
        self.assertNotIn("No rendered report/summary was provided.", assistant)

    def test_completed_job_uses_compact_json_last_resort(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="history"
        ), patch("odb_autodba.frontend.gradio_app.submit_history_job", return_value={"ok": True, "job_id": "jobjson"}), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"supporting_data": {"x": 1}}},
        ):
            out = gradio_app._submit_message("history", [], {}, "prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("Compact job payload", assistant)
        self.assertIn("\"supporting_data\"", assistant)

    def test_investigation_trace_only_shows_hydration_failure_message_not_raw_json(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_investigation_job", return_value={"ok": True, "job_id": "jobtrace"}
        ), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"trace_path": "/tmp/trace_only.jsonl"}},
        ):
            out = gradio_app._submit_investigation("What is the size of the database?", [], "prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("hydrated report was unavailable", assistant)
        self.assertIn("/tmp/trace_only.jsonl", assistant)
        self.assertNotIn("Compact job payload", assistant)

    def test_timeout_handled_cleanly(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch("odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "jobt"}), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"ok": False, "status": "running", "error": "job polling timed out"},
        ), patch("odb_autodba.frontend.gradio_app.mcp_fallback_local_enabled", return_value=False):
            out = gradio_app._submit_message("Check health", [], {}, "prod__db__1521__pdb1")
        self.assertIn("MCP job failed/unavailable", out[0][-1]["content"])

    def test_health_output_mentions_target_database(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch("odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "job1"}), patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "FULL REPORT"}},
        ):
            out = gradio_app._submit_message("Check health of my Oracle database", [], {}, "prod__db__1521__pdb1")
        assistant = out[0][-1]["content"]
        self.assertIn("Target database:", assistant)

    def test_mcp_payload_includes_transient_target_metadata_without_password(self) -> None:
        target = build_transient_target(
            environment="adhoc",
            host="prod-db01.example.com",
            port=1521,
            username="monitor",
            service_name="PDB1",
            password_env="PROD_DB01_PASSWORD",
            display_name="Adhoc prod",
        )
        register_transient_target(target, password=None, replace=True)
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app._message_route_for_mcp", return_value="health"
        ), patch("odb_autodba.frontend.gradio_app.submit_health_job", return_value={"ok": True, "job_id": "job9"}) as submit_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "FULL REPORT"}},
        ):
            gradio_app._submit_message("Check health", [], {}, target.db_key)
        _, kwargs = submit_mock.call_args
        self.assertEqual(kwargs.get("db_key"), target.db_key)
        payload = kwargs.get("target")
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload.get("db_key"), target.db_key)
        self.assertNotIn("'password':", str(payload).lower())


if __name__ == "__main__":
    unittest.main()
