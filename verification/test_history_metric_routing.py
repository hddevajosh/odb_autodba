from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.services.autodba_service import answer_history_metric_question
from odb_autodba.utils.sql_analysis import detect_history_metric_question


class HistoryMetricRoutingTests(unittest.TestCase):
    def test_detect_history_metric_question_cpu_avg(self) -> None:
        detected = detect_history_metric_question("average cpu consumption on all health check reports")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric"), "cpu")
        self.assertEqual(detected.get("aggregation"), "avg")

    def test_detect_history_metric_question_memory_avg(self) -> None:
        detected = detect_history_metric_question("average memory usage from health reports")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric"), "memory")
        self.assertEqual(detected.get("aggregation"), "avg")

    def test_detect_history_metric_question_cpu_usage_overall(self) -> None:
        detected = detect_history_metric_question("cpu usage overall")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric"), "cpu")
        self.assertEqual(detected.get("aggregation"), "avg")

    def test_detect_history_metric_question_average_memory_usage_without_history_phrase(self) -> None:
        detected = detect_history_metric_question("average memory usage")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric"), "memory")
        self.assertEqual(detected.get("aggregation"), "avg")

    def test_detect_history_metric_question_trend(self) -> None:
        detected = detect_history_metric_question("trend of cpu in health reports")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric"), "cpu")
        self.assertEqual(detected.get("aggregation"), "trend")

    def test_non_history_metric_prompt_not_detected(self) -> None:
        self.assertIsNone(detect_history_metric_question("check health of my oracle database"))

    def test_gradio_route_prefers_history_metric_not_health(self) -> None:
        route = gradio_app._message_route_for_mcp("what has been average cpu consumption on all health check reports?")
        self.assertEqual(route, "history_metric_question")
        self.assertEqual(gradio_app._message_route_for_mcp("cpu usage overall"), "history_metric_question")

    def test_mcp_routing_uses_history_metric_endpoint_not_health(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.submit_history_metric_job",
            return_value={"ok": True, "job_id": "jobhm"},
        ) as history_metric_mock, patch(
            "odb_autodba.frontend.gradio_app.submit_health_job",
        ) as health_mock, patch(
            "odb_autodba.frontend.gradio_app.poll_job",
            return_value={"status": "completed", "result": {"rendered_report": "# Historical CPU Consumption"}},
        ):
            gradio_app._submit_message(
                "what has been average cpu consumption on all health check reports?",
                [],
                {},
                "prod__db__1521__pdb1",
            )
        history_metric_mock.assert_called_once_with(
            "what has been average cpu consumption on all health check reports?",
            db_key="prod__db__1521__pdb1",
        )
        health_mock.assert_not_called()

    def test_service_no_history_returns_fallback_message(self) -> None:
        class _Target:
            def __init__(self, db_key: str) -> None:
                self.db_key = db_key

        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=_Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=None,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
            return_value=[],
        ):
            payload = answer_history_metric_question("average cpu consumption", db_key="prod__db__1521__pdb1")
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("db_key"), "prod__db__1521__pdb1")
        self.assertIn("No saved health reports found for time window", payload.get("rendered_report") or "")
        self.assertIn("No saved health reports found for time window", payload.get("summary") or "")

    def test_service_history_exists_computes_average_cpu(self) -> None:
        class _Target:
            def __init__(self, db_key: str) -> None:
                self.db_key = db_key

        traces = [
            SimpleNamespace(metrics={"host_cpu_pct": 30.0}),
            SimpleNamespace(metrics={"host_cpu_pct": 50.0}),
            SimpleNamespace(metrics={"host_cpu_pct": 40.0}),
        ]
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=_Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=None,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
            return_value=traces,
        ), patch(
            "odb_autodba.services.autodba_service.HistoryService.answer_history_question",
        ) as history_sql_path:
            payload = answer_history_metric_question("average cpu consumption", db_key="prod__db__1521__pdb1")
        history_sql_path.assert_not_called()
        self.assertIn("Historical CPU Consumption", payload.get("rendered_report") or "")
        self.assertIn("Average Host CPU", payload.get("rendered_report") or "")
        self.assertNotIn("Average value across requested metric fields", payload.get("rendered_report") or "")
        self.assertIn("historical cpu consumption summary generated", (payload.get("summary") or "").lower())


if __name__ == "__main__":
    unittest.main()
