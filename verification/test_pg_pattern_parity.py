from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.history.jsonl_service import route_history_metric_question
from odb_autodba.services.autodba_service import answer_history_metric_question


class PgPatternParityTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def test_route_history_metric_question_without_health_reports_phrase(self) -> None:
        route = route_history_metric_question("What is average CPU consumption on this database?")
        self.assertIsNotNone(route)
        self.assertEqual(route.get("metric_family"), "cpu")
        self.assertEqual(route.get("aggregation"), "avg")
        self.assertEqual(route.get("source_preference"), "index_first")

    def test_gradio_route_cpu_memory_questions_to_history_metric_job(self) -> None:
        self.assertEqual(
            gradio_app._message_route_for_mcp("What is average CPU consumption on this database?"),
            "history_metric_question",
        )
        self.assertEqual(
            gradio_app._message_route_for_mcp("What is average memory utilization on this database?"),
            "history_metric_question",
        )

    def test_service_prefers_index_source_when_available(self) -> None:
        index_payload = {
            "ok": True,
            "confident": True,
            "route": {"metric_family": "cpu", "aggregation": "avg"},
            "summary": "Historical cpu consumption resolved from index with 4 sample(s) across 2 run(s).",
            "rendered_report": "# Historical CPU Consumption\n\nSummary:\nAverage Host CPU: 24.00%\n",
            "supporting_data": {"metric_family": "cpu", "source": "index"},
        }
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=index_payload,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
        ) as traces_reader:
            payload = answer_history_metric_question("average cpu consumption", db_key="db1")
        traces_reader.assert_not_called()
        self.assertEqual(payload.get("source"), "index")
        self.assertIn("Average Host CPU", payload.get("rendered_report") or "")

    def test_service_falls_back_to_jsonl_when_index_missing(self) -> None:
        traces = [
            type("T", (), {"completed_at": "2026-05-01T00:00:00+00:00", "metrics": {"host_memory_pct": 70.0}})(),
            type("T", (), {"completed_at": "2026-05-02T00:00:00+00:00", "metrics": {"host_memory_pct": 80.0}})(),
        ]
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=None,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
            return_value=traces,
        ), patch(
            "odb_autodba.services.autodba_service.get_running_sessions_inventory",
        ) as live_sessions, patch(
            "odb_autodba.services.autodba_service.get_blocking_chains",
        ) as live_blocking:
            payload = answer_history_metric_question("average memory utilization", db_key="db1")
        live_sessions.assert_not_called()
        live_blocking.assert_not_called()
        self.assertEqual(payload.get("source"), "jsonl_fallback")
        self.assertIn("Average Host Memory", payload.get("rendered_report") or "")


if __name__ == "__main__":
    unittest.main()
