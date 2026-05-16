from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.services.autodba_service import answer_history_metric_question
from odb_autodba.utils.sql_analysis import detect_history_metric_question


class HistoryMetricQuestionsTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def test_average_cpu_routes_to_history_metric(self) -> None:
        detected = detect_history_metric_question("average cpu consumption on this database")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric_family"), "cpu")
        self.assertEqual(detected.get("aggregation"), "avg")
        self.assertEqual(gradio_app._message_route_for_mcp("average cpu consumption on this database"), "history_metric_question")

    def test_average_memory_routes_to_history_metric(self) -> None:
        detected = detect_history_metric_question("average memory usage")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric_family"), "memory")
        self.assertEqual(detected.get("aggregation"), "avg")

    def test_blocking_yesterday_routes_to_history_metric(self) -> None:
        detected = detect_history_metric_question("were there any blocking locks yesterday?")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric_family"), "blocking")
        self.assertEqual(detected.get("aggregation"), "any")
        self.assertEqual((detected.get("time_window") or {}).get("label"), "yesterday")
        self.assertEqual(gradio_app._message_route_for_mcp("were there any blocking locks yesterday?"), "history_metric_question")

    def test_show_blocking_now_routes_to_live_blocking(self) -> None:
        self.assertEqual(gradio_app._message_route_for_mcp("show blocking sessions now"), "blocking_analysis")
        self.assertIsNone(detect_history_metric_question("show blocking sessions now"))

    def test_tablespace_max_routes_to_history_metric(self) -> None:
        detected = detect_history_metric_question("max tablespace usage last week")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric_family"), "tablespace")
        self.assertEqual(detected.get("aggregation"), "max")
        self.assertEqual((detected.get("time_window") or {}).get("label"), "last_week")

    def test_ora_errors_count_routes_to_history_metric(self) -> None:
        detected = detect_history_metric_question("how many times did ORA errors occur?")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric_family"), "alerts")
        self.assertEqual(detected.get("aggregation"), "count")

    def test_top_sql_cpu_trend_routes_to_history_metric(self) -> None:
        detected = detect_history_metric_question("trend of top SQL CPU")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.get("metric_family"), "sql_workload")
        self.assertEqual(detected.get("aggregation"), "trend")

    def test_unsupported_metric_returns_friendly_supported_list(self) -> None:
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=None,
        ), patch(
            "odb_autodba.services.autodba_service.detect_history_metric_question",
            return_value={"metric_family": "quantum", "aggregation": "avg", "requested_fields": ["q"], "time_window": {"label": "all"}},
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
            return_value=[],
        ):
            payload = answer_history_metric_question("average quantum latency", db_key="prod__db__1521__pdb1")
        self.assertTrue(payload.get("ok"))
        self.assertIn("Unsupported historical metric family", payload.get("summary") or "")
        self.assertIn("supported families", (payload.get("summary") or "").lower())

    def test_focused_report_not_full_historical_trend_report(self) -> None:
        traces = [
            SimpleNamespace(completed_at="2026-05-01T10:00:00+00:00", metrics={"host_cpu_pct": 20.0}),
            SimpleNamespace(completed_at="2026-05-02T10:00:00+00:00", metrics={"host_cpu_pct": 40.0}),
        ]
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=None,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
            return_value=traces,
        ):
            payload = answer_history_metric_question("average cpu consumption", db_key="prod__db__1521__pdb1")
        report = payload.get("rendered_report") or ""
        self.assertIn("# Historical CPU Consumption", report)
        self.assertNotIn("Oracle Historical Trend Analysis", report)

    def test_no_live_sql_executed_for_history_metric_question(self) -> None:
        traces = [
            SimpleNamespace(completed_at="2026-05-01T10:00:00+00:00", metrics={"host_memory_pct": 70.0}),
            SimpleNamespace(completed_at="2026-05-02T10:00:00+00:00", metrics={"host_memory_pct": 80.0}),
        ]
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=None,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
            return_value=traces,
        ), patch(
            "odb_autodba.services.autodba_service.HistoryService.answer_history_question",
        ) as history_llm_path, patch(
            "odb_autodba.services.autodba_service.get_running_sessions_inventory",
        ) as live_sessions, patch(
            "odb_autodba.services.autodba_service.get_blocking_chains",
        ) as blocking_live:
            payload = answer_history_metric_question("average memory usage", db_key="prod__db__1521__pdb1")
        history_llm_path.assert_not_called()
        live_sessions.assert_not_called()
        blocking_live.assert_not_called()
        self.assertIn("Historical Memory Usage", payload.get("rendered_report") or "")

    def test_mixed_metric_aggregation_does_not_merge_units(self) -> None:
        traces = [
            SimpleNamespace(
                completed_at="2026-05-01T10:00:00+00:00",
                metrics={"host_cpu_pct": 20.0, "container_cpu_pct": 35.0, "top_cpu_sql_cpu_s": 80.0},
            ),
            SimpleNamespace(
                completed_at="2026-05-02T10:00:00+00:00",
                metrics={"host_cpu_pct": 40.0, "container_cpu_pct": 45.0, "top_cpu_sql_cpu_s": 120.0},
            ),
        ]
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=None,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
            return_value=traces,
        ):
            payload = answer_history_metric_question("average cpu consumption", db_key="prod__db__1521__pdb1")
        report = payload.get("rendered_report") or ""
        self.assertIn("Average Host CPU", report)
        self.assertIn("Average Oracle CPU", report)
        self.assertIn("Average Top SQL CPU", report)
        self.assertNotIn("Average Host Memory", report)
        self.assertNotIn("Average value across requested metric fields", report)
        supporting = payload.get("supporting_data") or {}
        self.assertEqual(supporting.get("source"), "jsonl_fallback")
        fields = supporting.get("field_summaries") or []
        self.assertTrue(fields)
        first = fields[0]
        for key in ("sample_count", "latest", "current", "average_normal", "recent_average", "min", "max", "range", "state"):
            self.assertIn(key, first)

    def test_blocking_question_returns_blocking_summary(self) -> None:
        traces = [
            SimpleNamespace(completed_at="2026-04-20T02:24:00+00:00", metrics={"blocking_count": 0}),
            SimpleNamespace(completed_at="2026-04-21T02:24:00+00:00", metrics={"blocking_count": 1}),
            SimpleNamespace(completed_at="2026-04-22T02:24:00+00:00", metrics={"blocking_count": 1}),
        ]
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=None,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
            return_value=traces,
        ), patch(
            "odb_autodba.services.autodba_service.detect_history_metric_question",
            return_value={
                "metric_family": "blocking",
                "aggregation": "any",
                "requested_fields": ["blocking_count"],
                "time_window": {"label": "all"},
            },
        ):
            payload = answer_history_metric_question("blocking history", db_key="prod__db__1521__pdb1")
        report = payload.get("rendered_report") or ""
        self.assertIn("Blocking detected in 2/3 runs (66.7%)", report)
        self.assertIn("Max blocking sessions: 1", report)
        self.assertIn("Last occurrence: 2026-04-22 02:24 UTC", report)

    def test_average_cpu_uses_index_first_when_available(self) -> None:
        index_payload = {
            "ok": True,
            "confident": True,
            "route": {"metric_family": "cpu", "aggregation": "avg"},
            "summary": "Historical cpu consumption resolved from index with 10 sample(s) across 5 run(s).",
            "rendered_report": "# Historical CPU Consumption\n\nSummary:\nAverage Host CPU: 22.00%\nAverage Oracle CPU: 30.00%\nAverage Top SQL CPU: 12.00 sec\n",
            "supporting_data": {
                "metric_family": "cpu",
                "aggregation": "avg",
                "sample_count": 10,
                "source": "index",
            },
        }
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=index_payload,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
        ) as traces_reader:
            payload = answer_history_metric_question("average cpu consumption", db_key="prod__db__1521__pdb1")
        traces_reader.assert_not_called()
        self.assertEqual(payload.get("source"), "index")
        self.assertIn("Average Host CPU", payload.get("rendered_report") or "")
        self.assertIn("Average Oracle CPU", payload.get("rendered_report") or "")
        self.assertIn("Average Top SQL CPU", payload.get("rendered_report") or "")

    def test_average_memory_uses_index_first_when_available(self) -> None:
        index_payload = {
            "ok": True,
            "confident": True,
            "route": {"metric_family": "memory", "aggregation": "avg"},
            "summary": "Historical memory utilization resolved from index with 8 sample(s) across 4 run(s).",
            "rendered_report": "# Historical Memory Utilization\n\nSummary:\nAverage Host Memory: 68.00%\nAverage Oracle Memory: 44.00%\n",
            "supporting_data": {
                "metric_family": "memory",
                "aggregation": "avg",
                "sample_count": 8,
                "source": "index",
            },
        }
        with patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod__db__1521__pdb1"),
        ), patch(
            "odb_autodba.history.jsonl_service.JsonlHistoryService.answer_history_question_from_index",
            return_value=index_payload,
        ), patch(
            "odb_autodba.services.autodba_service.read_health_run_traces",
        ) as traces_reader:
            payload = answer_history_metric_question("average memory utilization", db_key="prod__db__1521__pdb1")
        traces_reader.assert_not_called()
        self.assertEqual(payload.get("source"), "index")
        self.assertIn("Average Host Memory", payload.get("rendered_report") or "")
        self.assertIn("Average Oracle Memory", payload.get("rendered_report") or "")


if __name__ == "__main__":
    unittest.main()
