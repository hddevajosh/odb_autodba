from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.history.jsonl_service import JsonlHistoryService
from odb_autodba.models.schemas import TraceHealthRunRecord


def _trace(
    *,
    run_id: str,
    completed_at: str,
    trace_path: str | None,
    database_name: str = "UNITDB",
    summary: str = "summary",
    metrics: dict | None = None,
) -> TraceHealthRunRecord:
    return TraceHealthRunRecord(
        run_id=run_id,
        recorded_at=completed_at,
        completed_at=completed_at,
        database_name=database_name,
        trace_path=trace_path,
        summary=summary,
        metrics=metrics or {},
    )


class HistoryDedupeTests(unittest.TestCase):
    def test_duplicate_run_id_rows_dedupe_to_one(self) -> None:
        traces = [
            _trace(run_id="r1", completed_at="2026-05-01T00:00:00Z", trace_path="/tmp/a.json", metrics={"active_sessions": 2}),
            _trace(run_id="r1", completed_at="2026-05-01T00:00:00Z", trace_path="/tmp/a_dup.json", metrics={"active_sessions": 2}),
        ]
        with patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces):
            context = JsonlHistoryService().compare_recent_runs(limit=10, database_name="UNITDB")
        self.assertEqual(context.runs_scanned, 1)
        self.assertEqual(len(context.recent_runs), 1)

    def test_duplicate_trace_path_rows_dedupe_to_one(self) -> None:
        traces = [
            _trace(run_id="r1", completed_at="2026-05-01T00:00:00Z", trace_path="/tmp/same.json", metrics={"active_sessions": 2}),
            _trace(run_id="r2", completed_at="2026-04-30T23:00:00Z", trace_path="/tmp/same.json", metrics={"active_sessions": 3}),
        ]
        with patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces):
            context = JsonlHistoryService().compare_recent_runs(limit=10, database_name="UNITDB")
        self.assertEqual(context.runs_scanned, 1)
        self.assertEqual(len(context.recent_runs), 1)

    def test_richer_record_wins_when_duplicate_keys_exist(self) -> None:
        traces = [
            _trace(run_id="r-rich", completed_at="2026-04-30T10:00:00Z", trace_path="/tmp/rich.json", metrics={"top_cpu_sql_cpu_s": 88.0, "active_sessions": 5}),
            _trace(run_id="r-rich", completed_at="2026-05-01T10:00:00Z", trace_path="/tmp/lean.json", metrics={}),
        ]
        with patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces):
            runs = JsonlHistoryService().load_recent_runs(limit=10, database_name="UNITDB")
        self.assertEqual(len(runs), 1)
        self.assertIn("top_cpu_sql_cpu_s", runs[0].metrics)


if __name__ == "__main__":
    unittest.main()
