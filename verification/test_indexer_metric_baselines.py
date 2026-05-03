from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from odb_autodba.rag.indexer import rebuild_database_planner_memory
from odb_autodba.rag.trace_store import read_database_planner_memory


class IndexerMetricBaselinesTests(unittest.TestCase):
    def _runtime_root(self, td: str) -> Path:
        return Path(td) / "runtime" / "databases"

    def _append_run(
        self,
        *,
        td: str,
        db_key: str,
        run_id: str,
        completed_at: str,
        metrics: dict,
        overall_status: str = "OK",
    ) -> None:
        path = self._runtime_root(td) / db_key / "traces" / "health_runs.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "run_id": run_id,
            "recorded_at": completed_at,
            "completed_at": completed_at,
            "database_name": "FREE",
            "overall_status": overall_status,
            "summary": "run",
            "metrics": metrics,
            "issues": [],
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    def test_metric_baselines_include_planner_memory_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td, unittest.mock.patch.dict(
            os.environ,
            {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))},
            clear=False,
        ):
            self._append_run(
                td=td,
                db_key="db1",
                run_id="r1",
                completed_at="2026-05-01T00:00:00Z",
                metrics={"host_cpu_pct": 20.0, "top_cpu_sql_cpu_s": 40.0},
                overall_status="OK",
            )
            self._append_run(
                td=td,
                db_key="db1",
                run_id="r2",
                completed_at="2026-05-02T00:00:00Z",
                metrics={"host_cpu_pct": 90.0, "top_cpu_sql_cpu_s": 200.0},
                overall_status="WARNING",
            )
            rebuild_database_planner_memory(db_key="db1")
            rows = read_database_planner_memory(db_key="db1")

        self.assertTrue(rows)
        baselines = rows[0].database_behavior_profile.metric_baselines
        self.assertIn("host_cpu_pct", baselines)
        payload = baselines["host_cpu_pct"]
        for key in (
            "sample_count",
            "average_normal",
            "recent_average",
            "min",
            "max",
            "latest",
            "state",
            "pressure_run_count",
            "stable_run_count",
            "recent_values",
            "first_seen",
            "last_seen",
        ):
            self.assertIn(key, payload)

    def test_db_key_scoped_baselines_do_not_cross_contaminate(self) -> None:
        with tempfile.TemporaryDirectory() as td, unittest.mock.patch.dict(
            os.environ,
            {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))},
            clear=False,
        ):
            self._append_run(
                td=td,
                db_key="db_a",
                run_id="a1",
                completed_at="2026-05-01T00:00:00Z",
                metrics={"host_cpu_pct": 20.0},
            )
            self._append_run(
                td=td,
                db_key="db_b",
                run_id="b1",
                completed_at="2026-05-01T00:00:00Z",
                metrics={"host_cpu_pct": 99.0},
            )
            rebuild_database_planner_memory(db_key="db_a")
            rebuild_database_planner_memory(db_key="db_b")
            rows_a = read_database_planner_memory(db_key="db_a")
            rows_b = read_database_planner_memory(db_key="db_b")

        self.assertTrue(rows_a)
        self.assertTrue(rows_b)
        latest_a = rows_a[0].database_behavior_profile.metric_baselines["host_cpu_pct"]["latest"]
        latest_b = rows_b[0].database_behavior_profile.metric_baselines["host_cpu_pct"]["latest"]
        self.assertEqual(latest_a, 20.0)
        self.assertEqual(latest_b, 99.0)


if __name__ == "__main__":
    unittest.main()
