from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.agents.correlation_engine import correlate_root_cause_from_traces, render_correlation_section
from odb_autodba.mcp.jobs import create_job, get_job, run_job
from odb_autodba.models.schemas import PlannerResponse
from odb_autodba.services.autodba_service import run_health_check


class CorrelationEngineTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def _runtime_root(self, td: str) -> Path:
        return Path(td) / "runtime" / "databases"

    def _trace_file(self, td: str, db_key: str) -> Path:
        path = self._runtime_root(td) / db_key / "traces" / "health_runs.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _append_run(
        self,
        *,
        td: str,
        db_key: str,
        run_id: str,
        completed_at: str,
        metrics: dict,
        issues: list[dict] | None = None,
        summary: str = "run",
    ) -> None:
        row = {
            "run_id": run_id,
            "recorded_at": completed_at,
            "completed_at": completed_at,
            "database_name": "DB1",
            "overall_status": "WARNING" if issues else "OK",
            "summary": summary,
            "metrics": metrics,
            "issues": issues or [],
        }
        path = self._trace_file(td, db_key)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    def _write_recurring_index(self, *, td: str, db_key: str, rows: list[dict]) -> None:
        path = self._runtime_root(td) / db_key / "indexes" / "recurring_issues.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    def _write_history_index(self, *, td: str, db_key: str, rows: list[dict]) -> None:
        path = self._runtime_root(td) / db_key / "indexes" / "history_indexing.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    def test_reads_only_db_key_scoped_runtime_path(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(
                td=td,
                db_key="db_a",
                run_id="a1",
                completed_at="2026-05-01T01:00:00Z",
                metrics={"host_cpu_pct": 20.0, "blocking_count": 0},
                issues=[{"category": "sql", "title": "Top SQL", "severity": "WARNING", "description": "sql heavy"}],
            )
            self._append_run(
                td=td,
                db_key="db_b",
                run_id="b1",
                completed_at="2026-05-01T01:00:00Z",
                metrics={"host_cpu_pct": 90.0, "blocking_count": 3},
                issues=[{"category": "blocking", "title": "Lock waits", "severity": "CRITICAL", "description": "blockers"}],
            )
            corr = correlate_root_cause_from_traces("db_a")

        self.assertEqual(corr.get("db_key"), "db_a")
        self.assertIn("/db_a/traces", str((corr.get("sources_used") or {}).get("traces_dir") or ""))
        self.assertNotEqual(((corr.get("primary_cause") or {}).get("category")), "blocking_lock")

    def test_works_with_health_runs_jsonl_only(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(
                td=td,
                db_key="db1",
                run_id="r1",
                completed_at="2026-05-01T01:00:00Z",
                metrics={"host_cpu_pct": 30.0, "custom_x": 9.0},
                issues=[],
            )
            corr = correlate_root_cause_from_traces("db1")

        self.assertTrue(corr.get("ok"))
        self.assertGreater((corr.get("sources_used") or {}).get("health_runs_used", 0), 0)

    def test_does_not_require_db_connection(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(
                td=td,
                db_key="db1",
                run_id="r1",
                completed_at="2026-05-01T01:00:00Z",
                metrics={"host_cpu_pct": 25.0},
            )
            corr = correlate_root_cause_from_traces("db1")
        self.assertTrue(corr.get("ok"))

    def test_generic_numeric_metric_discovery_works(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(td=td, db_key="db1", run_id="r1", completed_at="2026-05-01T01:00:00Z", metrics={"quantum_latency_ms": 2.0})
            self._append_run(td=td, db_key="db1", run_id="r2", completed_at="2026-05-02T01:00:00Z", metrics={"quantum_latency_ms": 8.0})
            corr = correlate_root_cause_from_traces("db1")

        metric_paths = {item.get("path") for item in (corr.get("metric_signals") or [])}
        self.assertIn("metrics.quantum_latency_ms", metric_paths)

    def test_new_unknown_numeric_metric_is_trended_and_included(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(td=td, db_key="db1", run_id="r1", completed_at="2026-05-01T01:00:00Z", metrics={"foo_bar_signal": 1.0})
            self._append_run(td=td, db_key="db1", run_id="r2", completed_at="2026-05-02T01:00:00Z", metrics={"foo_bar_signal": 5.0})
            corr = correlate_root_cause_from_traces("db1")

        row = next((item for item in (corr.get("metric_signals") or []) if item.get("path") == "metrics.foo_bar_signal"), None)
        self.assertIsNotNone(row)
        self.assertEqual(row.get("family"), "unclassified_metric")

    def test_removed_missing_metric_does_not_crash_and_records_schema_observation(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(td=td, db_key="db1", run_id="r1", completed_at="2026-05-01T01:00:00Z", metrics={"disk_latency_ms": 10.0})
            self._append_run(td=td, db_key="db1", run_id="r2", completed_at="2026-05-02T01:00:00Z", metrics={"host_cpu_pct": 20.0})
            corr = correlate_root_cause_from_traces("db1")

        observations = corr.get("schema_observations") or {}
        missing = observations.get("metric_missing_in_latest") or []
        self.assertTrue(any("metrics.disk_latency_ms" == item for item in missing))

    def test_sql_issue_recurrence_produces_sql_signal(self) -> None:
        sql_issue = {"category": "sql", "title": "Top SQL high elapsed", "severity": "WARNING", "description": "sql pattern"}
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(td=td, db_key="db1", run_id="r1", completed_at="2026-05-01T01:00:00Z", metrics={"top_elapsed_sql_elapsed_s": 30.0}, issues=[sql_issue])
            self._append_run(td=td, db_key="db1", run_id="r2", completed_at="2026-05-02T01:00:00Z", metrics={"top_elapsed_sql_elapsed_s": 50.0}, issues=[sql_issue])
            corr = correlate_root_cause_from_traces("db1")

        self.assertIn(((corr.get("primary_cause") or {}).get("category")), {"sql_performance_pattern", "sql_regression", "object_or_stats_issue"})

    def test_blocking_issue_produces_blocking_lock_when_current_metric_exists(self) -> None:
        blocking = {"category": "blocking", "title": "Lock contention", "severity": "CRITICAL", "description": "blocking chains"}
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(td=td, db_key="db1", run_id="r1", completed_at="2026-05-01T01:00:00Z", metrics={"blocking_count": 2}, issues=[blocking])
            self._append_run(td=td, db_key="db1", run_id="r2", completed_at="2026-05-02T01:00:00Z", metrics={"blocking_count": 4}, issues=[blocking])
            corr = correlate_root_cause_from_traces("db1")

        self.assertEqual((corr.get("primary_cause") or {}).get("category"), "blocking_lock")

    def test_cpu_pressure_not_selected_when_cpu_low_and_only_sql_issue_exists(self) -> None:
        sql_issue = {"category": "sql", "title": "SQL heavy", "severity": "WARNING", "description": "top sql"}
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(
                td=td,
                db_key="db1",
                run_id="r1",
                completed_at="2026-05-01T01:00:00Z",
                metrics={"host_cpu_pct": 25.0, "top_cpu_sql_cpu_s": 120.0},
                issues=[sql_issue],
            )
            corr = correlate_root_cause_from_traces("db1")

        self.assertNotEqual((corr.get("primary_cause") or {}).get("category"), "cpu_pressure")

    def test_local_app_host_cpu_contradiction_reduces_cpu_confidence(self) -> None:
        cpu_issue = {"category": "cpu", "title": "CPU high", "severity": "CRITICAL", "description": "cpu"}
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(
                td=td,
                db_key="db1",
                run_id="r1",
                completed_at="2026-05-01T01:00:00Z",
                metrics={"host_cpu_pct": 95.0, "host_check_scope": "local_app_host", "top_cpu_sql_cpu_s": 2.0},
                issues=[cpu_issue],
            )
            corr = correlate_root_cause_from_traces("db1")

        contradictions = [str(item) for item in (corr.get("contradictions") or [])]
        self.assertTrue(any("local_app_host" in item for item in contradictions))
        self.assertNotEqual((corr.get("primary_cause") or {}).get("confidence"), "HIGH")

    def test_historical_recurrence_does_not_override_stronger_current_evidence(self) -> None:
        blocking = {"category": "blocking", "title": "Lock contention", "severity": "CRITICAL", "description": "blockers"}
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(td=td, db_key="db1", run_id="r1", completed_at="2026-05-01T01:00:00Z", metrics={"blocking_count": 3}, issues=[blocking])
            self._append_run(td=td, db_key="db1", run_id="r2", completed_at="2026-05-02T01:00:00Z", metrics={"blocking_count": 4}, issues=[blocking])
            self._write_recurring_index(
                td=td,
                db_key="db1",
                rows=[
                    {
                        "fingerprint": "x",
                        "database_name": "DB1",
                        "category": "generic",
                        "title": "old recurrence",
                        "severity": "WARNING",
                        "first_seen": "2026-04-01T00:00:00Z",
                        "last_seen": "2026-05-01T00:00:00Z",
                        "run_count": 100,
                        "unhealthy_run_count": 80,
                    }
                ],
            )
            corr = correlate_root_cause_from_traces("db1")

        self.assertEqual((corr.get("primary_cause") or {}).get("category"), "blocking_lock")

    def test_output_includes_sources_used_and_score_components(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(td=td, db_key="db1", run_id="r1", completed_at="2026-05-01T01:00:00Z", metrics={"host_cpu_pct": 30.0})
            corr = correlate_root_cause_from_traces("db1")

        self.assertIsInstance(corr.get("sources_used"), dict)
        self.assertIsInstance(corr.get("score_components"), dict)

    def test_correlation_adapts_to_context(self) -> None:
        cpu_issue = {"category": "cpu", "title": "CPU pressure", "severity": "WARNING", "description": "cpu high"}
        blocking_issue = {"category": "blocking", "title": "Lock waits", "severity": "WARNING", "description": "blocking"}
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(
                td=td,
                db_key="db1",
                run_id="r1",
                completed_at="2026-05-01T01:00:00Z",
                metrics={"host_cpu_pct": 92.0, "blocking_count": 3},
                issues=[cpu_issue, blocking_issue],
            )
            corr_cpu = correlate_root_cause_from_traces("db1", context="cpu")
            corr_blocking = correlate_root_cause_from_traces("db1", context="blocking")

        self.assertEqual((corr_cpu.get("primary_cause") or {}).get("category"), "cpu_pressure")
        self.assertEqual((corr_blocking.get("primary_cause") or {}).get("category"), "blocking_lock")

    def test_rendered_report_contains_root_cause_correlation_section(self) -> None:
        corr = {
            "primary_cause": {"category": "inconclusive", "label": "Inconclusive", "confidence": "LOW", "score": 0.1, "evidence": []},
            "contributing_factors": [],
            "contradictions": [],
            "missing_evidence": [],
            "recommended_next_steps": [],
            "sources_used": {"health_runs_used": 1, "history_index_entry_count": 0, "recurring_issue_index_count": 0},
        }
        rendered = render_correlation_section(corr)
        self.assertIn("## 🔴 Root Cause Correlation", rendered)

    def test_service_result_includes_correlation(self) -> None:
        response = PlannerResponse(
            mode="full_health_report",
            summary="Oracle health check completed.",
            body_markdown="# report",
            supporting_data={"host_check": {"host_check_scope": "local_app_host"}},
        )
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td))}, clear=False):
            self._append_run(td=td, db_key="db1", run_id="r1", completed_at="2026-05-01T01:00:00Z", metrics={"host_cpu_pct": 20.0})
            with patch("odb_autodba.services.autodba_service.PlannerAgent.handle_message", return_value=response), patch(
                "odb_autodba.services.autodba_service.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                payload = run_health_check(db_key="db1")

        self.assertIsInstance(payload.get("correlation"), dict)
        self.assertIn("## 🔴 Root Cause Correlation", str(payload.get("rendered_report") or ""))

    def test_mcp_job_result_preserves_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {
                    "ODB_AUTODBA_JOBS_DIR": td,
                    "ODB_AUTODBA_RUNTIME_ROOT": str(self._runtime_root(td)),
                },
                clear=False,
            ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
                job = create_job("health_check", db_key="db1")
                with patch(
                    "odb_autodba.mcp.jobs.run_health_check",
                    return_value={
                        "ok": True,
                        "db_key": "db1",
                        "summary": "ok",
                        "rendered_report": "# report\n\n## 🔴 Root Cause Correlation",
                        "supporting_data": {},
                        "correlation": {
                            "primary_cause": {"category": "inconclusive", "confidence": "LOW", "score": 0.0, "evidence": []},
                            "sources_used": {"health_runs_used": 0},
                            "score_components": {},
                        },
                    },
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}

        result = payload.get("result") or {}
        self.assertIsInstance(result.get("correlation"), dict)
        self.assertIn("sources_used", result.get("correlation") or {})


if __name__ == "__main__":
    unittest.main()
