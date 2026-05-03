from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.mcp.jobs import create_job, get_job, run_job, update_job


class McpJobsTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def test_create_job_writes_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("health_check", db_key="db1", payload={"x": 1})
                path = Path(td) / f"{job['job_id']}.json"
                self.assertTrue(path.exists())
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(payload.get("job_type"), "health_check")
                self.assertEqual(payload.get("status"), "pending")

    def test_update_job_changes_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("health_check", db_key="db1")
                updated = update_job(job["job_id"], status="running")
                self.assertEqual(updated.get("status"), "running")
                payload = get_job(job["job_id"])
                self.assertEqual((payload or {}).get("status"), "running")

    def test_run_job_completes_health_with_mocked_service(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("health_check", db_key="db1")
                with patch(
                    "odb_autodba.mcp.jobs.run_health_check",
                    return_value={
                        "summary": "ok",
                        "supporting_data": {},
                        "db_key": "db1",
                        "rendered_report": "# full report\n\n## 🔴 Root Cause Analysis",
                        "root_cause": {"category": "CPU pressure", "confidence": "MEDIUM", "evidence": ["x"], "reasoning": "y", "impacted_components": ["z"]},
                        "correlation": {
                            "primary_cause": {"category": "cpu_pressure", "confidence": "MEDIUM", "score": 0.55, "evidence": ["cpu signal"]},
                            "sources_used": {"health_runs_used": 2},
                            "score_components": {},
                        },
                    },
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
                self.assertEqual(payload.get("status"), "completed")
                self.assertIsInstance(payload.get("result"), dict)
                self.assertEqual((payload.get("result") or {}).get("summary"), "ok")
                self.assertIn("## 🔴 Root Cause Analysis", (payload.get("result") or {}).get("rendered_report") or "")
                self.assertIsInstance((payload.get("result") or {}).get("root_cause"), dict)
                self.assertIsInstance((payload.get("result") or {}).get("correlation"), dict)

    def test_run_job_marks_failed_on_exception(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("health_check", db_key="db1")
                with patch("odb_autodba.mcp.jobs.run_health_check", side_effect=RuntimeError("password=abc")):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
                self.assertEqual(payload.get("status"), "failed")
                self.assertEqual(payload.get("error_type"), "RuntimeError")
                self.assertNotIn("abc", str(payload.get("error") or ""))

    def test_run_job_completes_active_sessions_with_mocked_service(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("active_sessions", db_key="db1")
                with patch(
                    "odb_autodba.mcp.jobs.get_active_sessions",
                    return_value={
                        "summary": "active sessions ok",
                        "supporting_data": {},
                        "db_key": "db1",
                        "ok": True,
                        "rendered_report": "## Active Sessions Table",
                    },
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
                self.assertEqual(payload.get("status"), "completed")
                self.assertEqual((payload.get("result") or {}).get("summary"), "active sessions ok")
                self.assertEqual((payload.get("result") or {}).get("rendered_report"), "## Active Sessions Table")

    def test_job_json_does_not_store_password(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "x", "password": "secret"})
                path = Path(td) / f"{job['job_id']}.json"
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("secret", text)
                self.assertIn("***REDACTED***", text)

    def test_sql_id_analysis_job_dispatch_calls_service_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("sql_id_analysis", db_key="db1", payload={"sql_id": "daxra005nhfz2"})
                with patch(
                    "odb_autodba.mcp.jobs.analyze_sql_id",
                    return_value={
                        "ok": True,
                        "db_key": "db1",
                        "sql_id": "daxra005nhfz2",
                        "summary": "SQL_ID daxra005nhfz2 deep dive completed.",
                        "rendered_report": "# SQL_ID Deep Dive — daxra005nhfz2",
                        "supporting_data": {"sql_id": "daxra005nhfz2"},
                    },
                ) as analyzer:
                    run_job(job["job_id"])
                analyzer.assert_called_once_with("daxra005nhfz2", db_key="db1")
                payload = get_job(job["job_id"]) or {}
                result = payload.get("result") or {}
                self.assertEqual(payload.get("status"), "completed")
                self.assertEqual(result.get("sql_id"), "daxra005nhfz2")
                self.assertIn("SQL_ID Deep Dive", str(result.get("rendered_report") or ""))

    def test_history_metric_job_dispatch_calls_service(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("history_metric_question", db_key="db1", payload={"question": "average cpu from history"})
                with patch(
                    "odb_autodba.mcp.jobs.answer_history_metric_question",
                    return_value={
                        "ok": True,
                        "db_key": "db1",
                        "summary": "History source: raw JSONL only.",
                        "rendered_report": "# Historical CPU Consumption",
                        "supporting_data": {"domain": "cpu", "source": "index"},
                        "source": "index",
                    },
                ) as history_metric:
                    run_job(job["job_id"])
                history_metric.assert_called_once_with("average cpu from history", db_key="db1")
                payload = get_job(job["job_id"]) or {}
                self.assertEqual(payload.get("status"), "completed")
                self.assertEqual(payload.get("job_type"), "history_metric_question")
                result = payload.get("result") or {}
                self.assertEqual(result.get("source"), "index")
                self.assertEqual((result.get("supporting_data") or {}).get("source"), "index")

    def test_awr_analysis_job_dispatch_calls_service(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("awr_analysis", db_key="db1", payload={"question": "analyze awr"})
                with patch(
                    "odb_autodba.mcp.jobs.analyze_awr",
                    return_value={
                        "ok": True,
                        "db_key": "db1",
                        "summary": "AWR analysis complete",
                        "rendered_report": "# Oracle Historical Trend Analysis",
                        "supporting_data": {"domain": "awr"},
                    },
                ) as awr_mock:
                    run_job(job["job_id"])
                awr_mock.assert_called_once_with("analyze awr", db_key="db1")
                payload = get_job(job["job_id"]) or {}
                self.assertEqual(payload.get("status"), "completed")
                self.assertEqual(payload.get("job_type"), "awr_analysis")

    def test_blocking_analysis_job_dispatch_calls_service(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("blocking_analysis", db_key="db1")
                with patch(
                    "odb_autodba.mcp.jobs.analyze_blocking_sessions",
                    return_value={
                        "ok": True,
                        "db_key": "db1",
                        "summary": "Blocking analysis completed.",
                        "rendered_report": "# Blocking Lock Analysis",
                        "supporting_data": {"blocking_rows": []},
                    },
                ) as blocking_mock:
                    run_job(job["job_id"])
                blocking_mock.assert_called_once_with(db_key="db1")
                payload = get_job(job["job_id"]) or {}
                self.assertEqual(payload.get("status"), "completed")
                self.assertEqual(payload.get("job_type"), "blocking_analysis")

    def test_investigation_job_hydrates_rendered_report_from_trace_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_trace.jsonl"
            trace_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "event_type": "investigation.start",
                                "payload": {"problem_statement": "What is the size of the database?"},
                            }
                        ),
                        json.dumps(
                            {
                                "event_type": "investigation.step",
                                "payload": {
                                    "step_number": 1,
                                    "goal": "Measure size",
                                    "sql": "select 1 as total_gb from dual",
                                    "status": "success",
                                    "row_count": 1,
                                    "result_preview": "Returned 1 row(s).",
                                    "result_rows": [{"total_gb": 1}],
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "event_type": "investigation.done",
                                "payload": {
                                    "likely_cause": "Requested inventory metric was collected.",
                                    "confidence": "HIGH",
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": td, "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "size?"})
                with patch(
                    "odb_autodba.mcp.jobs.run_ai_investigation",
                    return_value={
                        "ok": True,
                        "summary": "done",
                        "db_key": "db1",
                        "trace_path": str(trace_path),
                        "rendered_report": "",
                    },
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
                result = payload.get("result") or {}
                report_path = str(result.get("report_path") or "")
                self.assertTrue(report_path.endswith(f"investigation_{job['job_id']}.md"))
                self.assertIn("/runtime/databases/db1/exports/", report_path)
                self.assertTrue(Path(report_path).exists())

        self.assertEqual(payload.get("status"), "completed")
        self.assertIn("# AI Investigation Result", str(result.get("rendered_report") or ""))

    def test_investigation_job_hydrates_when_rendered_report_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_trace.jsonl"
            trace_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "event_type": "investigation.start",
                                "payload": {"problem_statement": "What is the size of the database?"},
                            }
                        ),
                        json.dumps(
                            {
                                "event_type": "investigation.step",
                                "payload": {
                                    "step_number": 1,
                                    "goal": "Measure size",
                                    "sql": "select 1 as total_gb from dual",
                                    "status": "success",
                                    "row_count": 1,
                                    "result_preview": "Returned 1 row(s).",
                                    "result_rows": [{"total_gb": 1}],
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "event_type": "investigation.done",
                                "payload": {
                                    "likely_cause": "Requested inventory metric was collected.",
                                    "confidence": "HIGH",
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": td, "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "size?"})
                with patch(
                    "odb_autodba.mcp.jobs.run_ai_investigation",
                    return_value={
                        "ok": True,
                        "summary": "done",
                        "db_key": "db1",
                        "trace_path": str(trace_path),
                        "rendered_report": "# AI Investigation Report\n\n## Investigation Summary\nShort summary only.",
                    },
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
                result = payload.get("result") or {}
                report_text = str(result.get("rendered_report") or "")
                self.assertIn("## SQL Executed", report_text)
                self.assertIn("## Result", report_text)
                self.assertIn("## 🔵 Investigation Conclusion", report_text)
                report_path = str(result.get("report_path") or "")
                self.assertTrue(Path(report_path).exists())
                self.assertEqual(Path(report_path).read_text(encoding="utf-8"), report_text)

        self.assertEqual(payload.get("status"), "completed")


if __name__ == "__main__":
    unittest.main()
