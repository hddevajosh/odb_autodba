from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.mcp.jobs import create_job, get_job, run_job, update_job
from odb_autodba.models.schemas import InvestigationReport, InvestigationStep, InvestigationStepDecision, SQLExecutionResult


class McpJobsTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    @staticmethod
    def _investigation_report(problem_statement: str) -> InvestigationReport:
        return InvestigationReport(
            problem_statement=problem_statement,
            summary="Ran 1 logical investigation step(s) with 1 SQL execution(s).",
            likely_cause="Collected requested evidence.",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Collect evidence",
                    sql="select 1 as sample_col from dual",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["sample_col"],
                    result_rows=[{"sample_col": 1}],
                )
            ],
        )

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

    def test_job_json_redacts_secret_like_nested_keys_but_preserves_password_env(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job(
                    "health_check",
                    db_key="db1",
                    payload={
                        "api_key": "secret-api",
                        "nested": {"private_key": "secret-private", "token_value": "secret-token"},
                        "target": {
                            "environment": "dev",
                            "host": "db",
                            "port": 1521,
                            "username": "system",
                            "service_name": "PDB1",
                            "password_env": "ORACLE_PASSWORD",
                        },
                    },
                )
                text = (Path(td) / f"{job['job_id']}.json").read_text(encoding="utf-8")
        self.assertNotIn("secret-api", text)
        self.assertNotIn("secret-private", text)
        self.assertNotIn("secret-token", text)
        self.assertIn("ORACLE_PASSWORD", text)

    def test_job_result_remains_json_serializable_after_sanitization(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("health_check", db_key="db1")
                update_job(job["job_id"], result={"items": [{"secret_token": "abc", "value": object()}]})
                payload = get_job(job["job_id"]) or {}
                text = json.dumps(payload, ensure_ascii=True, default=str)
        self.assertNotIn("abc", text)
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

    def test_investigation_job_completed_returns_inline_report_text(self) -> None:
        with tempfile.TemporaryDirectory() as td:
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
                        "problem_statement": "What is the size of the database?",
                        "trace_path": "/tmp/inv_trace.jsonl",
                        "rendered_report": "# AI Investigation Result\n\n## Question\nWhat is the size of the database?\n\n## Summary\ndone\n\n## Result\nx",
                    },
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
                result = payload.get("result") or {}
                self.assertTrue(str(result.get("report_text") or "").strip())
                self.assertEqual(str(result.get("report_text") or ""), str(result.get("rendered_report") or ""))
                self.assertEqual(str(result.get("problem_statement") or ""), "What is the size of the database?")
                self.assertEqual(str(result.get("status") or ""), "completed")
                self.assertEqual(str(result.get("error_type") or ""), "")
                self.assertTrue(str(result.get("investigation_id") or "").strip())
        self.assertEqual(payload.get("status"), "completed")

    def test_investigation_job_does_not_hydrate_trace_when_inline_report_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runtime_root = Path(td) / "runtime" / "databases"
            trace_path = Path(td) / "investigation_trace.jsonl"
            trace_path.write_text('{"event_type":"investigation.start","payload":{"problem_statement":"q"}}\n', encoding="utf-8")
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(runtime_root)},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "q"})
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
                result = payload.get("result") if isinstance(payload.get("result"), dict) else {}

            self.assertEqual(payload.get("status"), "completed")
            self.assertEqual(str(result.get("status") or ""), "completed")
            self.assertEqual(str(result.get("job_id") or ""), job["job_id"])
            self.assertTrue(str(result.get("investigation_id") or "").strip())
            self.assertEqual(str(result.get("thread_memory_enabled")), "False")
            self.assertEqual(str(result.get("error_type") or ""), "")
            self.assertTrue(str(result.get("trace_path") or "").strip())
            self.assertEqual(
                str(result.get("report_text") or ""),
                "# AI Investigation Report\n\n## Investigation Summary\nShort summary only.",
            )

            report_path = Path(str(result.get("report_path") or ""))
            self.assertEqual(
                report_path,
                runtime_root / "db1" / "exports" / f"investigation_{job['job_id']}.md",
            )
            self.assertTrue(report_path.exists())
            self.assertIn("Short summary only.", report_path.read_text(encoding="utf-8"))

    def test_report_markdown_write_failure_keeps_investigation_completed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "q"})
                with patch(
                    "odb_autodba.mcp.jobs.run_ai_investigation",
                    return_value={
                        "ok": True,
                        "summary": "done",
                        "db_key": "db1",
                        "rendered_report": "# AI Investigation Result\n\n## Question\nq",
                        "trace_path": "",
                    },
                ), patch(
                    "odb_autodba.mcp.jobs._write_investigation_export",
                    side_effect=OSError("disk full"),
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}

        self.assertEqual(payload.get("status"), "completed")
        result = payload.get("result") or {}
        self.assertTrue(str(result.get("report_text") or "").strip())
        self.assertFalse(str(result.get("report_path") or "").strip())
        self.assertTrue(any("investigation_report_export_write_failed" in str(item) for item in (result.get("warnings") or [])))

    def test_completed_investigation_missing_inline_report_fails_result_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "q"})
                with patch(
                    "odb_autodba.mcp.jobs.run_ai_investigation",
                    return_value={"ok": True, "summary": "done", "db_key": "db1", "rendered_report": "", "report_text": "", "trace_path": ""},
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}

        self.assertEqual(payload.get("status"), "failed")
        self.assertEqual(payload.get("error_type"), "investigation_result_error")
        self.assertIn("report_text was missing", str(payload.get("error") or "").lower())

    def test_completed_investigation_missing_inline_report_hydrates_from_trace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_trace.jsonl"
            events = [
                {
                    "event_type": "investigation.start",
                    "payload": {"problem_statement": "help me investigate blocking lock which is present in this database?"},
                },
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 1,
                        "goal": "Identify current blocking sessions",
                        "sql": "select blocking_session, sid as blocked_sid from v$session where blocking_session is not null",
                        "status": "success",
                        "row_count": 1,
                        "result_columns": ["blocking_session", "blocked_sid"],
                        "result_rows": [{"blocking_session": 601, "blocked_sid": 812}],
                    },
                },
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 2,
                        "goal": "Identify locked object",
                        "sql": "select owner, object_name from dba_objects where object_id = 42",
                        "status": "success",
                        "row_count": 1,
                        "result_columns": ["owner", "object_name"],
                        "result_rows": [{"owner": "APP", "object_name": "ORDERS"}],
                    },
                },
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 3,
                        "goal": "Retrieve SQL text for blocker",
                        "sql": "select sql_id, sql_text from v$sql where sql_id = 'abcd1234'",
                        "status": "success",
                        "row_count": 1,
                        "result_columns": ["sql_id", "sql_text"],
                        "result_rows": [{"sql_id": "abcd1234", "sql_text": "select * from orders"}],
                    },
                },
                {
                    "event_type": "investigation.conclusion",
                    "payload": {
                        "likely_cause": "Blocking lock evidence collected.",
                        "sql_execution_count": 3,
                        "termination_reason": "evidence_complete",
                    },
                },
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "q"})
                with patch(
                    "odb_autodba.mcp.jobs.run_ai_investigation",
                    return_value={"ok": True, "summary": "done", "db_key": "db1", "rendered_report": "", "report_text": "", "trace_path": str(trace_path)},
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}

        self.assertEqual(payload.get("status"), "completed")
        result = payload.get("result") or {}
        rendered = str(result.get("report_text") or "")
        self.assertIn("## SQL Evidence Collected", rendered)
        self.assertIn("### Step 1 — Identify current blocking sessions", rendered)
        self.assertIn("### Step 2 — Identify locked object", rendered)
        self.assertIn("### Step 3 — Retrieve SQL text for blocker", rendered)
        self.assertIn("ORDERS", rendered)
        self.assertIn("Blocking lock evidence collected.", rendered)
        self.assertNotIn("```json", rendered)

    def test_investigation_payload_ok_false_is_recorded_as_failed_job(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "q"})
                with patch(
                    "odb_autodba.mcp.jobs.run_ai_investigation",
                    return_value={"ok": False, "summary": "Investigation failed.", "error_type": "ValueError", "error": "boom"},
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
        self.assertEqual(payload.get("status"), "failed")
        self.assertEqual(payload.get("error_type"), "ValueError")
        self.assertIsInstance(payload.get("result"), dict)

    def test_investigation_job_accepts_problem_statement_payload_alias(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            captured: dict[str, str] = {}
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"problem_statement": "List all the tables in database please?"})

                def _fake_investigation(question: str, **_: object) -> dict[str, object]:
                    captured["question"] = question
                    return {
                        "ok": True,
                        "summary": "done",
                        "db_key": "db1",
                        "rendered_report": "# AI Investigation Result\n\n## Question\nList all the tables in database please?\n\n## Summary\nx\n\n## Result\nx\n\n## SQL Steps Run\n```sql\nselect 1 from dual\n```",
                        "trace_path": "",
                    }

                with patch("odb_autodba.mcp.jobs.run_ai_investigation", side_effect=_fake_investigation):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
        self.assertEqual(payload.get("status"), "completed")
        self.assertEqual(captured.get("question"), "List all the tables in database please?")

    def test_mcp_investigation_does_not_call_thread_memory_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ), patch(
                "odb_autodba.services.autodba_service.get_oracle_target",
                return_value=self._Target("db1"),
            ), patch(
                "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
                return_value=self._investigation_report("List all schemas and tables"),
            ):
                job = create_job(
                    "investigation",
                    db_key="db1",
                    payload={"question": "List all schemas and tables", "thread_id": "invth_legacy", "continue_context": True},
                )
                run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
        self.assertEqual(payload.get("status"), "completed")
        self.assertEqual(((payload.get("result") or {}).get("thread_memory_enabled")), False)

    def test_mcp_investigation_trace_write_failure_keeps_job_completed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {
                    "ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"),
                    "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases"),
                    "OPENAI_API_KEY": "",
                },
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ), patch(
                "odb_autodba.services.autodba_service.get_oracle_target",
                return_value=self._Target("db1"),
            ), patch(
                "odb_autodba.agents.investigation_agent.get_oracle_target",
                return_value=self._Target("db1"),
            ), patch(
                "odb_autodba.agents.investigation_agent.append_investigation_event",
                side_effect=OSError("trace volume is read-only"),
            ), patch(
                "odb_autodba.agents.investigation_agent.InvestigationAgent._next_step_decision",
                side_effect=[
                    (
                        InvestigationStepDecision(
                            next_action="run_sql",
                            goal="Collect evidence",
                            sql="select 1 as sample_col from dual",
                            confidence=0.7,
                        ),
                        "",
                    ),
                    (
                        InvestigationStepDecision(
                            next_action="conclude",
                            goal="Finalize",
                            final_answer="Collected requested evidence.",
                            confidence=0.8,
                            is_final=True,
                        ),
                        "",
                    ),
                ],
            ), patch(
                "odb_autodba.agents.investigation_agent.execute_investigation_sql",
                return_value=SQLExecutionResult(
                    status="success",
                    elapsed_ms=5,
                    columns=["sample_col"],
                    rows=[{"sample_col": 1}],
                    row_count=1,
                    truncated=False,
                ),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "List all schemas and tables"})
                run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
        self.assertEqual(payload.get("status"), "completed")
        result = payload.get("result") or {}
        self.assertTrue(str(result.get("report_text") or "").strip())
        self.assertEqual(str(result.get("error_type") or ""), "")

    def test_investigation_export_typeerror_is_recorded_as_warning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "q"})
                with patch(
                    "odb_autodba.mcp.jobs.run_ai_investigation",
                    return_value={
                        "ok": True,
                        "summary": "done",
                        "db_key": "db1",
                        "thread_id": "invth_x",
                        "trace_path": "/tmp/inv_trace.jsonl",
                        "rendered_report": "# AI Investigation Result\n\n## Question\nq\n\n## Summary\ns\n\n## Result\nr\n\n## SQL Steps Run\n```sql\nselect 1 from dual\n```",
                    },
                ), patch(
                    "odb_autodba.mcp.jobs._write_investigation_export",
                    side_effect=TypeError("not json serializable"),
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
        self.assertEqual(payload.get("status"), "completed")
        result = payload.get("result") or {}
        self.assertTrue(str(result.get("report_text") or "").strip())
        self.assertTrue(any("investigation_report_export_write_failed" in str(item) for item in (result.get("warnings") or [])))

    def test_investigation_completed_result_with_non_string_keys_still_serializes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {"ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"), "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases")},
                clear=False,
            ), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job("investigation", db_key="db1", payload={"question": "q"})
                with patch(
                    "odb_autodba.mcp.jobs.run_ai_investigation",
                    return_value={
                        "ok": True,
                        "summary": "done",
                        "db_key": "db1",
                        "trace_path": "",
                        "rendered_report": "# AI Investigation Result\n\n## Question\nq\n\n## Summary\ns\n\n## Result\nr\n\n## SQL Steps Run\n```sql\nselect 1 from dual\n```",
                        "supporting_data": {1: "one", (2, 3): "two-three"},
                    },
                ):
                    run_job(job["job_id"])
                payload = get_job(job["job_id"]) or {}
        self.assertEqual(payload.get("status"), "completed")
        text = json.dumps(payload, ensure_ascii=True, default=str)
        self.assertIn("two-three", text)


if __name__ == "__main__":
    unittest.main()
