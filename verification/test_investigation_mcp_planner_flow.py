from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from odb_autodba.agents.investigation_agent import InvestigationAgent
from odb_autodba.mcp.jobs import create_job, get_job, run_job
from odb_autodba.models.schemas import InvestigationReport, InvestigationStep
from odb_autodba.services.autodba_service import run_ai_investigation


class InvestigationMcpPlannerFlowTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def _report(
        self,
        *,
        problem: str,
        plan_type: str,
        sql: str,
        planner_provider: str = "openai",
        fallback_used: bool = False,
        fallback_reason: str = "",
    ) -> InvestigationReport:
        return InvestigationReport(
            problem_statement=problem,
            summary="Ran 1 Oracle investigation step(s).",
            likely_cause="Requested read-only lookup evidence was collected successfully.",
            evidence=["Step 1 sample row captured."],
            recommended_next_actions=["Review returned rows and request additional filters if needed."],
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Collect requested evidence",
                    sql=sql,
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["sample_col"],
                    result_rows=[{"sample_col": "x"}],
                )
            ],
            plan_type=plan_type,
            planner_provider=planner_provider,
            planner_model="gpt-5.5",
            planner_elapsed_ms=25,
            planner_steps_count=1,
            planner_requested=True,
            fallback_used=fallback_used,
            fallback_reason=fallback_reason,
        )

    def test_mcp_investigation_job_uses_existing_investigation_planner(self) -> None:
        report = self._report(
            problem="list all the tables in this database please?",
            plan_type="inventory_read_only_lookup",
            sql="select owner, table_name from dba_tables fetch first 20 rows only",
        )
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"ODB_AUTODBA_JOBS_DIR": td},
            clear=False,
        ), patch(
            "odb_autodba.mcp.jobs.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ) as investigate:
            job = create_job("investigation", db_key="db1", payload={"question": "list all the tables in this database please?"})
            run_job(job["job_id"])
            payload = get_job(job["job_id"]) or {}
            self.assertEqual(payload.get("status"), "completed")
            investigate.assert_called_once()
            called_question = str(investigate.call_args.args[0] if investigate.call_args and investigate.call_args.args else "")
            self.assertEqual(called_question, "list all the tables in this database please?")

    def test_direct_and_mcp_investigation_use_same_planner_function(self) -> None:
        report = self._report(
            problem="What is the size of this database?",
            plan_type="inventory_read_only_lookup",
            sql="select round(sum(bytes)/1024/1024/1024,2) as total_gb from dba_data_files",
        )
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"ODB_AUTODBA_JOBS_DIR": td},
            clear=False,
        ), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.mcp.jobs.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ) as investigate:
            direct = run_ai_investigation("What is the size of this database?", db_key="db1")
            self.assertTrue(direct.get("ok"))
            job = create_job("investigation", db_key="db1", payload={"question": "What is the size of this database?"})
            run_job(job["job_id"])
            self.assertEqual(investigate.call_count, 2)

    def test_tables_lookup_uses_planner_sql_without_perf_fallback_and_no_correlation_section(self) -> None:
        report = self._report(
            problem="list all the tables in this database please?",
            plan_type="inventory_read_only_lookup",
            sql="select owner, table_name from dba_tables fetch first 20 rows only",
        )
        with patch("odb_autodba.services.autodba_service.get_oracle_target", return_value=self._Target("db1")), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ):
            payload = run_ai_investigation("list all the tables in this database please?", db_key="db1")
        rendered = str(payload.get("rendered_report") or "").lower()
        self.assertIn("dba_tables", rendered)
        self.assertNotIn("gv$session", rendered)
        self.assertNotIn("gv$sqlstats", rendered)
        self.assertNotIn("## 🔴 root cause correlation".lower(), rendered)
        self.assertNotIn("```json", rendered)
        self.assertIn("sample_col", rendered)
        self.assertEqual(((payload.get("supporting_data") or {}).get("planner_steps_count")), 1)

    def test_size_lookup_has_no_inconclusive_rca_or_correlation_sections(self) -> None:
        report = self._report(
            problem="What is the size of this database?",
            plan_type="inventory_read_only_lookup",
            sql="select round(sum(bytes)/1024/1024/1024,2) as total_gb from dba_data_files",
        )
        with patch("odb_autodba.services.autodba_service.get_oracle_target", return_value=self._Target("db1")), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ):
            payload = run_ai_investigation("What is the size of this database?", db_key="db1")
        rendered = str(payload.get("rendered_report") or "")
        self.assertNotIn("## 🔴 Root Cause Analysis", rendered)
        self.assertNotIn("## 🔴 Root Cause Correlation", rendered)
        self.assertNotIn("Collect ASH/AWR", rendered)

    def test_blocking_question_uses_current_blocking_sql_not_forced_historical_summary(self) -> None:
        report = self._report(
            problem="are there any blocking locks in this database?",
            plan_type="current_state",
            sql="select inst_id, sid, serial#, blocking_session, event, wait_class from gv$session where blocking_session is not null",
        )
        with patch("odb_autodba.services.autodba_service.get_oracle_target", return_value=self._Target("db1")), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ):
            payload = run_ai_investigation("are there any blocking locks in this database?", db_key="db1")
        rendered = str(payload.get("rendered_report") or "").lower()
        self.assertIn("blocking_session", rendered)
        self.assertNotIn("sql performance pattern", rendered)

    def test_diagnostic_question_can_include_root_cause_and_correlation_sections(self) -> None:
        report = self._report(
            problem="why is the database slow?",
            plan_type="diagnostic",
            sql="select sql_id, round(cpu_time/1e6,3) cpu_s from gv$sqlstats order by cpu_time desc fetch first 10 rows only",
        )
        with patch("odb_autodba.services.autodba_service.get_oracle_target", return_value=self._Target("db1")), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ):
            payload = run_ai_investigation("why is the database slow?", db_key="db1")
        rendered = str(payload.get("rendered_report") or "")
        self.assertIn("## 🔴 Root Cause Analysis", rendered)
        self.assertIn("## 🔴 Root Cause Correlation", rendered)

    def test_non_performance_planner_failure_does_not_silently_run_generic_perf_sql(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False), patch("odb_autodba.agents.investigation_agent.get_oracle_target", return_value=self._Target("db1")), patch(
            "odb_autodba.agents.investigation_agent.append_investigation_trace",
            return_value="inv_test",
        ), patch(
            "odb_autodba.agents.investigation_agent.investigation_trace_path",
            return_value=type("P", (), {"__str__": lambda self: "/tmp/inv_test.jsonl"})(),
        ):
            agent = InvestigationAgent(db_key="db1")
            with patch.object(
                agent,
                "_plan_steps",
                return_value={
                    "plan_type": "inventory_read_only_lookup",
                    "steps": [],
                    "planner_provider": "deterministic_fallback",
                    "planner_model": "deterministic",
                    "planner_elapsed_ms": 3,
                    "planner_steps_count": 0,
                    "fallback_used": True,
                    "fallback_reason": "planner_error",
                    "notes": ["AI planner could not generate safe SQL for this request."],
                },
            ):
                report = agent.investigate("list all the tables in this database please?", db_key="db1")
        self.assertEqual(len(report.steps), 0)
        self.assertIn("could not generate safe sql", report.likely_cause.lower())

    def test_invalid_planner_sql_is_not_executed_and_returns_validation_note(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False), patch("odb_autodba.agents.investigation_agent.get_oracle_target", return_value=self._Target("db1")), patch(
            "odb_autodba.agents.investigation_agent.append_investigation_trace",
            return_value="inv_test2",
        ), patch(
            "odb_autodba.agents.investigation_agent.investigation_trace_path",
            return_value=type("P", (), {"__str__": lambda self: "/tmp/inv_test2.jsonl"})(),
        ):
            agent = InvestigationAgent(db_key="db1")
            with patch.object(
                agent,
                "_plan_steps",
                return_value={
                    "plan_type": "inventory_read_only_lookup",
                    "steps": [],
                    "planner_provider": "deterministic_fallback",
                    "planner_model": "deterministic",
                    "planner_elapsed_ms": 4,
                    "planner_steps_count": 0,
                    "fallback_used": True,
                    "fallback_reason": "invalid_sql",
                    "notes": ["AI planner could not generate safe SQL for this request. (invalid_sql)"],
                },
            ):
                report = agent.investigate("list all the tables in this database please?", db_key="db1")
        self.assertEqual(len(report.steps), 0)
        self.assertEqual(report.fallback_reason, "")

    def test_investigation_logs_include_planner_fields(self) -> None:
        report = self._report(
            problem="What is the size of this database?",
            plan_type="inventory_read_only_lookup",
            sql="select round(sum(bytes)/1024/1024/1024,2) as total_gb from dba_data_files",
        )
        with patch("odb_autodba.services.autodba_service.get_oracle_target", return_value=self._Target("db1")), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ), self.assertLogs("odb_autodba.services.autodba_service", level="INFO") as logs:
            run_ai_investigation("What is the size of this database?", db_key="db1")
        joined = "\n".join(logs.output)
        self.assertIn("investigation_planner_requested=true", joined)
        self.assertIn("planner_model=gpt-5.5", joined)
        self.assertIn("planner_steps_count=1", joined)
        self.assertIn("fallback_used=false", joined)
        self.assertIn("thread_memory_enabled=false", joined)

    def test_mcp_dispatch_logs_agent_usage_flag(self) -> None:
        report = self._report(
            problem="What is the size of this database?",
            plan_type="inventory_read_only_lookup",
            sql="select round(sum(bytes)/1024/1024/1024,2) as total_gb from dba_data_files",
        )
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"ODB_AUTODBA_JOBS_DIR": td},
            clear=False,
        ), patch(
            "odb_autodba.mcp.jobs.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ), self.assertLogs("odb_autodba.mcp.jobs", level="INFO") as logs:
            job = create_job("investigation", db_key="db1", payload={"question": "What is the size of this database?"})
            run_job(job["job_id"])
        joined = "\n".join(logs.output)
        self.assertIn("mcp_investigation_uses_agent=true", joined)


if __name__ == "__main__":
    unittest.main()
