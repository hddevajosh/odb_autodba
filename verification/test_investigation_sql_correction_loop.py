from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.agents.investigation_agent import InvestigationAgent
from odb_autodba.db.investigation_sql import SQLExecutionResult
from odb_autodba.mcp.jobs import create_job, get_job, run_job
from odb_autodba.models.schemas import InvestigationReport, InvestigationStep, InvestigationStepDecision
from odb_autodba.services.autodba_service import run_ai_investigation
from odb_autodba.utils.formatter import render_investigation_final_report


class InvestigationSqlCorrectionLoopTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    @staticmethod
    def _error_result(message: str) -> SQLExecutionResult:
        return SQLExecutionResult(status="error", elapsed_ms=5, error=message)

    @staticmethod
    def _success_result(*, columns: list[str], rows: list[dict]) -> SQLExecutionResult:
        return SQLExecutionResult(
            status="success",
            elapsed_ms=10,
            columns=columns,
            rows=rows,
            row_count=len(rows),
            truncated=False,
        )

    @staticmethod
    def _decision_run_sql(*, goal: str, sql: str) -> InvestigationStepDecision:
        return InvestigationStepDecision(next_action="run_sql", goal=goal, sql=sql, confidence=0.7)

    @staticmethod
    def _decision_conclude(*, final_answer: str = "done") -> InvestigationStepDecision:
        return InvestigationStepDecision(next_action="conclude", goal="Finalize", final_answer=final_answer, confidence=0.8, is_final=True)

    @staticmethod
    def _decision_clarify(*, question: str) -> InvestigationStepDecision:
        return InvestigationStepDecision(next_action="clarify", goal="Clarify", clarification_question=question, confidence=0.4)

    def _patch_common_targeting(self):
        return (
            patch("odb_autodba.services.autodba_service.get_oracle_target", return_value=self._Target("db1")),
            patch("odb_autodba.agents.investigation_agent.get_oracle_target", return_value=self._Target("db1")),
            patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")),
        )

    def test_simple_lookup_database_size_uses_single_step_without_rca(self) -> None:
        with self._patch_common_targeting()[0], self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(
                    goal="Fetch database size",
                    sql="select round(sum(bytes)/1024/1024/1024,2) as total_gb from dba_data_files",
                ),
                self._decision_conclude(final_answer="Database size collected."),
            ],
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["total_gb"], rows=[{"total_gb": 250.23}]),
        ):
            payload = run_ai_investigation("What is database size?", db_key="db1")
        rendered = str(payload.get("rendered_report") or "")
        self.assertIn("## Result", rendered)
        self.assertIn("total_gb", rendered)
        self.assertNotIn("## 🔴 Root Cause Analysis", rendered)

    def test_compound_sql_id_stats_flow_continues_after_vsql_zero_rows(self) -> None:
        sql_id = "0m92022d1yzhs"
        step1_sql = f"select sql_id from v$sql where sql_id = '{sql_id}'"
        step2_sql = (
            f"select distinct object_owner, object_name, object_type, 'DBA_HIST_SQL_PLAN' as source "
            f"from dba_hist_sql_plan where sql_id = '{sql_id}' and object_owner is not null and object_name is not null"
        )
        step3_sql = (
            "select owner, table_name, object_type, to_char(last_analyzed, 'YYYY-MM-DD HH24:MI:SS') as last_analyzed "
            "from dba_tab_statistics where owner = 'DEVA1' and table_name = 'LOCK_TEST'"
        )
        with self._patch_common_targeting()[0], self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="Check live SQL_ID", sql=step1_sql),
                self._decision_run_sql(goal="Check historical plan objects", sql=step2_sql),
                self._decision_run_sql(goal="Fetch last analyzed stats", sql=step3_sql),
                self._decision_conclude(final_answer="Historical plan objects and stats collected."),
            ],
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            side_effect=[
                self._success_result(columns=["sql_id"], rows=[]),
                self._success_result(
                    columns=["object_owner", "object_name", "object_type", "source"],
                    rows=[{"object_owner": "DEVA1", "object_name": "LOCK_TEST", "object_type": "TABLE", "source": "DBA_HIST_SQL_PLAN"}],
                ),
                self._success_result(
                    columns=["owner", "table_name", "object_type", "last_analyzed"],
                    rows=[{"owner": "DEVA1", "table_name": "LOCK_TEST", "object_type": "TABLE", "last_analyzed": "2026-05-01 07:00:00"}],
                ),
            ],
        ):
            payload = run_ai_investigation(
                "Check all tables involved in SQL_ID 0m92022d1yzhs and see when stats were last analyzed",
                db_key="db1",
            )
        rendered = str(payload.get("rendered_report") or "")
        self.assertIn("LOCK_TEST", rendered)
        self.assertIn("last_analyzed", rendered)
        self.assertNotIn("## 🔴 Root Cause Analysis", rendered)

    def test_huge_tables_and_created_prompt_runs_read_only_inventory_sql(self) -> None:
        sql = (
            "select s.owner, s.segment_name as table_name, "
            "round(sum(s.bytes)/1024/1024/1024,2) as table_gb, "
            "to_char(o.created, 'YYYY-MM-DD HH24:MI:SS') as created "
            "from dba_segments s join dba_objects o "
            "on o.owner=s.owner and o.object_name=s.segment_name and o.object_type='TABLE' "
            "where s.segment_type='TABLE' "
            "group by s.owner, s.segment_name, o.created "
            "order by table_gb desc fetch first 10 rows only"
        )
        with self._patch_common_targeting()[0], self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="Find huge tables with created date", sql=sql),
                self._decision_conclude(final_answer="Collected huge-table size and created timestamp evidence."),
            ],
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(
                columns=["owner", "table_name", "table_gb", "created"],
                rows=[{"owner": "APP1", "table_name": "ORDERS", "table_gb": 22.5, "created": "2026-04-01 10:00:00"}],
            ),
        ):
            payload = run_ai_investigation("Help me find huge tables and when they were created", db_key="db1")
        rendered = str(payload.get("rendered_report") or "").lower()
        self.assertIn("orders", rendered)
        self.assertIn("created", rendered)
        self.assertNotIn("## 🔴 root cause analysis".lower(), rendered)

    def test_bad_dictionary_sql_is_linted_before_execution_and_repaired(self) -> None:
        bad_sql = "select table_name from v$sql_plan where sql_id='abc'"
        repaired_sql = "select object_owner, object_name from v$sql_plan where sql_id='abc' and object_name is not null"
        with self._patch_common_targeting()[0], self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="Find plan objects", sql=bad_sql),
                self._decision_conclude(final_answer="done"),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_sql_correction",
            return_value={"sql": repaired_sql, "reason": "V$SQL_PLAN uses OBJECT_NAME not TABLE_NAME"},
        ) as repair, patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["object_owner", "object_name"], rows=[{"object_owner": "DEVA1", "object_name": "LOCK_TEST"}]),
        ) as execute_sql:
            run_ai_investigation("show objects involved in sql_id abc", db_key="db1")
        self.assertEqual(execute_sql.call_count, 1)
        self.assertEqual(repair.call_count, 1)
        self.assertIn("object_name", str(execute_sql.call_args.args[0]).lower())

    def test_user_tables_created_lint_repairs_to_user_objects(self) -> None:
        with self._patch_common_targeting()[0], self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="List table created dates", sql="select table_name, created from user_tables"),
                self._decision_conclude(final_answer="done"),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_sql_correction",
            return_value={
                "sql": "select t.table_name, o.created from user_tables t join user_objects o on o.object_name=t.table_name and o.object_type='TABLE'",
                "reason": "CREATED in USER_OBJECTS",
            },
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["table_name", "created"], rows=[{"table_name": "LOCK_TEST", "created": "2026-05-01 07:00:00"}]),
        ) as execute_sql:
            run_ai_investigation("List table creation date", db_key="db1")
        repaired_sql_used = str(execute_sql.call_args.args[0]).lower()
        self.assertIn("user_objects", repaired_sql_used)

    def test_zero_row_semantics_for_blocking_can_conclude(self) -> None:
        with self._patch_common_targeting()[0], self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(
                    goal="Check current blockers",
                    sql="select inst_id, sid, blocking_session from gv$session where blocking_session is not null",
                ),
                self._decision_conclude(final_answer="No current blockers found."),
            ],
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["inst_id", "sid", "blocking_session"], rows=[]),
        ):
            payload = run_ai_investigation("Are there blocking locks currently?", db_key="db1")
        report_text = str(payload.get("rendered_report") or "")
        self.assertIn("termination_reason: evidence_complete", report_text)
        self.assertNotIn("step_failed", report_text)

    def test_attempt_budget_and_sql_execution_cap_enforced(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "",
                "ODB_AUTODBA_INVESTIGATION_MAX_SQL_ATTEMPTS": "5",
                "ODB_AUTODBA_INVESTIGATION_SQL_EXECUTION_CAP": "2",
            },
            clear=False,
        ), self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="s1", sql="select 1 from dual"),
                self._decision_run_sql(goal="s2", sql="select 2 from dual"),
                self._decision_run_sql(goal="s3", sql="select 3 from dual"),
            ],
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["x"], rows=[{"x": 1}]),
        ) as execute_sql:
            report = InvestigationAgent(db_key="db1").investigate("Why is database slow?", db_key="db1")
        self.assertEqual(execute_sql.call_count, 2)
        self.assertEqual(report.sql_execution_cap, 2)

    def test_output_sections_and_primary_result_selection(self) -> None:
        report = InvestigationReport(
            problem_statement="Check SQL_ID tables and stats",
            summary="Ran 3 logical investigation step(s) with 3 SQL execution(s).",
            likely_cause="Requested read-only lookup evidence was collected successfully.",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Check live SQL_ID",
                    sql="select sql_id from v$sql where sql_id='x'",
                    result_preview="Returned 0 row(s).",
                    row_count=0,
                    status="success",
                    result_columns=["sql_id"],
                    result_rows=[],
                ),
                InvestigationStep(
                    step_number=2,
                    goal="Find objects",
                    sql="select object_owner, object_name from dba_hist_sql_plan",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["object_owner", "object_name"],
                    result_rows=[{"object_owner": "DEVA1", "object_name": "LOCK_TEST"}],
                ),
                InvestigationStep(
                    step_number=3,
                    goal="Stats",
                    sql="select owner, table_name, last_analyzed from dba_tab_statistics where 1=0",
                    result_preview="Returned 0 row(s).",
                    row_count=0,
                    status="success",
                    result_columns=["owner", "table_name", "last_analyzed"],
                    result_rows=[],
                ),
            ],
            required_evidence_status={"sql_id_source_checked": True, "plan_objects_identified": True},
            termination_reason="completed",
        )
        rendered = render_investigation_final_report(report)
        self.assertIn("## Question", rendered)
        self.assertIn("## Summary", rendered)
        self.assertIn("## Result", rendered)
        self.assertIn("## Observation", rendered)
        self.assertIn("## DBA Inference", rendered)
        self.assertIn("## Evidence Source", rendered)
        self.assertIn("## Confidence / Termination", rendered)
        self.assertIn("LOCK_TEST", rendered)
        self.assertNotIn("```json", rendered)

    def test_trace_events_include_meta_attempt_repair_step_and_conclusion(self) -> None:
        error = 'ORA-00904: "CREATED": invalid identifier'
        trace_root = Path(tempfile.mkdtemp())
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False), self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="List table created", sql="select table_name, created from user_tables"),
                self._decision_conclude(final_answer="done"),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_sql_correction",
            return_value={
                "sql": "select t.table_name, o.created from user_tables t join user_objects o on o.object_name=t.table_name and o.object_type='TABLE'",
                "reason": "CREATED in USER_OBJECTS",
            },
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            side_effect=[
                self._error_result(error),
                self._success_result(columns=["table_name", "created"], rows=[{"table_name": "LOCK_TEST", "created": "2026-05-08 09:00:00"}]),
            ],
        ):
            report = InvestigationAgent(db_key="db1", trace_root=trace_root).investigate(
                "List all tables in database and its creation date?",
                db_key="db1",
            )
        trace_path = Path(str(report.trace_path or ""))
        self.assertTrue(trace_path.exists())
        text = trace_path.read_text(encoding="utf-8")
        self.assertIn('"event_type": "investigation.meta"', text)
        self.assertIn('"event_type": "investigation.sql_attempt"', text)
        self.assertIn('"event_type": "investigation.sql_repair"', text)
        self.assertIn('"event_type": "investigation.step"', text)
        self.assertIn('"event_type": "investigation.conclusion"', text)

    def test_mcp_and_direct_path_use_same_stepwise_agent(self) -> None:
        report = InvestigationReport(
            problem_statement="What is database size?",
            summary="Ran 1 logical investigation step(s) with 1 SQL execution(s).",
            likely_cause="Requested read-only lookup evidence was collected successfully.",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Fetch database size",
                    sql="select round(sum(bytes)/1024/1024/1024,2) as total_gb from dba_data_files",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["total_gb"],
                    result_rows=[{"total_gb": 100.5}],
                )
            ],
        )
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), self._patch_common_targeting()[0], self._patch_common_targeting()[2], patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ) as investigate:
            direct = run_ai_investigation("What is database size?", db_key="db1")
            self.assertTrue(direct.get("ok"))
            job = create_job("investigation", db_key="db1", payload={"question": "What is database size?"})
            run_job(job["job_id"])
            payload = get_job(job["job_id"]) or {}
            self.assertEqual(payload.get("status"), "completed")
            self.assertEqual(investigate.call_count, 2)

    def test_oracle_dictionary_guidance_includes_generic_inventory_scope_rules(self) -> None:
        agent = InvestigationAgent(db_key="db1")
        guidance = agent._oracle_dictionary_guidance().lower()
        self.assertIn("database-wide", guidance)
        self.assertIn("dba_*", guidance)
        self.assertIn("all_*", guidance)
        self.assertIn("user_*", guidance)
        self.assertIn("oracle_maintained", guidance)

    def test_dictionary_lint_flags_ambiguous_unqualified_join_columns(self) -> None:
        agent = InvestigationAgent(db_key="db1")
        lint = agent._dictionary_lint(
            sql=(
                "select owner, table_name, bytes "
                "from dba_tables t join dba_segments s on s.owner=t.owner and s.segment_name=t.table_name"
            ),
            goal="Find huge tables",
        )
        self.assertEqual(str(lint.get("fatal") or "").lower(), "true")
        self.assertIn("ora-00918", str(lint.get("message") or "").lower())

    def test_user_scope_note_added_for_database_wide_question_when_user_views_used(self) -> None:
        agent = InvestigationAgent(db_key="db1")
        note = agent._scope_note_for_sql(
            problem_statement="List all tables in database please",
            sql="select table_name from user_tables",
        )
        self.assertIn("current schema only", note.lower())

    def test_investigation_start_log_includes_question_presence_and_hash(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False), self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_plan_steps",
            return_value={
                "plan_type": "inventory_read_only_lookup",
                "steps": [{"goal": "g", "sql": "select 1 from dual"}],
                "planner_provider": "deterministic_fallback",
                "planner_model": "deterministic",
                "planner_elapsed_ms": 1,
                "planner_steps_count": 1,
                "fallback_used": True,
                "fallback_reason": "planner_error",
                "notes": [],
            },
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["x"], rows=[{"x": 1}]),
        ), self.assertLogs("odb_autodba.agents.investigation_agent", level="INFO") as logs:
            InvestigationAgent(db_key="db1").investigate("What is database size?", db_key="db1")
        joined = "\n".join(logs.output).lower()
        self.assertIn("investigation_start", joined)
        self.assertIn("question_present=true", joined)
        self.assertIn("question_hash=", joined)

    def test_inventory_clarify_triggers_forced_replan_and_executes_sql(self) -> None:
        clarify_decision = self._decision_clarify(question="Can you clarify which schema?")
        forced_sql_decision = self._decision_run_sql(
            goal="List schemas and tables",
            sql="select owner, table_name from dba_tables fetch first 20 rows only",
        )
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False), self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_request_next_step_decision",
            side_effect=[
                (clarify_decision, ""),
                (self._decision_conclude(final_answer="done"), ""),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_forced_inventory_replan",
            return_value=(forced_sql_decision, ""),
        ) as forced_replan, patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["owner", "table_name"], rows=[{"owner": "APP1", "table_name": "T1"}]),
        ) as execute_sql:
            report = InvestigationAgent(db_key="db1").investigate(
                "List all schemas and tables",
                db_key="db1",
            )
        self.assertGreaterEqual(len(report.steps), 1)
        self.assertGreaterEqual(execute_sql.call_count, 1)
        self.assertIn("dba_tables", report.steps[0].sql.lower())
        forced_replan.assert_called_once()
        self.assertNotEqual(report.termination_reason, "clarification_required")

    def test_planner_failure_does_not_map_to_clarification_required(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False), self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_request_next_step_decision",
            return_value=(None, "planner_failed"),
        ):
            report = InvestigationAgent(db_key="db1").investigate("List all tables in database", db_key="db1")
        self.assertEqual(report.termination_reason, "planner_failed")
        self.assertNotEqual(report.termination_reason, "clarification_required")

    def test_ambiguous_prompt_keeps_clarification_required_with_question(self) -> None:
        clarify_q = "Which object do you mean by 'that one'?"
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False), self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_request_next_step_decision",
            return_value=(self._decision_clarify(question=clarify_q), ""),
        ), patch.object(
            InvestigationAgent,
            "_request_forced_inventory_replan",
        ) as forced_replan:
            report = InvestigationAgent(db_key="db1").investigate("Check that one", db_key="db1")
        self.assertEqual(report.termination_reason, "clarification_required")
        self.assertEqual(report.clarification_question, clarify_q)
        forced_replan.assert_not_called()

    def test_placeholder_lint_blocks_execution_for_your_owner_sql(self) -> None:
        with self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="Find object stats", sql="select * from dba_tab_statistics where owner='YOUR_OWNER'"),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_sql_correction",
            return_value=None,
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["x"], rows=[{"x": 1}]),
        ) as execute_sql:
            report = InvestigationAgent(db_key="db1").investigate("Find table stats", db_key="db1")
        self.assertEqual(execute_sql.call_count, 0)
        self.assertEqual(report.termination_reason, "step_failed")

    def test_blocking_invalid_vsession_columns_repaired_before_execution(self) -> None:
        bad_sql = "select sid, sql_text, object_id from v$session where blocking_session is not null"
        repaired_sql = (
            "select s.inst_id, s.sid, s.sql_id, q.sql_text, lo.object_id "
            "from gv$session s left join gv$sql q on q.inst_id=s.inst_id and q.sql_id=s.sql_id "
            "left join gv$locked_object lo on lo.inst_id=s.inst_id and lo.session_id=s.sid "
            "where s.blocking_session is not null fetch first 20 rows only"
        )
        with self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="Find blockers", sql=bad_sql),
                self._decision_conclude(final_answer="done"),
                self._decision_conclude(final_answer="done"),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_sql_correction",
            return_value={"sql": repaired_sql, "reason": "Use GV$SESSION + GV$SQL + GV$LOCKED_OBJECT"},
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(
                columns=["inst_id", "sid", "sql_id", "sql_text", "object_id", "blocking_session"],
                rows=[{"inst_id": 1, "sid": 41, "sql_id": "abc", "sql_text": "select 1", "object_id": 100, "blocking_session": 42}],
            ),
        ) as execute_sql:
            report = InvestigationAgent(db_key="db1").investigate("Show blocking locks currently", db_key="db1")
        self.assertGreaterEqual(execute_sql.call_count, 1)
        self.assertNotIn("v$session where blocking_session", str(report.steps[0].sql).lower())
        self.assertNotIn("object_id from v$session", str(report.steps[0].sql).lower())

    def test_schema_size_and_tables_inside_schema_requires_two_evidence_items(self) -> None:
        with self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(
                    goal="Schema totals",
                    sql="select owner, round(sum(bytes)/1024/1024,2) mb from dba_segments group by owner",
                ),
                self._decision_run_sql(
                    goal="Table sizes",
                    sql="select owner, segment_name as table_name, bytes from dba_segments where segment_type='TABLE'",
                ),
                self._decision_conclude(final_answer="done"),
            ],
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            side_effect=[
                self._success_result(columns=["owner", "mb"], rows=[{"owner": "APP1", "mb": 10.0}]),
                self._success_result(columns=["owner", "table_name", "bytes"], rows=[{"owner": "APP1", "table_name": "T1", "bytes": 1024}]),
            ],
        ):
            report = InvestigationAgent(db_key="db1").investigate("schema wise total size and tables inside schema", db_key="db1")
        self.assertTrue(report.required_evidence_status.get("schema_total_size_fetched"))
        self.assertTrue(report.required_evidence_status.get("table_size_by_schema_fetched"))
        self.assertGreaterEqual(len(report.steps), 2)

    def test_locktest_sessions_only_is_incomplete_for_metadata_question(self) -> None:
        agent = InvestigationAgent(db_key="db1")
        decision = InvestigationStepDecision(next_action="run_sql", goal="check sessions", sql="select sid from gv$session where sql_id='x'")
        step = InvestigationStep(
            step_number=1,
            goal="check sessions",
            sql="select sid from gv$session where sql_id='x'",
            result_preview="Returned 0 row(s).",
            row_count=0,
            status="success",
            result_columns=["sid"],
            result_rows=[],
        )
        reason = agent._incomplete_evidence_reason(
            question="Check LOCK_TEST creation date size stats indexes sessions locks",
            decision=decision,
            step=step,
            required_evidence=agent._required_evidence_for_question("Check LOCK_TEST creation date size stats indexes sessions locks"),
            prior_step_results=[],
        )
        self.assertIsNotNone(reason)

    def test_repair_claiming_replacement_but_repeating_same_sql_stops(self) -> None:
        bad_sql = "select sid, sql_text, object_id from v$session where blocking_session is not null"
        with self._patch_common_targeting()[1], patch.object(
            InvestigationAgent,
            "_next_step_decision",
            side_effect=[
                self._decision_run_sql(goal="Find blockers", sql=bad_sql),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_sql_correction",
            return_value={"sql": bad_sql, "reason": "Replaced invalid tokens"},
        ), patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._error_result("ORA-00904: invalid identifier"),
        ) as execute_sql:
            report = InvestigationAgent(db_key="db1").investigate("Show blockers", db_key="db1")
        self.assertEqual(execute_sql.call_count, 0)
        self.assertIn(report.termination_reason, {"step_failed", "unrecoverable_sql_error"})


if __name__ == "__main__":
    unittest.main()
