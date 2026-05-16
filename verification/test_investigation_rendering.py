from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.agents.investigation_agent import InvestigationAgent
from odb_autodba.models.schemas import InvestigationReport, InvestigationSQLAttemptRecord, InvestigationStep
from odb_autodba.services.autodba_service import run_ai_investigation
from odb_autodba.utils.formatter import render_investigation_final_report


class InvestigationRenderingTests(unittest.TestCase):
    def _report(self, likely_cause: str, *, plan_type: str = "inventory_read_only_lookup") -> InvestigationReport:
        return InvestigationReport(
            problem_statement="x",
            summary="Ran 1 logical investigation step(s) with 1 SQL execution(s).",
            likely_cause=likely_cause,
            plan_type=plan_type,
            evidence=["e1"],
            recommended_next_actions=["n1"],
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="g1",
                    sql="select 1 from dual",
                    result_preview="ok",
                    row_count=1,
                    status="success",
                    result_columns=["X"],
                    result_rows=[{"X": 1}],
                )
            ],
        )

    def test_inventory_investigation_does_not_render_root_cause_section(self) -> None:
        with patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=self._report("Requested inventory metric was collected: database size estimate."),
        ):
            payload = run_ai_investigation("What is the size of the database?")
        report = payload.get("rendered_report") or ""
        self.assertIn("# AI Investigation Result", report)
        self.assertIn("## SQL Evidence Collected", report)
        self.assertNotIn("## 🔴 Root Cause Analysis", report)

    def test_diagnostic_investigation_renders_root_cause_heading(self) -> None:
        with patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=self._report(
                "One or more high-cost SQL statements appear to be contributing to the slowdown.",
                plan_type="diagnostic",
            ),
        ):
            payload = run_ai_investigation("Why is DB slow?")
        report = payload.get("rendered_report") or ""
        self.assertIn("## 🔴 Root Cause Analysis", report)

    def test_clarification_required_header_uses_needs_clarification_status(self) -> None:
        clarify_report = InvestigationReport(
            problem_statement="Check that one",
            summary="No SQL steps were executed.",
            likely_cause="Need clarification before SQL execution.",
            plan_type="inventory_read_only_lookup",
            steps=[],
            termination_reason="clarification_required",
            clarification_question="Which object should I inspect?",
        )
        with patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=clarify_report,
        ):
            payload = run_ai_investigation("Check that one")
        report = payload.get("rendered_report") or ""
        self.assertIn("clarification: Which object should I inspect?", report)
        self.assertIn("termination_reason: clarification_required", report)
        self.assertEqual(payload.get("status"), "needs_clarification")

    def test_renderer_renders_all_success_steps_with_tables(self) -> None:
        report = InvestigationReport(
            problem_statement="help me investigate blocking lock which is present in this database?",
            summary="Ran 3 logical investigation step(s) with 3 SQL execution(s).",
            likely_cause="Blocking lock evidence collected.",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Identify current blocking sessions",
                    sql="select blocking_session, sid as blocked_sid from v$session where blocking_session is not null",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["blocking_session", "blocked_sid"],
                    result_rows=[{"blocking_session": 601, "blocked_sid": 812}],
                ),
                InvestigationStep(
                    step_number=2,
                    goal="Identify locked object",
                    sql="select owner, object_name from dba_objects where object_id = 42",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["owner", "object_name"],
                    result_rows=[{"owner": "APP", "object_name": "ORDERS"}],
                ),
                InvestigationStep(
                    step_number=3,
                    goal="Retrieve SQL text for blocker",
                    sql="select sql_id, sql_text from v$sql where sql_id = 'abcd1234'",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["sql_id", "sql_text"],
                    result_rows=[{"sql_id": "abcd1234", "sql_text": "select * from orders"}],
                ),
            ],
        )
        rendered = render_investigation_final_report(report)
        self.assertIn("## SQL Evidence Collected", rendered)
        self.assertIn("### Step 1 — Identify current blocking sessions", rendered)
        self.assertIn("### Step 2 — Identify locked object", rendered)
        self.assertIn("### Step 3 — Retrieve SQL text for blocker", rendered)
        self.assertGreaterEqual(rendered.count("<div style=\"overflow-x:auto;\"><pre>"), 3)
        self.assertNotIn("```json", rendered)

    def test_renderer_keeps_correction_attempts_and_success_output(self) -> None:
        report = InvestigationReport(
            problem_statement="Investigate blocker SQL text",
            summary="Ran 1 logical investigation step(s) with 2 SQL execution(s).",
            likely_cause="Repaired SQL succeeded.",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Retrieve SQL text for blocker",
                    sql="select sql_text from v$session where sid = 601",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["sql_id", "sql_text"],
                    result_rows=[{"sql_id": "abcd1234", "sql_text": "select * from orders"}],
                    correction_attempts=[
                        InvestigationSQLAttemptRecord(
                            attempt_no=1,
                            attempt=1,
                            sql="select sql_text from v$session where sid = 601",
                            validation_ok=True,
                            execution_status="error",
                            status="error",
                            recoverable=True,
                            error='ORA-00904: "SQL_TEXT": invalid identifier',
                            error_code="ORA-00904",
                        ),
                        InvestigationSQLAttemptRecord(
                            attempt_no=2,
                            attempt=2,
                            sql="select sql_id, sql_text from v$sql where sql_id = 'abcd1234'",
                            repaired=True,
                            validation_ok=True,
                            execution_status="success",
                            status="success",
                            recoverable=False,
                        ),
                    ],
                    final_attempt_count=2,
                )
            ],
        )
        rendered = render_investigation_final_report(report)
        self.assertIn("Status: success after repair", rendered)
        self.assertIn("Repaired from failed attempt: yes", rendered)
        self.assertIn("## Correction Attempts", rendered)
        self.assertIn("Attempt 1 failed:", rendered)
        self.assertIn("Final repaired SQL:", rendered)
        self.assertIn("Output:", rendered)
        self.assertIn("sql_id", rendered.lower())

    def test_renderer_zero_and_large_output_handling(self) -> None:
        rows = [{"col_a": i, "col_b": "x" * 90} for i in range(60)]
        report = InvestigationReport(
            problem_statement="Show output handling",
            summary="Ran 2 logical investigation step(s) with 2 SQL execution(s).",
            likely_cause="Output formatting check.",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Zero-row check",
                    sql="select * from dual where 1 = 0",
                    result_preview="Returned 0 row(s).",
                    row_count=0,
                    status="success",
                    result_columns=["dummy"],
                    result_rows=[],
                ),
                InvestigationStep(
                    step_number=2,
                    goal="Large-row check",
                    sql="select level as col_a, rpad('x', 90, 'x') as col_b from dual connect by level <= 60",
                    result_preview="Returned 60 row(s).",
                    row_count=60,
                    status="success",
                    result_columns=["col_a", "col_b"],
                    result_rows=rows,
                    result_truncated=True,
                ),
            ],
        )
        rendered = render_investigation_final_report(report)
        self.assertIn("Returned 0 rows.", rendered)
        self.assertIn("Displayed first 50 row(s); output truncated.", rendered)
        self.assertNotIn('"col_a":', rendered)
        self.assertNotIn("```json", rendered)

    def test_dba_inference_blocking_is_specific(self) -> None:
        agent = InvestigationAgent(ai_service=None)
        inference = agent._compose_dba_inference(
            problem_statement="Investigate blocking lock now",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Blocker details",
                    sql="select blocker_sid, blocked_sid, object_owner, object_name, object_type, blocker_sql_id, blocker_sql_text, event from gv$session",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_rows=[
                        {
                            "blocker_sid": 601,
                            "blocked_sid": 812,
                            "object_owner": "APP",
                            "object_name": "ORDERS",
                            "object_type": "TABLE",
                            "blocker_sql_id": "abcd1234",
                            "blocker_sql_text": "update app.orders set status='X' where id=:1",
                            "event": "enq: TX - row lock contention",
                        }
                    ],
                )
            ],
            historical_context={},
            termination_reason="evidence_complete",
            plan_type="current_state",
            base_inference="placeholder",
        )
        self.assertIn("blocker SID 601", inference)
        self.assertIn("APP.ORDERS", inference)
        self.assertIn("abcd1234", inference)
        self.assertIn("uncommitted transactional DML", inference)

    def test_dba_inference_sql_id_is_specific(self) -> None:
        agent = InvestigationAgent(ai_service=None)
        inference = agent._compose_dba_inference(
            problem_statement="Investigate SQL_ID 0m92022d1yzhs",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="SQL details",
                    sql="select sql_id, plan_hash_value, executions, elapsed_s, cpu_s, object_owner, object_name, object_type from v$sql",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_rows=[
                        {
                            "sql_id": "0m92022d1yzhs",
                            "plan_hash_value": 123456789,
                            "executions": 42,
                            "elapsed_s": 9.2,
                            "cpu_s": 7.1,
                            "object_owner": "APP",
                            "object_name": "LOCK_TEST",
                            "object_type": "TABLE",
                        }
                    ],
                )
            ],
            historical_context={},
            termination_reason="evidence_complete",
            plan_type="diagnostic",
            base_inference="placeholder",
        )
        self.assertIn("SQL_ID 0m92022d1yzhs", inference)
        self.assertIn("plan_hash_value", inference)
        self.assertIn("executions", inference)
        self.assertIn("APP.LOCK_TEST", inference)

    def test_inventory_inference_does_not_imply_incident_root_cause(self) -> None:
        agent = InvestigationAgent(ai_service=None)
        inference = agent._compose_dba_inference(
            problem_statement="List all tables in this database",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="List tables",
                    sql="select owner, table_name from dba_tables fetch first 5 rows only",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_rows=[{"owner": "APP", "table_name": "T1"}],
                )
            ],
            historical_context={},
            termination_reason="evidence_complete",
            plan_type="inventory_read_only_lookup",
            base_inference="placeholder",
        )
        self.assertIn("no incident root cause is implied", inference.lower())


if __name__ == "__main__":
    unittest.main()
