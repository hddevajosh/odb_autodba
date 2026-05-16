from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import patch

from odb_autodba.agents.investigation_agent import InvestigationAgent
from odb_autodba.models.schemas import InvestigationStepDecision, SQLExecutionResult


class InvestigationPlannerRecoveryTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

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

    def test_step_decision_schema_normalizes_aliases_evidence_actions_and_confidence(self) -> None:
        decision = InvestigationStepDecision.model_validate(
            {
                "action": "run",
                "query": "select * from dual",
                "reason": "test",
                "objective": "collect evidence",
                "required_evidence_status": [{"name": "table_inventory_fetched", "satisfied": False}],
                "recommended_actions": "review results",
                "confidence": "high",
            }
        )
        self.assertEqual(decision.next_action, "run_sql")
        self.assertEqual(decision.sql, "select * from dual")
        self.assertEqual(decision.analysis, "test")
        self.assertEqual(decision.goal, "collect evidence")
        self.assertEqual(decision.required_evidence_status.get("table_inventory_fetched"), False)
        self.assertEqual(decision.recommended_actions, ["review results"])
        self.assertAlmostEqual(decision.confidence, 0.85, places=2)

    def test_parser_accepts_markdown_json_and_prose_json(self) -> None:
        agent = InvestigationAgent(db_key="db1")
        fenced = """```json\n{"next_action":"run_sql","sql":"select * from dual","goal":"test"}\n```"""
        prose = """Here is the decision:\n{"next_action":"run_sql","sql":"select * from dual","goal":"test"}"""
        parsed_fenced = agent._parse_planner_json(fenced)
        parsed_prose = agent._parse_planner_json(prose)
        self.assertEqual(str(parsed_fenced.get("next_action")), "run_sql")
        self.assertIn("select * from dual", str(parsed_fenced.get("sql") or "").lower())
        self.assertEqual(str(parsed_prose.get("next_action")), "run_sql")

    def test_plain_sql_salvage_wraps_safe_sql_for_clear_inventory(self) -> None:
        agent = InvestigationAgent(db_key="db1")
        decision, reason = agent._parse_planner_decision_content(
            content="SELECT owner, table_name FROM dba_tables fetch first 10 rows only",
            original_question="List all tables in database",
            force_inventory_replan=False,
        )
        self.assertEqual(reason, "")
        self.assertIsNotNone(decision)
        self.assertEqual(decision.next_action, "run_sql")
        self.assertIn("select owner, table_name from dba_tables", str(decision.sql or "").lower())

    def test_plain_sql_salvage_rejects_unsafe_sql(self) -> None:
        agent = InvestigationAgent(db_key="db1")
        decision, reason = agent._parse_planner_decision_content(
            content="DELETE FROM app.orders WHERE 1=1",
            original_question="List all tables in database",
            force_inventory_replan=False,
        )
        self.assertIsNone(decision)
        self.assertEqual(reason, "planner_json_parse_failed")

    def test_invalid_json_then_repair_json_returns_run_sql(self) -> None:
        responses = ["planner output: not valid json"]

        class _Completion:
            def __init__(self, text: str) -> None:
                self.choices = [types.SimpleNamespace(message=types.SimpleNamespace(content=text))]

        class _Completions:
            def create(self, **kwargs):  # noqa: ANN003
                return _Completion(responses.pop(0))

        class _OpenAI:
            def __init__(self, **kwargs):  # noqa: ANN003
                self.chat = types.SimpleNamespace(completions=_Completions())

        agent = InvestigationAgent(db_key="db1")
        with patch.dict(sys.modules, {"openai": types.SimpleNamespace(OpenAI=_OpenAI)}), patch.object(
            agent,
            "_request_planner_json_repair",
            return_value='{"next_action":"run_sql","sql":"select * from dual","goal":"test"}',
        ):
            decision, reason = agent._call_openai_planner_for_step_decision(
                model_name="gpt-4o-mini",
                timeout_sec=10,
                openai_api_key="test-key",
                payload={"original_question": "List all tables in database"},
                force_inventory_replan=False,
            )
        self.assertEqual(reason, "")
        self.assertIsNotNone(decision)
        self.assertEqual(decision.next_action, "run_sql")
        self.assertIn("select * from dual", str(decision.sql or "").lower())

    def test_clear_inventory_parse_failure_triggers_forced_replan_and_executes_sql(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False), patch(
            "odb_autodba.agents.investigation_agent.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch.object(
            InvestigationAgent,
            "_request_next_step_decision",
            side_effect=[
                (None, "planner_json_parse_failed"),
                (self._decision_conclude(final_answer="done"), ""),
                (self._decision_conclude(final_answer="done"), ""),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_forced_inventory_replan",
            return_value=(
                self._decision_run_sql(goal="List all tables", sql="select owner, table_name from dba_tables fetch first 20 rows only"),
                "",
            ),
        ) as forced_replan, patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["owner", "table_name"], rows=[{"owner": "APP1", "table_name": "T1"}]),
        ) as execute_sql:
            report = InvestigationAgent(db_key="db1").investigate(
                "List all tables in database",
                db_key="db1",
            )
        self.assertGreaterEqual(len(report.steps), 1)
        self.assertGreaterEqual(execute_sql.call_count, 1)
        self.assertNotEqual(report.termination_reason, "planner_json_parse_failed")
        forced_replan.assert_called_once()

    def test_repeated_invalid_responses_end_with_planner_json_parse_failed_and_low_confidence(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False), patch(
            "odb_autodba.agents.investigation_agent.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch.object(
            InvestigationAgent,
            "_request_next_step_decision",
            return_value=(None, "planner_json_parse_failed"),
        ), patch.object(
            InvestigationAgent,
            "_request_forced_inventory_replan",
            return_value=(None, "planner_json_parse_failed"),
        ):
            report = InvestigationAgent(db_key="db1").investigate(
                "What all tables exist in database, whats there creation date and size?",
                db_key="db1",
            )
        self.assertEqual(report.termination_reason, "planner_json_parse_failed")
        self.assertEqual(report.confidence, "LOW")
        self.assertIn("No SQL steps were executed.", report.summary)
        self.assertIn("invalid JSON", report.likely_cause)

    def test_ambiguous_question_keeps_clarification_required(self) -> None:
        clarify_q = "Which object do you mean by 'that one'?"
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False), patch(
            "odb_autodba.agents.investigation_agent.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch.object(
            InvestigationAgent,
            "_request_next_step_decision",
            return_value=(self._decision_clarify(question=clarify_q), ""),
        ), patch.object(
            InvestigationAgent,
            "_request_forced_inventory_replan",
        ) as forced_replan:
            report = InvestigationAgent(db_key="db1").investigate("check that one", db_key="db1")
        self.assertEqual(report.termination_reason, "clarification_required")
        self.assertEqual(report.clarification_question, clarify_q)
        forced_replan.assert_not_called()

    def test_clear_inventory_clarify_is_not_accepted_and_forced_replan_runs(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False), patch(
            "odb_autodba.agents.investigation_agent.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch.object(
            InvestigationAgent,
            "_request_next_step_decision",
            side_effect=[
                (self._decision_clarify(question="Can you clarify scope?"), ""),
                (self._decision_conclude(final_answer="done"), ""),
            ],
        ), patch.object(
            InvestigationAgent,
            "_request_forced_inventory_replan",
            return_value=(
                self._decision_run_sql(goal="List schemas and tables", sql="select owner, table_name from dba_tables fetch first 20 rows only"),
                "",
            ),
        ) as forced_replan, patch(
            "odb_autodba.agents.investigation_agent.execute_investigation_sql",
            return_value=self._success_result(columns=["owner", "table_name"], rows=[{"owner": "APP1", "table_name": "T1"}]),
        ):
            report = InvestigationAgent(db_key="db1").investigate("List all schemas and tables", db_key="db1")
        self.assertNotEqual(report.termination_reason, "clarification_required")
        forced_replan.assert_called_once()

    def test_model_source_logging_uses_investigation_planner_model_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "",
                "ODB_AUTODBA_INVESTIGATION_PLANNER_MODEL": "gpt-5.3-codex",
            },
            clear=False,
        ), patch(
            "odb_autodba.agents.investigation_agent.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch.object(
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
            InvestigationAgent(db_key="db1").investigate("List all schemas and tables", db_key="db1")
        joined = "\n".join(logs.output)
        self.assertIn("investigation_model=gpt-5.3-codex", joined)
        self.assertIn("model_source=ODB_AUTODBA_INVESTIGATION_PLANNER_MODEL", joined)
        self.assertIn("openai_api_key_present=false", joined)


if __name__ == "__main__":
    unittest.main()
