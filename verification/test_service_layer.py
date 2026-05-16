from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.models.schemas import InvestigationReport, InvestigationStep, PlannerResponse
from odb_autodba.services.autodba_service import (
    answer_history_metric_question,
    get_active_sessions,
    get_historical_trends,
    run_ai_investigation,
    run_health_check,
)


class ServiceLayerTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def _assert_root_cause_shape(self, payload: dict) -> None:
        root_cause = payload.get("root_cause")
        self.assertIsInstance(root_cause, dict)
        for key in (
            "category",
            "confidence",
            "evidence",
            "reasoning",
            "impacted_components",
            "primary_evidence",
            "supporting_evidence",
            "next_validation_step",
        ):
            self.assertIn(key, root_cause)

    def _assert_correlation_shape(self, payload: dict) -> None:
        correlation = payload.get("correlation")
        self.assertIsInstance(correlation, dict)
        for key in (
            "primary_cause",
            "contributing_factors",
            "metric_signals",
            "issue_signals",
            "entity_signals",
            "contradictions",
            "missing_evidence",
            "timeline",
            "recommended_next_steps",
            "score_components",
            "sources_used",
            "schema_observations",
        ):
            self.assertIn(key, correlation)

    def test_health_check_returns_structured_dict(self) -> None:
        response = PlannerResponse(
            mode="full_health_report",
            summary="Oracle health check completed.",
            body_markdown="# report\n\n## Host Check Scope\n\n- Mode: local_app_host\n- Scope: Local AutoDBA app host",
            supporting_data={
                "trace_path": "/tmp/trace.json",
                "x": 1,
                "host_check": {
                    "host_check_mode": "local_app_host",
                    "host_check_scope": "local_app_host",
                    "host_check_label": "Local AutoDBA app host",
                    "host_check_warning": "These metrics describe the AutoDBA runtime machine, not necessarily the Oracle DB server.",
                },
            },
        )
        with patch("odb_autodba.services.autodba_service.PlannerAgent.handle_message", return_value=response), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("default__localhost__1521__freepdb1"),
        ):
            payload = run_health_check()
        self.assertIsInstance(payload, dict)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("summary"), "Oracle health check completed.")
        self.assertEqual(payload.get("trace_path"), "/tmp/trace.json")
        self.assertEqual(payload.get("db_key"), "default__localhost__1521__freepdb1")
        self.assertIn("## 🔴 Root Cause Analysis", payload.get("rendered_report") or "")
        self.assertIn("Local AutoDBA app host", payload.get("rendered_report") or "")
        self.assertIn("report_path", payload)
        self._assert_root_cause_shape(payload)
        self._assert_correlation_shape(payload)
        self.assertIsInstance(payload.get("supporting_data"), dict)
        self.assertEqual(
            ((payload.get("supporting_data") or {}).get("host_check") or {}).get("host_check_scope"),
            "local_app_host",
        )

    def test_historical_trends_returns_indexed_metadata(self) -> None:
        response = PlannerResponse(
            mode="history_report",
            summary="Historical Oracle run comparison completed.",
            body_markdown="# history",
            supporting_data={
                "history_data_sources": {
                    "history_source_used": "indexed recurrence + metrics",
                    "index_usage_summary": "recurring + chunks",
                    "history_index_status": "active",
                }
            },
        )
        with patch("odb_autodba.services.autodba_service.PlannerAgent.handle_message", return_value=response), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod_db"),
        ):
            payload = get_historical_trends(db_key="prod_db")
        self.assertIsInstance(payload, dict)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("db_key"), "prod_db")
        self.assertIn("## 🔴 Root Cause Analysis", payload.get("rendered_report") or "")
        self.assertIn("## 🔴 Root Cause Correlation", payload.get("rendered_report") or "")
        self._assert_root_cause_shape(payload)
        self._assert_correlation_shape(payload)
        self.assertIn("history_data_sources", payload)
        self.assertEqual(payload["history_data_sources"].get("history_index_status"), "active")

    def test_active_sessions_returns_structured_dict(self) -> None:
        response = PlannerResponse(
            mode="focused_domain_report",
            summary="Active session snapshot collected (2 active session(s)).",
            body_markdown="# Active Sessions",
            supporting_data={"active_sessions": {"active_count": 2}},
        )
        with patch("odb_autodba.services.autodba_service.PlannerAgent.handle_message", return_value=response), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("prod_db"),
        ):
            payload = get_active_sessions(db_key="prod_db")
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("db_key"), "prod_db")
        self.assertIn("## 🔴 Root Cause Analysis", payload.get("rendered_report") or "")
        self.assertIn("## 🔴 Root Cause Correlation", payload.get("rendered_report") or "")
        self._assert_root_cause_shape(payload)
        self._assert_correlation_shape(payload)
        self.assertIn("active_sessions", payload.get("supporting_data") or {})

    def test_investigation_returns_structured_output(self) -> None:
        report = InvestigationReport(
            problem_statement="Investigate lock contention",
            summary="Ran 2 Oracle investigation step(s).",
            likely_cause="Blocking sessions found.",
            evidence=["Step 1..."],
            recommended_next_actions=["Collect ASH deep dive", "Review blocking graph"],
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Find blockers",
                    sql="select * from gv$session",
                    result_preview="Returned 2 row(s).",
                    row_count=2,
                    status="success",
                )
            ],
        )
        with patch("odb_autodba.services.autodba_service.InvestigationAgent.investigate", return_value=report), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("demo"),
        ):
            payload = run_ai_investigation("Investigate lock contention", db_key="demo")
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload.get("summary"), "Ran 2 Oracle investigation step(s).")
        self.assertEqual(payload.get("db_key"), "demo")
        self.assertEqual(payload.get("actions"), ["Collect ASH deep dive", "Review blocking graph"])
        self.assertTrue(payload.get("ok"))
        rendered = payload.get("rendered_report") or ""
        self.assertIn("# AI Investigation Result", rendered)
        self.assertIn("## Question", rendered)
        self.assertIn("## Summary", rendered)
        self.assertIn("## Result", rendered)
        self.assertIn("## Observation", rendered)
        self.assertIn("## 🔴 Root Cause Analysis", rendered)
        self.assertIn("## 🔴 Root Cause Correlation", rendered)
        self._assert_root_cause_shape(payload)
        self._assert_correlation_shape(payload)
        self.assertIsInstance(payload.get("supporting_data"), dict)

    def test_health_check_supporting_data_does_not_expose_ssh_password(self) -> None:
        response = PlannerResponse(
            mode="full_health_report",
            summary="Oracle health check completed.",
            body_markdown="# report",
            supporting_data={
                "host_check": {
                    "host_check_mode": "ssh_remote",
                    "host_check_scope": "unavailable",
                    "host_check_label": "Host metrics unavailable",
                    "host_check_warning": "Remote SSH host check failed: password=***REDACTED***",
                }
            },
        )
        with patch("odb_autodba.services.autodba_service.PlannerAgent.handle_message", return_value=response), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("default__localhost__1521__freepdb1"),
        ):
            payload = run_health_check()
        serialized = str(payload.get("supporting_data") or {})
        self.assertNotIn("hunter2", serialized)
        self.assertIn("***REDACTED***", serialized)

    def test_investigation_routes_history_metric_questions_to_history_service(self) -> None:
        history_payload = {
            "ok": True,
            "db_key": "demo",
            "summary": "Historical cpu consumption resolved from index.",
            "rendered_report": "# Historical CPU Consumption",
            "supporting_data": {"source": "index"},
            "source": "index",
        }
        with patch(
            "odb_autodba.services.autodba_service.answer_history_metric_question",
            return_value=history_payload,
        ) as history_answer, patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("demo"),
        ), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
        ) as investigate:
            payload = run_ai_investigation("What is average CPU consumption history on this database over time?", db_key="demo")
        history_answer.assert_called_once()
        investigate.assert_not_called()
        self.assertEqual(payload.get("source"), "index")
        self.assertIn("Historical CPU Consumption", payload.get("rendered_report") or "")

    def test_sql_id_metadata_question_does_not_route_to_history_metric_service(self) -> None:
        report = InvestigationReport(
            problem_statement="For SQL_ID 0m92022d1yzhs, find whether it exists in memory or AWR history, identify all tables/indexes used by the plan, show when table stats were last analyzed, and tell me if any stats look stale or missing.",
            summary="Ran 1 logical investigation step(s) with 1 SQL execution(s).",
            likely_cause="Collected SQL_ID metadata evidence.",
            plan_type="inventory_read_only_lookup",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Check SQL_ID metadata",
                    sql="select sql_id from v$sql where sql_id='0m92022d1yzhs'",
                    result_preview="Returned 0 row(s).",
                    row_count=0,
                    status="success",
                    result_columns=["sql_id"],
                    result_rows=[],
                )
            ],
        )
        with patch(
            "odb_autodba.services.autodba_service.answer_history_metric_question",
        ) as history_answer, patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("demo"),
        ), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=report,
        ) as investigate:
            payload = run_ai_investigation(
                "For SQL_ID 0m92022d1yzhs, find whether it exists in memory or AWR history, identify all tables/indexes used by the plan, show when table stats were last analyzed, and tell me if any stats look stale or missing.",
                db_key="demo",
            )
        history_answer.assert_not_called()
        investigate.assert_called_once()
        self.assertTrue(payload.get("ok"))

    def test_investigation_thread_memory_runtime_is_disabled(self) -> None:
        report = InvestigationReport(
            problem_statement="List all schemas and tables",
            summary="Ran 1 logical investigation step(s) with 1 SQL execution(s).",
            likely_cause="Collected schema/table inventory.",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="List schemas and tables",
                    sql="select owner, table_name from dba_tables fetch first 10 rows only",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["owner", "table_name"],
                    result_rows=[{"owner": "APP", "table_name": "ORDERS"}],
                )
            ],
        )
        with patch("odb_autodba.services.autodba_service.InvestigationAgent.investigate", return_value=report), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("demo"),
        ):
            payload = run_ai_investigation(
                "List all schemas and tables",
                db_key="demo",
                thread_id="invth_legacy",
                continue_context=True,
            )
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("thread_memory_enabled"), False)
        self.assertEqual(((payload.get("supporting_data") or {}).get("thread_memory_enabled")), False)

    def test_run_health_check_trace_path_isolated_by_db_key(self) -> None:
        def _fake_handle(*_args, **kwargs):
            key = str(kwargs.get("db_key") or "unknown")
            return PlannerResponse(
                mode="full_health_report",
                summary="Oracle health check completed.",
                body_markdown="# report",
                supporting_data={
                    "trace_path": f"/tmp/runtime/databases/{key}/traces/health.json",
                    "host_check": {
                        "host_check_mode": "local_app_host",
                        "host_check_scope": "local_app_host",
                        "host_check_label": "Local AutoDBA app host",
                        "host_check_warning": "These metrics describe the AutoDBA runtime machine, not necessarily the Oracle DB server.",
                    },
                },
            )

        def _target_resolver(db_key=None):
            return self._Target(str(db_key or "default__localhost__1521__freepdb1"))

        with patch("odb_autodba.services.autodba_service.PlannerAgent.handle_message", side_effect=_fake_handle), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            side_effect=_target_resolver,
        ):
            payload_a = run_health_check(db_key="dev__db01__1521__freepdb1")
            payload_b = run_health_check(db_key="prod__db01__1521__pdb1")

        self.assertIn("/dev__db01__1521__freepdb1/", payload_a.get("trace_path") or "")
        self.assertIn("/prod__db01__1521__pdb1/", payload_b.get("trace_path") or "")


if __name__ == "__main__":
    unittest.main()
