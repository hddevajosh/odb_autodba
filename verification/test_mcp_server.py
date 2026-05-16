from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import BackgroundTasks

from odb_autodba.mcp.server import (
    AwrAnalyzeRequest,
    BlockingAnalyzeRequest,
    HealthRequest,
    HistoryMetricRequest,
    HistoryRequest,
    InvestigateRequest,
    SqlIdAnalyzeRequest,
    SessionsRequest,
    awr_analyze,
    blocking_analyze,
    databases,
    health,
    history_metric,
    history,
    investigate,
    job_by_id,
    jobs,
    root,
    sql_id_analyze,
    sessions,
)


class McpServerTests(unittest.TestCase):
    def test_root_returns_ok_true(self) -> None:
        payload = root()
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("service"), "odb_autodba_mcp")

    def test_databases_returns_default_target_without_password(self) -> None:
        with patch(
            "odb_autodba.mcp.server.list_oracle_targets_safe",
            return_value=[
                {
                    "db_key": "default__localhost__1521__freepdb1",
                    "display_name": "default:localhost:1521:FREEPDB1",
                    "environment": "default",
                    "host": "localhost",
                    "port": 1521,
                    "service_name": "FREEPDB1",
                    "sid": None,
                    "pdb_name": None,
                    "username": "system",
                    "password_env_present": True,
                    "tags": ["local"],
                    "source": "/tmp/oracle_targets.yaml",
                }
            ],
        ):
            payload = databases()
        self.assertTrue(payload.get("ok"))
        rows = payload.get("databases") or []
        self.assertTrue(rows)
        self.assertNotIn("password", rows[0])

    def test_databases_returns_all_registry_targets(self) -> None:
        with patch(
            "odb_autodba.mcp.server.list_oracle_targets_safe",
            return_value=[
                {"db_key": "dev__localhost__1521__freepdb1", "display_name": "Dev", "host": "localhost", "port": 1521, "username": "system"},
                {"db_key": "prod__prod-db01__1521__pdb1", "display_name": "Prod", "host": "prod-db01", "port": 1521, "username": "app_monitor"},
            ],
        ):
            payload = databases()
        rows = payload.get("databases") or []
        self.assertEqual(len(rows), 2)

    def test_unknown_db_key_returns_clean_error_payload(self) -> None:
        bg = BackgroundTasks()
        with patch("odb_autodba.mcp.server.create_job", side_effect=ValueError("Unknown db_key 'missing'")):
            payload = health(HealthRequest(db_key="missing"), background_tasks=bg)
        self.assertFalse(payload.get("ok"))
        self.assertEqual(payload.get("error_type"), "ValueError")
        self.assertIn("Unknown db_key", str(payload.get("error")))

    def test_post_health_returns_job_id_immediately(self) -> None:
        bg = BackgroundTasks()
        with patch(
            "odb_autodba.mcp.server.create_job",
            return_value={
                "job_id": "job1",
                "status": "pending",
                "db_key": "db1",
                "job_type": "health_check",
            },
        ):
            payload = health(HealthRequest(db_key=None), background_tasks=bg)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "job1")
        self.assertEqual(payload.get("job_type"), "health_check")
        self.assertEqual(len(bg.tasks), 1)

    def test_post_history_returns_job_id_immediately(self) -> None:
        bg = BackgroundTasks()
        with patch(
            "odb_autodba.mcp.server.create_job",
            return_value={
                "job_id": "job2",
                "status": "pending",
                "db_key": "db1",
                "job_type": "historical_trends",
            },
        ):
            payload = history(HistoryRequest(db_key=None), background_tasks=bg)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "job2")
        self.assertEqual(payload.get("job_type"), "historical_trends")

    def test_post_sessions_returns_job_id_immediately(self) -> None:
        bg = BackgroundTasks()
        with patch(
            "odb_autodba.mcp.server.create_job",
            return_value={
                "job_id": "job3",
                "status": "pending",
                "db_key": "db1",
                "job_type": "active_sessions",
            },
        ):
            payload = sessions(SessionsRequest(db_key=None), background_tasks=bg)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "job3")
        self.assertEqual(payload.get("job_type"), "active_sessions")

    def test_get_job_returns_payload(self) -> None:
        with patch(
            "odb_autodba.mcp.server.get_job",
            return_value={"job_id": "job1", "status": "completed", "result": {"summary": "ok"}},
        ):
            payload = job_by_id("job1")
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "job1")
        self.assertEqual(payload.get("status"), "completed")

    def test_get_jobs_supports_filtering(self) -> None:
        with patch(
            "odb_autodba.mcp.server.list_jobs",
            return_value=[{"job_id": "job1", "status": "pending"}],
        ) as mock_list:
            payload = jobs(
                limit=10,
                status="pending",
                db_key="db1",
                job_type="health_check",
                created_after="2026-05-01T00:00:00+00:00",
                created_before="2026-05-02T00:00:00+00:00",
            )
        self.assertTrue(payload.get("ok"))
        self.assertEqual(len(payload.get("jobs") or []), 1)
        mock_list.assert_called_once_with(
            limit=10,
            status="pending",
            db_key="db1",
            job_type="health_check",
            created_after="2026-05-01T00:00:00+00:00",
            created_before="2026-05-02T00:00:00+00:00",
        )

    def test_post_investigate_empty_question_returns_validation_error(self) -> None:
        payload = investigate(InvestigateRequest(db_key=None, question="  "), background_tasks=BackgroundTasks())
        self.assertFalse(payload.get("ok"))
        self.assertEqual(payload.get("endpoint"), "/investigate")
        self.assertEqual(payload.get("error_type"), "ValidationError")

    def test_post_investigate_accepts_problem_statement_alias(self) -> None:
        bg = BackgroundTasks()
        with patch(
            "odb_autodba.mcp.server.create_job",
            return_value={
                "job_id": "job_inv_alias",
                "status": "pending",
                "db_key": "db1",
                "job_type": "investigation",
            },
        ) as create_mock:
            payload = investigate(InvestigateRequest(db_key="db1", problem_statement="List all the tables in database please?"), background_tasks=bg)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "job_inv_alias")
        kwargs = create_mock.call_args.kwargs
        sent_payload = kwargs.get("payload") or {}
        self.assertEqual(sent_payload.get("problem_statement"), "List all the tables in database please?")
        self.assertEqual(sent_payload.get("question"), "List all the tables in database please?")

    def test_post_sql_id_analyze_returns_job_id_immediately(self) -> None:
        bg = BackgroundTasks()
        with patch(
            "odb_autodba.mcp.server.create_job",
            return_value={
                "job_id": "job_sql_1",
                "status": "pending",
                "db_key": "db1",
                "job_type": "sql_id_analysis",
            },
        ):
            payload = sql_id_analyze(SqlIdAnalyzeRequest(db_key=None, sql_id="daxra005nhfz2"), background_tasks=bg)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "job_sql_1")
        self.assertEqual(payload.get("job_type"), "sql_id_analysis")
        self.assertEqual(len(bg.tasks), 1)

    def test_post_history_metric_returns_job_id(self) -> None:
        bg = BackgroundTasks()
        with patch(
            "odb_autodba.mcp.server.create_job",
            return_value={
                "job_id": "job_hist_metric",
                "status": "pending",
                "db_key": "db1",
                "job_type": "history_metric_question",
            },
        ):
            payload = history_metric(HistoryMetricRequest(db_key=None, question="average cpu history"), background_tasks=bg)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_type"), "history_metric_question")

    def test_post_awr_analyze_returns_job_id(self) -> None:
        bg = BackgroundTasks()
        with patch(
            "odb_autodba.mcp.server.create_job",
            return_value={
                "job_id": "job_awr",
                "status": "pending",
                "db_key": "db1",
                "job_type": "awr_analysis",
            },
        ):
            payload = awr_analyze(AwrAnalyzeRequest(db_key=None, question="analyze awr"), background_tasks=bg)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_type"), "awr_analysis")

    def test_post_blocking_analyze_returns_job_id(self) -> None:
        bg = BackgroundTasks()
        with patch(
            "odb_autodba.mcp.server.create_job",
            return_value={
                "job_id": "job_blocking",
                "status": "pending",
                "db_key": "db1",
                "job_type": "blocking_analysis",
            },
        ):
            payload = blocking_analyze(BlockingAnalyzeRequest(db_key=None), background_tasks=bg)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_type"), "blocking_analysis")


if __name__ == "__main__":
    unittest.main()
