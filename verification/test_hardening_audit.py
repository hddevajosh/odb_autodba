from __future__ import annotations

import inspect
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.mcp import jobs as mcp_jobs
from odb_autodba.rag import trace_store
from odb_autodba.rag.trace_store import append_health_run_trace


class HardeningAuditTests(unittest.TestCase):
    def test_trace_writes_use_db_key_runtime_tree_not_legacy_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            env = {
                "ODB_AUTODBA_RUNTIME_ROOT": str(Path(td) / "runtime" / "databases"),
                "ODB_AUTODBA_ENVIRONMENT": "unit",
                "ORACLE_HOST": "db-host",
                "ORACLE_PORT": "1521",
                "ORACLE_SERVICE_NAME": "freepdb1",
                "ORACLE_USER": "system",
                "ORACLE_PASSWORD": "unit-secret",
            }
            db_key = "audit__db__1521__pdb1"
            with patch.dict(os.environ, env, clear=False):
                record = append_health_run_trace(
                    {
                        "run_id": "audit1",
                        "completed_at": "2026-05-01T00:00:00+00:00",
                        "database_name": "AUDITDB",
                        "summary": "ok",
                        "overall_status": "OK",
                        "metrics": {},
                        "issues": [],
                    },
                    rebuild_artifacts=False,
                    db_key=db_key,
                )
            self.assertIn(f"/runtime/databases/{db_key}/traces/", str(record.trace_path))
            self.assertFalse((Path(td) / "runtime" / "traces").exists())
            self.assertFalse((Path(td) / "runs" / "traces").exists())

    def test_legacy_read_fallback_is_disabled_by_default_and_env_gated(self) -> None:
        source = inspect.getsource(trace_store._allow_legacy_read_fallback)
        self.assertIn("ODB_AUTODBA_ALLOW_LEGACY_READ_FALLBACK", source)
        with patch.dict(os.environ, {"ODB_AUTODBA_ALLOW_LEGACY_READ_FALLBACK": ""}, clear=False):
            self.assertFalse(trace_store._allow_legacy_read_fallback(db_key="anything"))

    def test_trace_writer_has_no_stdout_print_and_logs_rebuild_failures(self) -> None:
        source = inspect.getsource(trace_store.append_health_run_trace)
        self.assertNotIn("print(", source)
        self.assertIn("LOGGER.warning", source)

    def test_ui_mcp_fallback_does_not_dump_raw_json_by_default(self) -> None:
        rendered = gradio_app._render_mcp_result(
            {"status": "completed", "result": {"supporting_data": {"raw": "value"}}},
            fallback_title="Oracle Historical Trends",
        )
        self.assertIn("No rendered report or summary was provided", rendered)
        self.assertNotIn("Compact job payload", rendered)
        self.assertNotIn('"supporting_data"', rendered)

    def test_job_sanitizer_recognizes_secret_like_keys(self) -> None:
        payload = mcp_jobs._sanitize_value({"api_key": "k", "private_key": "p", "password_env": "ORACLE_PASSWORD"})
        self.assertEqual(payload.get("api_key"), "***REDACTED***")
        self.assertEqual(payload.get("private_key"), "***REDACTED***")
        self.assertEqual(payload.get("password_env"), "ORACLE_PASSWORD")


if __name__ == "__main__":
    unittest.main()
