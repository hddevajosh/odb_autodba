from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from odb_autodba.mcp.jobs import create_job, get_job, list_jobs, run_job, update_job


class JobConcurrencyTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def test_job_type_limit_keeps_extra_jobs_pending(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_JOBS_DIR": td,
                "ODB_AUTODBA_MAX_HEALTH_JOBS": "1",
                "ODB_AUTODBA_MAX_TOTAL_JOBS": "5",
                "ODB_AUTODBA_DEDUP_JOBS": "false",
            },
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            first = create_job("health_check", db_key="db1")
            second = create_job("health_check", db_key="db1")
            update_job(first["job_id"], status="running", started_at="2026-05-01T00:00:00+00:00")
            with patch("odb_autodba.mcp.jobs.run_health_check", return_value={"summary": "ok", "rendered_report": "x"}):
                run_job(second["job_id"])
            second_payload = get_job(second["job_id"]) or {}

        self.assertEqual(second_payload.get("status"), "pending")
        self.assertIn("limit", str(second_payload.get("queue_reason") or ""))

    def test_total_limit_keeps_jobs_pending(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_JOBS_DIR": td,
                "ODB_AUTODBA_MAX_TOTAL_JOBS": "1",
                "ODB_AUTODBA_MAX_INVESTIGATION_JOBS": "2",
                "ODB_AUTODBA_DEDUP_JOBS": "false",
            },
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            running = create_job("health_check", db_key="db1")
            blocked = create_job("investigation", db_key="db1", payload={"question": "size?"})
            update_job(running["job_id"], status="running", started_at="2026-05-01T00:00:00+00:00")
            with patch("odb_autodba.mcp.jobs.run_ai_investigation", return_value={"summary": "ok", "rendered_report": "x"}):
                run_job(blocked["job_id"])
            blocked_payload = get_job(blocked["job_id"]) or {}

        self.assertEqual(blocked_payload.get("status"), "pending")
        self.assertEqual(blocked_payload.get("queue_reason"), "total_running_limit_reached")

    def test_investigation_timeout_marks_job_failed(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_JOBS_DIR": td,
                "ODB_AUTODBA_INVESTIGATION_TIMEOUT_SECONDS": "1",
                "ODB_AUTODBA_DEDUP_JOBS": "false",
            },
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            job = create_job("investigation", db_key="db1", payload={"question": "size?"})

            def _slow_investigation(*args, **kwargs):
                time.sleep(1.2)
                return {"summary": "late"}

            with patch("odb_autodba.mcp.jobs.run_ai_investigation", side_effect=_slow_investigation):
                run_job(job["job_id"])
            payload = get_job(job["job_id"]) or {}

        self.assertEqual(payload.get("status"), "failed")
        self.assertEqual(payload.get("error_type"), "TimeoutError")
        self.assertIn("timed out", str(payload.get("error") or "").lower())

    def test_atomic_writes_leave_valid_json_under_parallel_updates(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"ODB_AUTODBA_JOBS_DIR": td},
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            job = create_job("health_check", db_key="db1")
            job_path = Path(td) / f"{job['job_id']}.json"

            def _writer(index: int) -> None:
                update_job(job["job_id"], error=f"error-{index}", error_type="RuntimeError")

            with ThreadPoolExecutor(max_workers=8) as pool:
                for idx in range(40):
                    pool.submit(_writer, idx)

            # Final file must be parseable JSON even after parallel updates.
            text = job_path.read_text(encoding="utf-8")
            parsed = json.loads(text)

        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed.get("job_id"), job["job_id"])

    def test_list_jobs_filters_and_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"ODB_AUTODBA_JOBS_DIR": td},
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            old = create_job("health_check", db_key="db1")
            new = create_job("investigation", db_key="db1", payload={"question": "size?"})
            update_job(old["job_id"], created_at="2026-05-01T00:00:00+00:00")
            update_job(new["job_id"], created_at="2026-05-01T01:00:00+00:00")
            rows = list_jobs(limit=10, db_key="db1", created_after="2026-05-01T00:30:00+00:00")

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("job_id"), new["job_id"])


if __name__ == "__main__":
    unittest.main()
