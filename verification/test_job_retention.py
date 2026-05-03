from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from odb_autodba.mcp.jobs import cleanup_old_jobs, create_job, get_job, update_job


class JobRetentionTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def test_cleanup_removes_old_completed_and_failed_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"ODB_AUTODBA_JOBS_DIR": td},
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            old_completed = create_job("health_check", db_key="db1")
            old_failed = create_job("historical_trends", db_key="db1")
            fresh_completed = create_job("active_sessions", db_key="db1")
            old_stamp = (datetime.now(UTC) - timedelta(hours=96)).isoformat()
            new_stamp = (datetime.now(UTC) - timedelta(hours=1)).isoformat()

            update_job(old_completed["job_id"], status="completed", completed_at=old_stamp)
            update_job(old_failed["job_id"], status="failed", completed_at=old_stamp)
            update_job(fresh_completed["job_id"], status="completed", completed_at=new_stamp)

            removed = cleanup_old_jobs(retention_hours=72)

            old_completed_payload = get_job(old_completed["job_id"])
            old_failed_payload = get_job(old_failed["job_id"])
            fresh_payload = get_job(fresh_completed["job_id"])

        self.assertEqual(removed, 2)
        self.assertIsNone(old_completed_payload)
        self.assertIsNone(old_failed_payload)
        self.assertIsNotNone(fresh_payload)

    def test_cleanup_never_removes_running_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"ODB_AUTODBA_JOBS_DIR": td},
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            running = create_job("health_check", db_key="db1")
            old_start = (datetime.now(UTC) - timedelta(hours=120)).isoformat()
            update_job(running["job_id"], status="running", started_at=old_start)

            removed = cleanup_old_jobs(retention_hours=1)
            payload = get_job(running["job_id"])

        self.assertEqual(removed, 0)
        self.assertIsNotNone(payload)
        self.assertEqual((payload or {}).get("status"), "running")


if __name__ == "__main__":
    unittest.main()
