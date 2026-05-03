from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from odb_autodba.mcp.jobs import create_job, get_job, update_job


class JobDedupTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def test_identical_pending_job_returns_existing_job_id(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_JOBS_DIR": td,
                "ODB_AUTODBA_DEDUP_JOBS": "true",
                "ODB_AUTODBA_DEDUP_WINDOW_SECONDS": "60",
            },
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            first = create_job("investigation", db_key="db1", payload={"question": "What is DB size?"})
            second = create_job("investigation", db_key="db1", payload={"question": "What is DB size?"})

        self.assertEqual(first["job_id"], second["job_id"])
        self.assertTrue(bool(second.get("deduped")))

    def test_dedup_ignores_jobs_outside_window(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_JOBS_DIR": td,
                "ODB_AUTODBA_DEDUP_JOBS": "true",
                "ODB_AUTODBA_DEDUP_WINDOW_SECONDS": "60",
            },
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            first = create_job("investigation", db_key="db1", payload={"question": "What is DB size?"})
            old_created = (datetime.now(UTC) - timedelta(seconds=120)).isoformat()
            update_job(first["job_id"], created_at=old_created)
            second = create_job("investigation", db_key="db1", payload={"question": "What is DB size?"})

        self.assertNotEqual(first["job_id"], second["job_id"])

    def test_dedup_does_not_match_different_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_JOBS_DIR": td,
                "ODB_AUTODBA_DEDUP_JOBS": "true",
                "ODB_AUTODBA_DEDUP_WINDOW_SECONDS": "60",
            },
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            first = create_job("investigation", db_key="db1", payload={"question": "What is DB size?"})
            second = create_job("investigation", db_key="db1", payload={"question": "Show active sessions"})

        self.assertNotEqual(first["job_id"], second["job_id"])

    def test_dedup_matches_running_job(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_JOBS_DIR": td,
                "ODB_AUTODBA_DEDUP_JOBS": "true",
                "ODB_AUTODBA_DEDUP_WINDOW_SECONDS": "60",
            },
            clear=False,
        ), patch("odb_autodba.mcp.jobs.get_oracle_target", return_value=self._Target("db1")):
            first = create_job("investigation", db_key="db1", payload={"question": "What is DB size?"})
            update_job(first["job_id"], status="running", started_at=datetime.now(UTC).isoformat())
            second = create_job("investigation", db_key="db1", payload={"question": "What is DB size?"})
            running = get_job(first["job_id"]) or {}

        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(running.get("status"), "running")


if __name__ == "__main__":
    unittest.main()
