from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app


class GradioRecentJobsTests(unittest.TestCase):
    def test_recent_jobs_requires_mcp_mode(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=False):
            text = gradio_app._recent_jobs_markdown("db1")
        self.assertIn("MCP mode", text)

    def test_recent_jobs_renders_compact_table(self) -> None:
        payload = {
            "ok": True,
            "jobs": [
                {
                    "job_id": "abc123",
                    "job_type": "investigation",
                    "status": "completed",
                    "db_key": "db1",
                    "created_at": "2026-05-01T01:00:00+00:00",
                    "completed_at": "2026-05-01T01:00:02+00:00",
                    "result": {"summary": "Investigated database size successfully"},
                }
            ],
        }
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.list_mcp_jobs", return_value=payload
        ) as mocked:
            text = gradio_app._recent_jobs_markdown("db1", limit=10)
        mocked.assert_called_once_with(limit=10, db_key="db1")
        self.assertIn("| job_id | type | status |", text)
        self.assertIn("abc123", text)
        self.assertIn("Investigated database size successfully", text)

    def test_recent_jobs_handles_mcp_error(self) -> None:
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.list_mcp_jobs", return_value={"ok": False, "error": "connection refused"}
        ):
            text = gradio_app._recent_jobs_markdown("db1", limit=10)
        self.assertIn("Recent jobs unavailable", text)


if __name__ == "__main__":
    unittest.main()
