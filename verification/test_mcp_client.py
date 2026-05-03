from __future__ import annotations

import io
import json
import os
import unittest
from unittest.mock import patch

from odb_autodba.mcp import client


class _FakeHttpResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class McpClientTests(unittest.TestCase):
    def test_defaults_when_env_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(client.use_mcp_enabled())
            self.assertEqual(client.get_mcp_base_url(), "http://127.0.0.1:8000")
            self.assertTrue(client.mcp_fallback_local_enabled())
            self.assertEqual(client.get_mcp_poll_seconds(), 1.0)
            self.assertEqual(client.get_mcp_poll_timeout_seconds(), 300.0)

    def test_alias_env_flags_supported(self) -> None:
        with patch.dict(
            os.environ,
            {
                "PGAUTODBA_USE_MCP": "true",
                "PGAUTODBA_MCP_BASE_URL": "http://localhost:9999",
                "PGAUTODBA_MCP_FALLBACK_LOCAL": "false",
            },
            clear=True,
        ):
            self.assertTrue(client.use_mcp_enabled())
            self.assertEqual(client.get_mcp_base_url(), "http://localhost:9999")
            self.assertFalse(client.mcp_fallback_local_enabled())

    def test_submit_health_job_posts_json(self) -> None:
        with patch("urllib.request.urlopen", return_value=_FakeHttpResponse({"ok": True, "job_id": "j1"})):
            payload = client.submit_health_job()
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "j1")

    def test_submit_sessions_job_posts_json(self) -> None:
        with patch("urllib.request.urlopen", return_value=_FakeHttpResponse({"ok": True, "job_id": "s1"})):
            payload = client.submit_sessions_job()
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "s1")

    def test_submit_history_metric_job_posts_json(self) -> None:
        with patch("urllib.request.urlopen", return_value=_FakeHttpResponse({"ok": True, "job_id": "hm1"})):
            payload = client.submit_history_metric_job("average cpu history")
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "hm1")

    def test_submit_awr_job_posts_json(self) -> None:
        with patch("urllib.request.urlopen", return_value=_FakeHttpResponse({"ok": True, "job_id": "awr1"})):
            payload = client.submit_awr_analysis_job("analyze awr")
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "awr1")

    def test_submit_blocking_job_posts_json(self) -> None:
        with patch("urllib.request.urlopen", return_value=_FakeHttpResponse({"ok": True, "job_id": "blk1"})):
            payload = client.submit_blocking_analysis_job()
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("job_id"), "blk1")

    def test_poll_job_completes(self) -> None:
        with patch("odb_autodba.mcp.client.get_job", side_effect=[{"status": "running"}, {"status": "completed", "ok": True}]):
            payload = client.poll_job("job1", timeout_seconds=3, poll_seconds=0.01)
        self.assertEqual(payload.get("status"), "completed")

    def test_poll_job_timeout(self) -> None:
        with patch("odb_autodba.mcp.client.get_job", return_value={"status": "running"}):
            payload = client.poll_job("job1", timeout_seconds=0.2, poll_seconds=0.05)
        self.assertFalse(payload.get("ok"))
        self.assertEqual(payload.get("error_type"), "TimeoutError")

    def test_connection_error_sanitized(self) -> None:
        with patch("urllib.request.urlopen", side_effect=RuntimeError("password=secret123")):
            payload = client.submit_history_job()
        self.assertFalse(payload.get("ok"))
        self.assertNotIn("secret123", str(payload))


if __name__ == "__main__":
    unittest.main()
