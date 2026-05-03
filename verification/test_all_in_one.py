from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

from odb_autodba import all_in_one


class AllInOneLauncherTests(unittest.TestCase):
    def test_builds_default_base_url_from_host_port(self) -> None:
        self.assertEqual(
            all_in_one.build_default_base_url("127.0.0.1", 8000),
            "http://127.0.0.1:8000",
        )

    def test_detects_existing_mcp_server_via_root(self) -> None:
        with patch("odb_autodba.all_in_one._get_json", return_value={"ok": True}) as mock_get:
            self.assertTrue(all_in_one.is_mcp_running("http://127.0.0.1:8000"))
        mock_get.assert_called_once_with("http://127.0.0.1:8000/", timeout_seconds=2.0)

    def test_sets_gradio_mcp_env_vars(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            all_in_one.configure_gradio_mcp_env("http://127.0.0.1:8000/")
            self.assertEqual(os.getenv("ODB_AUTODBA_USE_MCP"), "true")
            self.assertEqual(os.getenv("ODB_AUTODBA_MCP_BASE_URL"), "http://127.0.0.1:8000")
            self.assertEqual(os.getenv("ODB_AUTODBA_MCP_FALLBACK_LOCAL"), "true")

    def test_does_not_start_duplicate_mcp_when_ready(self) -> None:
        with patch("odb_autodba.all_in_one.resolve_mcp_host_port", return_value=("127.0.0.1", 8000)), patch(
            "odb_autodba.all_in_one.resolve_mcp_base_url", return_value="http://127.0.0.1:8000"
        ), patch("odb_autodba.all_in_one.resolve_gradio_host_port", return_value=("127.0.0.1", 7860)), patch(
            "odb_autodba.all_in_one.is_mcp_running", return_value=True
        ), patch("odb_autodba.all_in_one.wait_for_mcp_ready", return_value=True), patch(
            "odb_autodba.all_in_one.start_mcp_subprocess"
        ) as mock_start, patch("odb_autodba.all_in_one.shutdown_mcp_subprocess") as mock_shutdown:
            all_in_one.run_all_in_one(launch_gradio_fn=lambda: None)

        mock_start.assert_not_called()
        mock_shutdown.assert_not_called()

    def test_starts_and_stops_owned_mcp_when_not_running(self) -> None:
        fake_proc = MagicMock()
        fake_proc.poll.return_value = None

        with patch("odb_autodba.all_in_one.resolve_mcp_host_port", return_value=("127.0.0.1", 8000)), patch(
            "odb_autodba.all_in_one.resolve_mcp_base_url", return_value="http://127.0.0.1:8000"
        ), patch("odb_autodba.all_in_one.resolve_gradio_host_port", return_value=("127.0.0.1", 7860)), patch(
            "odb_autodba.all_in_one.is_mcp_running", return_value=False
        ), patch("odb_autodba.all_in_one.start_mcp_subprocess", return_value=fake_proc) as mock_start, patch(
            "odb_autodba.all_in_one.wait_for_mcp_ready", return_value=True
        ), patch("odb_autodba.all_in_one.shutdown_mcp_subprocess") as mock_shutdown:
            all_in_one.run_all_in_one(launch_gradio_fn=lambda: None)

        mock_start.assert_called_once()
        mock_shutdown.assert_called_once_with(fake_proc)

    def test_startup_timeout_raises_clean_error_and_stops_owned_proc(self) -> None:
        fake_proc = MagicMock()
        fake_proc.poll.return_value = None

        with patch("odb_autodba.all_in_one.resolve_mcp_host_port", return_value=("127.0.0.1", 8000)), patch(
            "odb_autodba.all_in_one.resolve_mcp_base_url", return_value="http://127.0.0.1:8000"
        ), patch("odb_autodba.all_in_one.resolve_gradio_host_port", return_value=("127.0.0.1", 7860)), patch(
            "odb_autodba.all_in_one.is_mcp_running", return_value=False
        ), patch("odb_autodba.all_in_one.start_mcp_subprocess", return_value=fake_proc), patch(
            "odb_autodba.all_in_one.wait_for_mcp_ready", return_value=False
        ), patch("odb_autodba.all_in_one.shutdown_mcp_subprocess") as mock_shutdown:
            with self.assertRaises(RuntimeError) as ctx:
                all_in_one.run_all_in_one(launch_gradio_fn=lambda: None, readiness_timeout_seconds=0.1)

        self.assertIn("readiness check failed", str(ctx.exception).lower())
        mock_shutdown.assert_called_once_with(fake_proc)


if __name__ == "__main__":
    unittest.main()
