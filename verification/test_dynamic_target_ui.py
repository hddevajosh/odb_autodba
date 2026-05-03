from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.target_registry import clear_transient_targets, list_oracle_targets_safe


class DynamicTargetUiTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_transient_targets()

    def tearDown(self) -> None:
        clear_transient_targets()

    def test_dynamic_db_key_generated_and_password_not_in_key_or_safe_payload(self) -> None:
        with patch("odb_autodba.frontend.gradio_app._test_connection_for_target", return_value=("FREE", "READ WRITE")):
            update, _, _, _, _ = gradio_app._test_and_use_target_ui(
                [(
                    "Local Oracle Free — default__localhost__1521__freepdb1",
                    "default__localhost__1521__freepdb1",
                )],
                {"default__localhost__1521__freepdb1": "Local Oracle Free — default__localhost__1521__freepdb1"},
                "dev",
                "localhost",
                "1521",
                "FREEPDB1",
                "",
                "",
                "system",
                "secret-pass",
                "",
                "normal",
                "Local Temp",
            )

        db_key = update.get("value")
        self.assertEqual(db_key, "dev__localhost__1521__freepdb1")
        self.assertNotIn("secret-pass", db_key)

        safe_rows = list_oracle_targets_safe()
        selected = [row for row in safe_rows if row.get("db_key") == db_key]
        self.assertTrue(selected)
        text = str(selected[0])
        self.assertNotIn("secret-pass", text)
        self.assertNotIn("password", text.lower())

    def test_selected_dynamic_db_key_passed_to_local_submit(self) -> None:
        with patch(
            "odb_autodba.frontend.gradio_app._submit_message_with_target",
            return_value=([], [], {}, "md", False, object(), "", "history"),
        ) as submit_mock:
            gradio_app._submit_message_ui(
                "Check health of my Oracle database",
                [],
                {},
                "dev__localhost__1521__freepdb1",
                {"dev__localhost__1521__freepdb1": "Local Temp — dev__localhost__1521__freepdb1"},
            )
        args, _ = submit_mock.call_args
        self.assertEqual(args[3], "dev__localhost__1521__freepdb1")

    def test_runtime_password_dynamic_target_mcp_mode_shows_limitation_when_no_fallback(self) -> None:
        with patch("odb_autodba.frontend.gradio_app._test_connection_for_target", return_value=("FREE", "READ WRITE")):
            update, labels, _, _, _ = gradio_app._test_and_use_target_ui(
                [("Local Oracle Free — default__localhost__1521__freepdb1", "default__localhost__1521__freepdb1")],
                {"default__localhost__1521__freepdb1": "Local Oracle Free — default__localhost__1521__freepdb1"},
                "dev",
                "host1",
                "1521",
                "PDB1",
                "",
                "",
                "monitor",
                "runtime-secret",
                "",
                "normal",
                "Runtime Target",
            )

        db_key = update.get("value")
        with patch("odb_autodba.frontend.gradio_app.use_mcp_enabled", return_value=True), patch(
            "odb_autodba.frontend.gradio_app.mcp_fallback_local_enabled", return_value=False
        ):
            out = gradio_app._submit_message_ui(
                "Check health of my Oracle database",
                [],
                {},
                db_key,
                labels,
            )
        assistant = out[0][-1]["content"]
        self.assertIn("MCP limitation", assistant)

    def test_invalid_connection_shows_friendly_error(self) -> None:
        with patch("odb_autodba.frontend.gradio_app._test_connection_for_target", side_effect=RuntimeError("password=abc123")):
            _, _, _, _, status = gradio_app._test_and_use_target_ui(
                [("Local Oracle Free — default__localhost__1521__freepdb1", "default__localhost__1521__freepdb1")],
                {"default__localhost__1521__freepdb1": "Local Oracle Free — default__localhost__1521__freepdb1"},
                "dev",
                "host1",
                "1521",
                "PDB1",
                "",
                "",
                "monitor",
                "secret",
                "",
                "normal",
                "x",
            )
        self.assertIn("Target test failed", status)
        self.assertNotIn("abc123", status)


if __name__ == "__main__":
    unittest.main()
