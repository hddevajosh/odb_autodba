from __future__ import annotations

from collections.abc import Iterable
import unittest
from unittest.mock import patch

from odb_autodba.frontend import gradio_app
from odb_autodba.target_registry import clear_transient_targets


class GradioTargetSelectorTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_transient_targets()

    def tearDown(self) -> None:
        clear_transient_targets()

    def _component_id_by_elem_id(self, config: dict, elem_id: str) -> int:
        for component in config.get("components", []):
            props = component.get("props") or {}
            if props.get("elem_id") == elem_id:
                return int(component["id"])
        raise AssertionError(f"Component with elem_id={elem_id!r} not found")

    def _component_id_by_label(self, config: dict, label: str) -> int:
        for component in config.get("components", []):
            props = component.get("props") or {}
            if props.get("label") == label:
                return int(component["id"])
        raise AssertionError(f"Component with label={label!r} not found")

    def _component_id_by_markdown_value(self, config: dict, text: str) -> int:
        for component in config.get("components", []):
            if component.get("type") != "markdown":
                continue
            props = component.get("props") or {}
            if props.get("value") == text:
                return int(component["id"])
        raise AssertionError(f"Markdown component with value={text!r} not found")

    def _layout_descendants(self, node: dict) -> set[int]:
        ids: set[int] = set()
        node_id = node.get("id")
        if isinstance(node_id, int):
            ids.add(node_id)
        children = node.get("children") if isinstance(node.get("children"), Iterable) else []
        for child in children:
            if isinstance(child, dict):
                ids.update(self._layout_descendants(child))
        return ids

    def _descendants_by_node_id(self, config: dict) -> dict[int, set[int]]:
        by_node: dict[int, set[int]] = {}

        def walk(node: dict) -> None:
            node_id = node.get("id")
            if isinstance(node_id, int):
                by_node[node_id] = self._layout_descendants(node)
            for child in node.get("children") or []:
                if isinstance(child, dict):
                    walk(child)

        walk(config.get("layout") or {})
        return by_node

    def test_dropdown_choices_created_from_registry(self) -> None:
        with patch(
            "odb_autodba.frontend.gradio_app.list_oracle_targets_safe",
            return_value=[
                {
                    "db_key": "default__localhost__1521__freepdb1",
                    "display_name": "Local Oracle Free",
                },
                {
                    "db_key": "prod__db01__1521__pdb1",
                    "display_name": "PROD DB01 PDB1",
                },
            ],
        ):
            selector = gradio_app._target_selector_context()

        choices = selector.get("choices") or []
        self.assertEqual(len(choices), 2)
        self.assertEqual(choices[0][1], "default__localhost__1521__freepdb1")
        self.assertIn("Local Oracle Free", choices[0][0])
        self.assertIn("default__localhost__1521__freepdb1", choices[0][0])

    def test_one_target_still_renders_dropdown(self) -> None:
        with patch(
            "odb_autodba.frontend.gradio_app.list_oracle_targets_safe",
            return_value=[
                {
                    "db_key": "default__localhost__1521__freepdb1",
                    "display_name": "Local Oracle Free",
                }
            ],
        ):
            selector = gradio_app._target_selector_context()

        choices = selector.get("choices") or []
        self.assertEqual(len(choices), 1)
        self.assertEqual(selector.get("default_key"), "default__localhost__1521__freepdb1")

    def test_target_selector_and_ad_hoc_fields_render_inside_collapsed_oracle_target(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()

        center_panel_id = self._component_id_by_elem_id(config, "center-panel")
        oracle_target_id = self._component_id_by_label(config, "Oracle Target")
        dropdown_id = self._component_id_by_label(config, "Target Database")
        host_id = self._component_id_by_label(config, "Host")
        descendants = self._descendants_by_node_id(config)
        center_descendants = descendants.get(center_panel_id) or set()
        oracle_target_descendants = descendants.get(oracle_target_id) or set()

        self.assertIn(oracle_target_id, center_descendants)
        self.assertIn(dropdown_id, center_descendants)
        self.assertIn(host_id, center_descendants)
        self.assertIn(dropdown_id, oracle_target_descendants)
        self.assertIn(host_id, oracle_target_descendants)
        oracle_props = next(
            component.get("props") or {}
            for component in config.get("components", [])
            if int(component.get("id") or -1) == oracle_target_id
        )
        self.assertFalse(bool(oracle_props.get("open")))

    def test_workflow_shortcuts_render_inside_action_rail(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()

        rail_id = self._component_id_by_elem_id(config, "action-rail")
        shortcuts_title_id = self._component_id_by_markdown_value(config, "Workflow Shortcuts")
        descendants = self._descendants_by_node_id(config)
        rail_descendants = descendants.get(rail_id) or set()

        self.assertIn(shortcuts_title_id, rail_descendants)

    def test_layout_css_includes_non_overlapping_rail_rules(self) -> None:
        css = gradio_app.APP_CSS
        self.assertIn("#app-shell", css)
        self.assertIn("max-width: 1440px;", css)
        self.assertIn("#center-panel {\n  min-width: 0;\n}", css)
        self.assertIn("top: 88px;", css)
        self.assertIn("width: 210px;", css)
        self.assertIn("margin-left: 252px;", css)

    def test_registry_failure_falls_back_to_default_target_with_warning(self) -> None:
        class _DefaultTarget:
            db_key = "default__localhost__1521__freepdb1"
            display_name = "default:localhost:1521:FREEPDB1"

            def safe_dict(self):
                return {
                    "db_key": self.db_key,
                    "display_name": self.display_name,
                }

        with patch(
            "odb_autodba.frontend.gradio_app.list_oracle_targets_safe",
            side_effect=RuntimeError("bad registry file"),
        ), patch(
            "odb_autodba.frontend.gradio_app.get_default_oracle_target",
            return_value=_DefaultTarget(),
        ):
            selector = gradio_app._target_selector_context()

        self.assertTrue(selector.get("choices"))
        self.assertIn("Target registry unavailable", str(selector.get("warning") or ""))

    def test_target_info_line_uses_selected_display(self) -> None:
        labels = {"prod__db01__1521__pdb1": "PROD DB01 PDB1 — prod__db01__1521__pdb1"}
        text = gradio_app._target_info_markdown("prod__db01__1521__pdb1", labels)
        self.assertIn("Selected target:", text)
        self.assertIn("PROD DB01 PDB1", text)

    def test_selected_db_key_passed_to_health_handler(self) -> None:
        with patch(
            "odb_autodba.frontend.gradio_app._submit_message_with_target",
            return_value=([], [], {}, "md", False, object(), "", "history"),
        ) as submit_mock:
            gradio_app._submit_message_ui(
                "Check health of my Oracle database",
                [],
                {},
                "prod__db01__1521__pdb1",
                {"prod__db01__1521__pdb1": "PROD DB01 PDB1 — prod__db01__1521__pdb1"},
            )

        args, _ = submit_mock.call_args
        self.assertEqual(args[3], "prod__db01__1521__pdb1")

    def test_selected_db_key_passed_to_sessions_handler(self) -> None:
        with patch(
            "odb_autodba.frontend.gradio_app._submit_message_with_target",
            return_value=([], [], {}, "md", False, object(), "", "history"),
        ) as submit_mock:
            gradio_app._submit_message_ui(
                "show active sessions",
                [],
                {},
                "prod__db01__1521__pdb1",
                {"prod__db01__1521__pdb1": "PROD DB01 PDB1 — prod__db01__1521__pdb1"},
            )

        args, _ = submit_mock.call_args
        self.assertEqual(args[3], "prod__db01__1521__pdb1")

    def test_selected_db_key_passed_to_history_handler(self) -> None:
        with patch(
            "odb_autodba.frontend.gradio_app._submit_message_with_target",
            return_value=([], [], {}, "md", False, object(), "", "history"),
        ) as submit_mock:
            gradio_app._submit_message_ui(
                "Show historical trends",
                [],
                {},
                "prod__db01__1521__pdb1",
                {"prod__db01__1521__pdb1": "PROD DB01 PDB1 — prod__db01__1521__pdb1"},
            )

        args, _ = submit_mock.call_args
        self.assertEqual(args[3], "prod__db01__1521__pdb1")

    def test_selected_db_key_passed_to_investigation_handler(self) -> None:
        with patch(
            "odb_autodba.frontend.gradio_app._submit_investigation",
            return_value=([], []),
        ) as inv_mock:
            gradio_app._submit_investigation_ui(
                "Investigate CPU",
                [],
                "prod__db01__1521__pdb1",
                {"prod__db01__1521__pdb1": "PROD DB01 PDB1 — prod__db01__1521__pdb1"},
            )

        _, kwargs = inv_mock.call_args
        self.assertEqual(kwargs.get("selected_db_key"), "prod__db01__1521__pdb1")

    def test_test_and_use_target_adds_choice_and_selects_it(self) -> None:
        with patch("odb_autodba.frontend.gradio_app._test_connection_for_target", return_value=("FREE", "READ WRITE")):
            update, labels, choices, info, status = gradio_app._test_and_use_target_ui(
                [("Local Oracle Free — default__localhost__1521__freepdb1", "default__localhost__1521__freepdb1")],
                {"default__localhost__1521__freepdb1": "Local Oracle Free — default__localhost__1521__freepdb1"},
                "dev",
                "db-dev01.example.com",
                "1521",
                "PDB1",
                "",
                "",
                "monitor",
                "runtime-secret",
                "",
                "normal",
                "Dev DB 01",
            )
        selected = update.get("value")
        self.assertEqual(selected, "dev__db-dev01-example-com__1521__pdb1")
        self.assertIn(selected, labels)
        self.assertTrue(any(item[1] == selected for item in choices))
        self.assertIn("Selected target:", info)
        self.assertIn("Connection test succeeded", status)

    def test_test_and_use_target_invalid_connection_shows_friendly_error(self) -> None:
        with patch("odb_autodba.frontend.gradio_app._test_connection_for_target", side_effect=RuntimeError("password=abc123")):
            _, _, _, _, status = gradio_app._test_and_use_target_ui(
                [("Local Oracle Free — default__localhost__1521__freepdb1", "default__localhost__1521__freepdb1")],
                {"default__localhost__1521__freepdb1": "Local Oracle Free — default__localhost__1521__freepdb1"},
                "dev",
                "db-dev01.example.com",
                "1521",
                "PDB1",
                "",
                "",
                "monitor",
                "runtime-secret",
                "",
                "normal",
                "Dev DB 01",
            )
        self.assertIn("Target test failed", status)
        self.assertNotIn("abc123", status)


if __name__ == "__main__":
    unittest.main()
