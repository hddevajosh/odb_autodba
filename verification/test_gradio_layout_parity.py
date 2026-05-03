from __future__ import annotations

from collections.abc import Iterable
import unittest

from odb_autodba.frontend import gradio_app


class GradioLayoutParityTests(unittest.TestCase):
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

    def _component_ids_by_button_label(self, config: dict, label: str) -> list[int]:
        ids: list[int] = []
        for component in config.get("components", []):
            if component.get("type") != "button":
                continue
            props = component.get("props") or {}
            if props.get("value") == label:
                ids.append(int(component["id"]))
        return ids

    def _button_variant(self, config: dict, label: str) -> str:
        for component in config.get("components", []):
            if component.get("type") != "button":
                continue
            props = component.get("props") or {}
            if props.get("value") == label:
                return str(props.get("variant") or "")
        raise AssertionError(f"Button with label={label!r} not found")

    def _button_props(self, config: dict, label: str) -> dict:
        for component in config.get("components", []):
            if component.get("type") != "button":
                continue
            props = component.get("props") or {}
            if props.get("value") == label:
                return props
        raise AssertionError(f"Button with label={label!r} not found")

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

    def _parent_by_node_id(self, config: dict) -> dict[int, int]:
        parents: dict[int, int] = {}

        def walk(node: dict) -> None:
            parent_id = node.get("id")
            for child in node.get("children") or []:
                if isinstance(child, dict):
                    child_id = child.get("id")
                    if isinstance(parent_id, int) and isinstance(child_id, int):
                        parents[child_id] = parent_id
                    walk(child)

        walk(config.get("layout") or {})
        return parents

    def test_panel_elem_ids_exist(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()
        self.assertEqual(getattr(app, "elem_id", None), "app-shell")
        for elem_id in (
            "action-rail",
            "center-panel",
            "target-panel",
            "recent-jobs-panel",
        ):
            self._component_id_by_elem_id(config, elem_id)
        self.assertIn("#app-shell", gradio_app.APP_CSS)

    def test_target_selector_and_dynamic_target_are_in_collapsed_oracle_target(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()
        center_panel_id = self._component_id_by_elem_id(config, "center-panel")
        oracle_target_id = self._component_id_by_label(config, "Oracle Target")
        target_dropdown_id = self._component_id_by_label(config, "Target Database")
        host_id = self._component_id_by_label(config, "Host")
        test_target_id = self._component_id_by_button_label(config, "Test & Use Target")
        descendants = self._descendants_by_node_id(config)
        center_descendants = descendants.get(center_panel_id) or set()
        oracle_target_descendants = descendants.get(oracle_target_id) or set()
        self.assertIn(oracle_target_id, center_descendants)
        self.assertIn(target_dropdown_id, oracle_target_descendants)
        self.assertIn(host_id, oracle_target_descendants)
        self.assertIn(test_target_id, oracle_target_descendants)
        self.assertIn(target_dropdown_id, center_descendants)
        props = next(
            component.get("props") or {}
            for component in config.get("components", [])
            if int(component.get("id") or -1) == oracle_target_id
        )
        self.assertFalse(bool(props.get("open")))

    def test_main_ui_no_visible_mode_or_target_lines_by_default(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()
        oracle_target_id = self._component_id_by_label(config, "Oracle Target")
        descendants = self._descendants_by_node_id(config)
        oracle_descendants = descendants.get(oracle_target_id) or set()
        mode_ids = []
        selected_target_ids = []
        for component in config.get("components", []):
            if component.get("type") != "markdown":
                continue
            props = component.get("props") or {}
            value = str(props.get("value") or "")
            if value.startswith("Execution mode:"):
                mode_ids.append(int(component["id"]))
            if value.startswith("Selected target:"):
                selected_target_ids.append(int(component["id"]))
        self.assertTrue(mode_ids, "Execution mode markdown should still exist inside Oracle Target")
        self.assertTrue(selected_target_ids, "Selected target markdown should still exist inside Oracle Target")
        for component_id in mode_ids + selected_target_ids:
            self.assertIn(component_id, oracle_descendants)

    def test_workflow_shortcuts_only_in_action_rail(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()
        rail_id = self._component_id_by_elem_id(config, "action-rail")
        center_id = self._component_id_by_elem_id(config, "center-panel")
        descendants = self._descendants_by_node_id(config)
        rail_desc = descendants.get(rail_id) or set()
        center_desc = descendants.get(center_id) or set()
        for label in ("Check Health", "Show Active Sessions", "Historical Trends"):
            button_ids = self._component_ids_by_button_label(config, label)
            self.assertTrue(button_ids, f"button {label!r} not found")
            for button_id in button_ids:
                self.assertIn(button_id, rail_desc)
                self.assertNotIn(button_id, center_desc)
            self.assertEqual(self._button_props(config, label).get("elem_classes"), ["workflow-button"])

    def test_recent_jobs_panel_exists_and_contains_refresh_button(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()
        oracle_target_id = self._component_id_by_label(config, "Oracle Target")
        recent_jobs_id = self._component_id_by_elem_id(config, "recent-jobs-panel")
        refresh_id = self._component_id_by_button_label(config, "Refresh Jobs")
        descendants = self._descendants_by_node_id(config)
        oracle_desc = descendants.get(oracle_target_id) or set()
        panel_desc = descendants.get(recent_jobs_id) or set()
        self.assertIn(recent_jobs_id, oracle_desc)
        self.assertIn(refresh_id, panel_desc)

    def test_primary_and_clear_button_variants_match_pg_pattern(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()
        self.assertEqual(self._button_variant(config, "Send"), "primary")
        self.assertEqual(self._button_variant(config, "Investigate with AI"), "primary")
        self.assertNotEqual(self._button_variant(config, "Clear"), "primary")
        self.assertEqual(self._button_props(config, "Send").get("elem_classes"), [])
        self.assertEqual(self._button_props(config, "Investigate with AI").get("elem_classes"), [])
        self.assertEqual(self._button_props(config, "Clear").get("elem_classes"), [])

    def test_bottom_buttons_share_one_plain_row_after_textbox(self) -> None:
        app = gradio_app.build_app()
        config = app.get_config_file()
        parent_by_id = self._parent_by_node_id(config)
        send_id = self._component_id_by_button_label(config, "Send")
        investigate_id = self._component_id_by_button_label(config, "Investigate with AI")
        clear_id = self._component_id_by_button_label(config, "Clear")
        textbox_id = self._component_id_by_label(config, "Ask Oracle AutoDBA")
        self.assertEqual(parent_by_id[send_id], parent_by_id[investigate_id])
        self.assertEqual(parent_by_id[send_id], parent_by_id[clear_id])
        self.assertNotEqual(parent_by_id[send_id], parent_by_id[textbox_id])

    def _component_id_by_button_label(self, config: dict, label: str) -> int:
        ids = self._component_ids_by_button_label(config, label)
        if not ids:
            raise AssertionError(f"Button with label={label!r} not found")
        return ids[0]

    def test_css_contains_pg_style_rail_offsets_and_center_margin(self) -> None:
        css = gradio_app.APP_CSS
        self.assertIn("#app-shell", css)
        self.assertIn("max-width: 1440px;", css)
        self.assertIn("top: 88px;", css)
        self.assertIn("width: 210px;", css)
        self.assertIn("margin-left: 252px;", css)
        self.assertNotIn("min-height: 72px", css)
        self.assertNotIn("position: fixed;\n  bottom:", css)


if __name__ == "__main__":
    unittest.main()
