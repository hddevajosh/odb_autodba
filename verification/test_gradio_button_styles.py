from __future__ import annotations

import inspect
import unittest

from odb_autodba.frontend import gradio_app


class GradioButtonStyleTests(unittest.TestCase):
    def test_shortcut_buttons_use_primary_variant(self) -> None:
        source = inspect.getsource(gradio_app.build_app)
        self.assertIn('btn = gr.Button(label, variant="primary", elem_classes=["workflow-shortcut-btn", "action-primary-btn"])', source)

    def test_investigate_button_matches_send_style_family(self) -> None:
        source = inspect.getsource(gradio_app.build_app)
        self.assertIn('send_btn = gr.Button("Send", variant="primary", elem_classes=["action-primary-btn"])', source)
        self.assertIn('investigate_btn = gr.Button("Investigate with AI", variant="primary", elem_classes=["action-primary-btn"])', source)

    def test_clear_button_remains_secondary(self) -> None:
        source = inspect.getsource(gradio_app.build_app)
        self.assertIn('clear_btn = gr.Button("Clear", variant="secondary", elem_classes=["action-secondary-btn"])', source)

    def test_primary_css_class_is_shared(self) -> None:
        css = gradio_app.APP_CSS
        self.assertIn(".action-primary-btn button", css)
        self.assertIn(".workflow-shortcut-btn button", css)
        self.assertIn(".action-secondary-btn button", css)


if __name__ == "__main__":
    unittest.main()
