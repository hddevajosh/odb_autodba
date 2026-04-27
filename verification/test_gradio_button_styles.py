from __future__ import annotations

import inspect
import unittest

from odb_autodba.frontend import gradio_app


class GradioButtonStyleTests(unittest.TestCase):
    def test_shortcut_buttons_use_primary_variant(self) -> None:
        source = inspect.getsource(gradio_app.build_app)
        self.assertIn('btn = gr.Button(label, size="lg", variant="primary", elem_classes=["workflow-button"])', source)

    def test_investigate_button_matches_send_style_family(self) -> None:
        source = inspect.getsource(gradio_app.build_app)
        self.assertIn('send_btn = gr.Button("Send", variant="primary")', source)
        self.assertIn('investigate_btn = gr.Button("Investigate with AI", variant="primary")', source)

    def test_clear_button_remains_secondary(self) -> None:
        source = inspect.getsource(gradio_app.build_app)
        self.assertIn('clear_btn = gr.Button("Clear")', source)

    def test_pg_style_classes_are_used(self) -> None:
        css = gradio_app.APP_CSS
        self.assertIn("#action-rail .rail-title", css)
        self.assertIn("#action-rail .workflow-button", css)
        self.assertIn("position: sticky", css)
        self.assertIn("@media (min-width: 1280px)", css)
        self.assertIn("position: fixed", css)


if __name__ == "__main__":
    unittest.main()
