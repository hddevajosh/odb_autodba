from __future__ import annotations

import logging
from datetime import datetime, UTC

import gradio as gr

from odb_autodba.agents.investigation_agent import InvestigationAgent
from odb_autodba.agents.planner_agent import PlannerAgent
from odb_autodba.guardrails.models import ExecutionContext
from odb_autodba.guardrails.policy_engine import evaluate_action
from odb_autodba.models.schemas import PlannerResponse, RemediationExecution, RemediationRecord, RemediationReview
from odb_autodba.tools.action_executor import execute_remediation_action
from odb_autodba.tools.action_history import append_action_record, load_action_records, render_action_history_markdown
from odb_autodba.tools.action_reviewer import review_remediation_proposal
from odb_autodba.utils.formatter import render_investigation_final_report, render_planner_response, render_remediation_card_markdown

LOGGER = logging.getLogger(__name__)

WORKFLOW_PROMPTS = (
    ("Check Health", "Check health of my Oracle database"),
    ("Show Active Sessions", "show active sessions"),
    ("Historical Trends", "Show historical trends for this Oracle database"),
)

APP_CSS = """
#app-shell { max-width: 1440px; margin: 0 auto; }
#action-rail {
  position: sticky;
  top: 16px;
  align-self: flex-start;
  padding-right: 14px;
  height: fit-content;
  max-height: calc(100vh - 24px);
}
#shortcut-rail-card {
  border: 0;
  border-radius: 0;
  background: transparent;
  box-shadow: none;
  padding: 2px 0 0 0;
}
#shortcut-rail-card > div {
  border: 0 !important;
  border-radius: 0 !important;
  background: transparent !important;
  box-shadow: none !important;
  padding: 0 !important;
}
#workflow-shortcuts-title {
  margin-bottom: 6px;
}
#workflow-shortcuts-title .title-main {
  font-size: 1.08rem;
  font-weight: 800;
  letter-spacing: 0.02em;
  color: #f6c343;
}
#workflow-shortcuts-title .title-sub {
  font-size: 0.95rem;
  font-weight: 700;
  color: #9ca3af;
}
.workflow-shortcut-btn button {
  width: 100%;
  min-height: 40px;
  border-radius: 10px !important;
  text-align: center;
  justify-content: center;
  padding: 8px 12px !important;
  margin: 0 !important;
}
.workflow-shortcut-btn {
  width: 100%;
}
#remediation-card { border: 1px solid #d6dee8; border-radius: 20px; padding: 18px; background: linear-gradient(180deg, #f9fbfd 0%, #eef4f8 100%); }
#app-shell button {
  background: #f6c343 !important;
  border: 1px solid #d4a52a !important;
  color: #2b2100 !important;
}
#app-shell button:hover {
  background: #ffd157 !important;
}
"""


def _planner() -> PlannerAgent:
    return PlannerAgent()


def _investigator() -> InvestigationAgent:
    return InvestigationAgent()


def _process_user_message_with_response(message: str) -> PlannerResponse:
    return _planner().handle_message(message)


def _submit_message(message: str, chat_state: list[dict], response_state: dict):
    if not message.strip():
        return chat_state, chat_state, response_state, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", render_action_history_markdown(load_action_records())
    response = _process_user_message_with_response(message)
    assistant_content = render_planner_response(response)
    lowered_message = message.lower()
    if "active session" in lowered_message:
        assistant_content += "\n\nIf you want deep SQL analysis, use command: `Analyze SQL_ID <sql_id>` to analyze."
    chat_state = chat_state + [
        {"role": "user", "content": message},
        {"role": "assistant", "content": assistant_content},
    ]
    response_state = {"response": response.model_dump(mode="json")}
    has_proposal = response.remediation_proposal is not None
    review_data = (response.supporting_data or {}).get("review")
    remediation_md = render_remediation_card_markdown(response.remediation_proposal, review_data)
    return chat_state, chat_state, response_state, remediation_md, False, gr.update(interactive=has_proposal), "", render_action_history_markdown(load_action_records())


def _submit_investigation(message: str, chat_state: list[dict]):
    if not message.strip():
        return chat_state, chat_state
    report = _investigator().investigate(message)
    chat_state = chat_state + [
        {"role": "user", "content": f"Investigate: {message}"},
        {"role": "assistant", "content": render_investigation_final_report(report)},
    ]
    return chat_state, chat_state


def _execute_remediation(confirmed: bool, response_state: dict):
    payload = (response_state or {}).get("response") or {}
    proposal_data = payload.get("remediation_proposal")
    if not proposal_data:
        return "No remediation proposal is available.", render_action_history_markdown(load_action_records())
    proposal = PlannerResponse.model_validate(payload).remediation_proposal
    review = review_remediation_proposal(proposal)
    review_text = _format_review_summary(review)
    if review.status != "approved":
        return f"Execution blocked by reviewer.\n{review_text}", render_action_history_markdown(load_action_records())
    decision = evaluate_action(proposal, ExecutionContext(confirmed=confirmed))
    if not decision.allowed:
        reasons = "; ".join(v.message for v in decision.violations)
        return f"{review_text}\nExecution blocked by guardrails: {reasons}", render_action_history_markdown(load_action_records())
    execution = execute_remediation_action(proposal)
    record = RemediationRecord(created_at=datetime.now(UTC).isoformat(), proposal=proposal, review=review, execution=execution)
    append_action_record(record)
    return f"{review_text}\nExecution status: {execution.status}. {execution.message}", render_action_history_markdown(load_action_records())


def _format_review_summary(review: RemediationReview) -> str:
    icon = "🟢" if review.status == "approved" else "🔴" if review.status == "rejected" else "🔵"
    rationale = review.rationale or "No reviewer rationale provided."
    notes_source = review.notes or review.reviewer_notes
    notes = "; ".join(notes_source[:3]) if notes_source else "No reviewer notes."
    passed = ", ".join(review.guardrail_checks_passed[:4]) if review.guardrail_checks_passed else "none"
    failed = ", ".join(review.guardrail_checks_failed[:4]) if review.guardrail_checks_failed else "none"
    return (
        f"Reviewer decision: {icon} {review.status} (confidence={review.confidence}). "
        f"{rationale} Checks passed: {passed}. Checks failed: {failed}. Notes: {notes}"
    )


def _clear_chat():
    return [], [], {}, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", render_action_history_markdown(load_action_records())


def build_app() -> gr.Blocks:
    with gr.Blocks(css=APP_CSS, title="Oracle AutoDBA", elem_id="app-shell") as app:
        chat_state = gr.State([])
        response_state = gr.State({})
        shortcut_clicks: list[tuple[gr.Button, str]] = []
        with gr.Row():
            with gr.Column(scale=1, elem_id="action-rail"):
                gr.Markdown(
                    "<div class='title-main'>Oracle AutoDBA</div><div class='title-sub'>Workflow shortcuts</div>",
                    elem_id="workflow-shortcuts-title",
                )
                with gr.Group(elem_id="shortcut-rail-card"):
                    for label, prompt in WORKFLOW_PROMPTS:
                        btn = gr.Button(label, variant="primary", elem_classes=["workflow-shortcut-btn"])
                        shortcut_clicks.append((btn, prompt))
            with gr.Column(scale=4, elem_id="center-panel"):
                chatbot = gr.Chatbot(type="messages", label="Planner Chat", height=550)
                message = gr.Textbox(lines=4, placeholder="Ask about Oracle health, SQL_ID, ORA errors, blocking, or trends.", label="Message")
                with gr.Row():
                    send_btn = gr.Button("Send", variant="primary")
                    investigate_btn = gr.Button("Investigate with AI")
                    clear_btn = gr.Button("Clear")
                with gr.Group(elem_id="remediation-card"):
                    remediation_md = gr.Markdown("No remediation proposed for the current analysis.")
                    confirm_checkbox = gr.Checkbox(label="I have reviewed the target session and want to allow this action.", value=False)
                    execute_btn = gr.Button("Execute Action", interactive=False)
                    validation_md = gr.Markdown("")
                with gr.Accordion("Action History", open=False):
                    action_history_md = gr.Markdown(render_action_history_markdown(load_action_records()))

        for btn, prompt in shortcut_clicks:
            btn.click(
                fn=lambda cs, rs, p=prompt: _submit_message(p, cs, rs),
                inputs=[chat_state, response_state],
                outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md],
            )
        send_btn.click(_submit_message, inputs=[message, chat_state, response_state], outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md])
        investigate_btn.click(_submit_investigation, inputs=[message, chat_state], outputs=[chatbot, chat_state])
        clear_btn.click(_clear_chat, outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md])
        execute_btn.click(_execute_remediation, inputs=[confirm_checkbox, response_state], outputs=[validation_md, action_history_md])
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    build_app().launch()


if __name__ == "__main__":
    main()
