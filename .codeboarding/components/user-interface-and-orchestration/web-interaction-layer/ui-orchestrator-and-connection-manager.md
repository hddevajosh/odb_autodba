---
component_id: 1.1.1
component_name: UI Orchestrator & Connection Manager
---

# UI Orchestrator & Connection Manager

## Component Description

Acts as the structural backbone of the subsystem, responsible for initializing the Gradio layout and managing the state of database targets. It handles the authentication and connectivity logic required to establish a session with the Oracle Engine.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 995-1121)
```
def build_app() -> gr.Blocks:
    selector = _target_selector_context()
    target_choices = list(selector.get("choices") or [])
    default_target = selector.get("default_key")
    labels_by_key = dict(selector.get("labels_by_key") or {})
    selector_warning = str(selector.get("warning") or "")
    dynamic_defaults = _dynamic_target_defaults()
    with gr.Blocks(css=APP_CSS, title="Oracle AutoDBA", elem_id="app-shell") as app:
        chat_state = gr.State([])
        response_state = gr.State({})
        labels_state = gr.State(labels_by_key)
        choices_state = gr.State(target_choices)
        shortcut_clicks: list[tuple[gr.Button, str]] = []

        gr.Markdown(
            "# Oracle AutoDBA\n"
            "Ask for live Oracle checks or trace-driven historical answers. "
            "The UI keeps workflow shortcuts separated from database target controls and chat operations.",
            elem_classes=["app-title"],
        )

        with gr.Row():
            with gr.Column(scale=0, min_width=190, elem_id="action-rail"):
                gr.Markdown("Workflow Shortcuts", elem_classes=["rail-title"])
                for label, prompt in WORKFLOW_PROMPTS:
                    btn = gr.Button(label, size="lg", variant="primary", elem_classes=["workflow-button"])
                    shortcut_clicks.append((btn, prompt))
            with gr.Column(scale=1, min_width=720, elem_id="center-panel"):
                with gr.Accordion("Oracle Target", open=False):
                    with gr.Group(elem_id="target-panel"):
                        mode_info = gr.Markdown(_execution_mode_label())
                        target_db = gr.Dropdown(
                            label="Target Database",
                            choices=target_choices,
                            value=default_target,
                            allow_custom_value=False,
                            interactive=True,
                        )
                        target_info = gr.Markdown(_target_info_markdown(default_target, labels_by_key))
                        if selector_warning:
                            gr.Markdown(f"Note: {selector_warning}")
                    with gr.Row():
                        input_environment = gr.Textbox(label="Environment", value=dynamic_defaults.get("environment", "default"))
                        input_host = gr.Textbox(label="Host", value=dynamic_defaults.get("host", "localhost"))
                        input_port = gr.Textbox(label="Port", value=dynamic_defaults.get("port", "1521"))
                    with gr.Row():
                        input_service_name = gr.Textbox(label="Service Name", value=dynamic_defaults.get("service_name", ""))
                        input_sid = gr.Textbox(label="SID (optional)", value=dynamic_defaults.get("sid", ""))
                        input_pdb_name = gr.Textbox(label="PDB (optional)", value=dynamic_defaults.get("pdb_name", ""))
                    with gr.Row():
                        input_username = gr.Textbox(label="Username", value=dynamic_defaults.get("username", "system"))
                        input_password = gr.Textbox(label="Password", type="password", value="")
                        input_password_env = gr.Textbox(label="Password Env (optional)", value=dynamic_defaults.get("password_env", ""))
                    with gr.Row():
                        input_connection_mode = gr.Dropdown(
                            label="Connection Mode",
                            choices=[("normal", "normal"), ("sysdba", "sysdba")],
                            value=dynamic_defaults.get("connection_mode", "normal"),
                            allow_custom_value=False,
                            interactive=True,
                        )
                        input_display_name = gr.Textbox(label="Display Name (optional)", value=dynamic_defaults.get("display_name", ""))
                    use_target_btn = gr.Button("Test & Use Target", variant="secondary")
                    dynamic_target_status = gr.Markdown("Enter target details, then click **Test & Use Target**.")
                    with gr.Accordion("Recent Jobs", open=False, elem_id="recent-jobs-panel"):
                        refresh_jobs_btn = gr.Button("Refresh Jobs", variant="secondary")
                        recent_jobs_md = gr.Markdown(_recent_jobs_markdown(default_target, limit=10))
                chatbot = gr.Chatbot(type="messages", label="Planner Chat", height=620, show_copy_button=True)
                message = gr.Textbox(
                    label="Ask Oracle AutoDBA",
                    placeholder="Ask a question about current health, history, blocking, SQL, AWR, or trends...",
                    lines=3,
                )
                with gr.Row():
                    send_btn = gr.Button("Send", variant="primary")
                    investigate_btn = gr.Button("Investigate with AI", variant="primary")
                    clear_btn = gr.Button("Clear")
                gr.Examples(
                    examples=[prompt for _, prompt in WORKFLOW_PROMPTS],
                    inputs=message,
                )
                with gr.Group(elem_id="remediation-card"):
                    remediation_md = gr.Markdown("No remediation proposed for the current analysis.")
                    confirm_checkbox = gr.Checkbox(label="I have reviewed the target session and want to allow this action.", value=False)
                    execute_btn = gr.Button("Execute Action", interactive=False)
                    validation_md = gr.Markdown("")
                with gr.Accordion("Action History", open=False):
                    action_history_md = gr.Markdown(_action_history_markdown(default_target))

        for btn, prompt in shortcut_clicks:
            btn.click(
                fn=lambda cs, rs, dbk, labels, p=prompt: _submit_message_ui(p, cs, rs, dbk, labels),
                inputs=[chat_state, response_state, target_db, labels_state],
                outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md],
            )
        use_target_btn.click(
            _test_and_use_target_ui,
            inputs=[
                choices_state,
                labels_state,
                input_environment,
                input_host,
                input_port,
                input_service_name,
                input_sid,
                input_pdb_name,
                input_username,
                input_password,
                input_password_env,
                input_connection_mode,
                input_display_name,
            ],
            outputs=[target_db, labels_state, choices_state, target_info, dynamic_target_status],
        )
        target_db.change(_target_info_markdown, inputs=[target_db, labels_state], outputs=[target_info])
        send_btn.click(
            _submit_message_ui,
            inputs=[message, chat_state, response_state, target_db, labels_state],
            outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md],
        )
        investigate_btn.click(_submit_investigation_ui, inputs=[message, chat_state, target_db, labels_state], outputs=[chatbot, chat_state])
        clear_btn.click(_clear_chat, inputs=[target_db], outputs=[chatbot, chat_state, response_state, remediation_md, confirm_checkbox, execute_btn, validation_md, action_history_md])
        execute_btn.click(_execute_remediation, inputs=[confirm_checkbox, response_state, target_db], outputs=[validation_md, action_history_md])
        target_db.change(_action_history_markdown, inputs=[target_db], outputs=[action_history_md])
        refresh_jobs_btn.click(_recent_jobs_markdown, inputs=[target_db], outputs=[recent_jobs_md])
        target_db.change(_recent_jobs_markdown, inputs=[target_db], outputs=[recent_jobs_md])
    return app
```

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 260-280)
```
def _test_connection_for_target(target, *, password: str | None) -> tuple[str, str]:
    resolved_password = _resolve_password_for_test(password, target.password_env)
    if not resolved_password:
        raise RuntimeError("Password is required. Provide Password or password_env.")
    service = target.service_name or target.sid or "FREEPDB1"
    settings = ConnectionSettings(
        host=target.host,
        port=int(target.port),
        service_name=service,
        user=target.username,
        password=resolved_password,
        dsn=target.connect_descriptor,
        sysdba=target.sysdba,
    )
    with db_connection(settings) as conn:
        cur = conn.cursor()
        cur.execute("select name, open_mode from v$database")
        row = cur.fetchone()
    name = str(row[0]) if row and len(row) > 0 else "unknown"
    open_mode = str(row[1]) if row and len(row) > 1 else "unknown"
    return name, open_mode
```

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 219-238)
```
def _upsert_target_choice(
    choices: list[tuple[str, str]],
    labels_by_key: dict[str, str],
    *,
    db_key: str,
    label: str,
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    next_choices: list[tuple[str, str]] = []
    replaced = False
    for friendly, key in choices:
        if key == db_key:
            next_choices.append((label, db_key))
            replaced = True
        else:
            next_choices.append((friendly, key))
    if not replaced:
        next_choices.append((label, db_key))
    next_labels = dict(labels_by_key)
    next_labels[db_key] = label
    return next_choices, next_labels
```


## Source Files:

- `agents/planner_tools.py`
- `agents/symptom_evolution.py`
- `db/logs.py`
- `db/module_health.py`
- `db/sql_monitor.py`
- `db/sql_text.py`
- `frontend/gradio_app.py`
- `utils/env_loader.py`
- `utils/report_normalizer.py`

