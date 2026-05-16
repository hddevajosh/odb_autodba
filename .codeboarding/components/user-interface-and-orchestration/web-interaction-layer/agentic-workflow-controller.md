---
component_id: 1.1.2
component_name: Agentic Workflow Controller
---

# Agentic Workflow Controller

## Component Description

Manages the transition from UI events to backend execution. It implements the routing logic that decides whether a request is handled locally or via the Model Context Protocol (MCP) and coordinates the high-level Planner logic that drives the agentic behavior.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 898-987)
```
def _submit_message_with_target(
    message: str,
    chat_state: list[dict],
    response_state: dict,
    selected_db_key: str | None,
    target_label: str,
):
    mode = get_execution_mode()
    if not message.strip():
        return chat_state, chat_state, response_state, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", _action_history_markdown(selected_db_key)
    if mode == "mcp":
        route = _message_route_for_mcp(message)
        target_payload, mcp_limitation = _mcp_target_payload_or_limitation(selected_db_key)
        if mcp_limitation:
            if mcp_fallback_local_enabled():
                LOGGER.info(
                    "execution_mode=mcp action=%s fallback_used=true fallback_target=local reason=target_limitation db_key=%s",
                    route or "investigate",
                    (selected_db_key or "").strip(),
                )
                result = _submit_message_local(
                    message,
                    chat_state,
                    response_state,
                    selected_db_key=selected_db_key,
                    target_label=target_label,
                )
                chatbot = list(result[0] or [])
                if chatbot and isinstance(chatbot[-1], dict):
                    chatbot[-1] = {
                        **chatbot[-1],
                        "content": f"{chatbot[-1].get('content')}\n\n{mcp_limitation}",
                    }
                return (
                    chatbot,
                    chatbot,
                    result[2],
                    result[3],
                    result[4],
                    result[5],
                    result[6],
                    result[7],
                )
            assistant_content = mcp_limitation
            chat_state = chat_state + [
                {"role": "user", "content": message},
                {"role": "assistant", "content": assistant_content},
            ]
            return chat_state, chat_state, response_state, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", _action_history_markdown(selected_db_key)
        try:
            return _submit_message_via_mcp(
                message,
                chat_state,
                response_state,
                route=route or "investigate",
                db_key=selected_db_key,
                target_label=target_label,
                target_payload=target_payload,
            )
        except Exception as exc:
            if mcp_fallback_local_enabled():
                LOGGER.info(
                    "execution_mode=mcp action=%s fallback_used=true fallback_target=local reason=job_failure db_key=%s",
                    route or "investigate",
                    (selected_db_key or "").strip(),
                )
                result = _submit_message_local(message, chat_state, response_state, selected_db_key=selected_db_key, target_label=target_label)
                chatbot = list(result[0] or [])
                if chatbot and isinstance(chatbot[-1], dict):
                    chatbot[-1] = {
                        **chatbot[-1],
                        "content": f"{chatbot[-1].get('content')}\n\nMCP job failed/unavailable; used local direct mode fallback.",
                    }
                return (
                    chatbot,
                    chatbot,
                    result[2],
                    result[3],
                    result[4],
                    result[5],
                    result[6],
                    result[7],
                )
            assistant_content = f"MCP job failed/unavailable: {_safe_error_message(str(exc))}"
            chat_state = chat_state + [
                {"role": "user", "content": message},
                {"role": "assistant", "content": assistant_content},
            ]
            return chat_state, chat_state, response_state, "No remediation proposed for the current analysis.", False, gr.update(interactive=False), "", _action_history_markdown(selected_db_key)
    return _submit_message_local(message, chat_state, response_state, selected_db_key=selected_db_key, target_label=target_label)
```

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 128-129)
```
def _planner() -> PlannerAgent:
    return PlannerAgent()
```

### /home/neha/projects/agents/odb_autodba/frontend/gradio_app.py (lines 675-700)
```
def _message_route_for_mcp(message: str) -> str | None:
    lowered = (message or "").strip().lower()
    # Deterministic priority order:
    # 1) SQL_ID analysis
    # 2) generalized history metric question
    # 3) AWR analysis
    # 4) blocking live analysis
    # 5) active sessions
    # 6) full historical trends
    # 7) health check
    # 8) generic investigation
    if detect_sql_id_analysis_intent(lowered):
        return "sql_id_analysis"
    if detect_history_metric_question(lowered):
        return "history_metric_question"
    if detect_awr_analysis_intent(lowered):
        return "awr_analysis"
    if detect_blocking_analysis_intent(lowered):
        return "blocking_analysis"
    if looks_like_active_sessions_request(lowered):
        return "sessions"
    if looks_like_history_request(lowered):
        return "history"
    if any(token in lowered for token in ("check health", "health check", "database health", "check health of my oracle")):
        return "health"
    return "investigate"
```


## Source Files:

- `frontend/gradio_app.py`

