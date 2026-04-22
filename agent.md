# Agent Notes

This file is for coding agents and maintainers working inside `odb_autodba`.
It summarizes the current architecture, safety boundaries, and verification
habits so changes stay aligned with the package.

## Purpose

`odb_autodba` is a local Oracle DBA copilot. It should favor live Oracle
evidence, conservative recommendations, and explicit operator control over
automatic changes. The app is meant to be useful even without an LLM.

## Runtime Flow

1. `frontend/gradio_app.py` launches the Gradio UI.
2. Normal chat calls `PlannerAgent.handle_message()`.
3. The planner routes to one of three deterministic flows:
   - SQL_ID deep dive through `db/query_deep_dive.py`
   - history comparison through `history/service.py`
   - full health snapshot through `db/health_checks.py`
4. Health snapshots derive issues and module summaries, then write traces.
5. Blocking chains may produce a remediation proposal.
6. Execution goes through review, guardrail evaluation, user confirmation, and
   then `tools/action_executor.py`.
7. The "Investigate with AI" UI button currently calls
   `InvestigationAgent`, which uses deterministic read-only SQL templates and
   validation.

## Important Modules

- `db/connection.py`: one connection source of truth. It loads `.env`, accepts
  `ORACLE_*` and `DB_*` aliases, and uses python-oracledb.
- `models/schemas.py`: shared Pydantic contracts. Update these before adding
  new planner response fields or trace payloads.
- `db/health_checks.py`: main evidence collector. Keep SQL queries read-only.
- `db/investigation_sql.py`: validates investigation SQL. Do not loosen this
  lightly.
- `guardrails/policy_engine.py` and `guardrails/rules.py`: final execution
  blockers.
- `tools/action_proposals.py`: currently only proposes blocker session kill.
- `history/` and `rag/`: JSONL persistence and simple retrieval helpers.

## Environment Rules

Supported database variables:

- `ORACLE_HOST` or `DB_HOST`
- `ORACLE_PORT` or `DB_PORT`
- `ORACLE_SERVICE_NAME`, `ORACLE_SERVICE`, or `DB_SERVICE`
- `ORACLE_USER` or `DB_USER`
- `ORACLE_PASSWORD`, `ORACLE_PASS`, or `DB_PASSWORD`
- `ORACLE_DSN` or `DB_DSN`

`ORACLE_*` wins over `DB_*` when both are present. `DB_CONN_NAME` is not used by
python-oracledb unless the value is also supplied as a driver-compatible
`DB_DSN`.

Do not log or print secret values. When debugging config, print variable names
or booleans such as `password_set=True`.

## Safety Rules

- Investigation SQL must remain read-only and single-statement.
- Remediation must remain allowlisted.
- Execution must require explicit operator confirmation from the UI.
- Keep protected users and background process filters active.
- Prefer adding evidence and validation over broadening automatic actions.
- If adding a new remediation type, update all of these together:
  `tools/action_proposals.py`, `guardrails/rules.py`,
  `guardrails/policy_engine.py`, `tools/action_reviewer.py`, README, and this
  file.

## Known Implementation Notes

- The default planner path does not call OpenAI. `agents/openai_assistant.py`
  is currently a standalone helper/future integration point.
- `ENABLE_HOST_CHECKS` is used. Older flags such as `ENABLE_AWR`,
  `ENABLE_ASH`, and `ENABLE_ACTIONS` may appear in `.env` files but are not
  branch controls in the current health path.
- AWR and ASH queries are attempted opportunistically and degrade by catching
  exceptions where implemented.
- Runtime outputs live under `odb_autodba/runs` and should stay untracked.

## Verification

Use the workspace interpreter:

```bash
.venv/bin/python -m compileall -q odb_autodba
```

If `pytest` is available:

```bash
.venv/bin/python -m pytest odb_autodba/verification
```

In this workspace, `pytest` may not be installed. The stdlib-compatible
connection-settings tests can still be called directly:

```bash
.venv/bin/python -c "from odb_autodba.verification.test_connection_settings import test_connection_settings_accept_db_env_aliases, test_connection_settings_prefers_oracle_env; test_connection_settings_accept_db_env_aliases(); test_connection_settings_prefers_oracle_env(); print('connection setting tests passed')"
```

For a real Oracle connection probe, avoid printing credentials:

```bash
.venv/bin/python -c "from odb_autodba.db.connection import fetch_one; print(fetch_one('select 1 as ok from dual'))"
```
