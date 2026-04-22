# odb_autodba

Oracle AutoDBA is a local Gradio copilot for Oracle health checks, focused SQL_ID analysis, read-only investigation, historical run comparison, and guarded remediation.

This implementation is evidence-first and mostly deterministic. It does not require an LLM for health collection, report rendering, history comparison, or remediation proposal/review logic.

## What It Does

- Collects live Oracle health evidence from dynamic performance and DBA views.
- Produces concise operator-facing reports with actionable findings.
- Supports SQL_ID deep-dive analysis (current + historical where available).
- Persists health run traces and JSONL summaries.
- Rebuilds derived history indexes for trend and recurring-pattern retrieval.
- Proposes guarded remediation actions for blocking locks.
- Requires explicit confirmation before executing allowlisted remediation SQL.

## Runtime Flow

1. `python -m odb_autodba` starts `frontend/gradio_app.py`.
2. UI messages are routed to `PlannerAgent.handle_message()`.
3. Planner chooses one deterministic path:
   - health snapshot (`db/health_checks.py`)
   - history analysis (`history/jsonl_service.py`, with source/index audit)
   - SQL_ID deep dive (`db/query_deep_dive.py`)
4. For health snapshots:
   - build report markdown
   - build remediation proposal/review payload
   - persist trace via `append_health_run_trace(...)`
   - automatically rebuild history indexes
5. UI renders report + remediation card; execution stays guarded.

History request path detail:

1. `PlannerAgent.handle_message(...)` detects history intent.
2. `HistoryService.answer_history_question(...)` calls `JsonlHistoryService.answer_history_question_from_jsonl(...)`.
3. History service computes trends/transitions from traces and runs `audit_history_pipeline(...)`.
4. Response includes source/freshness/rebuild metadata and a compact history-source note in formatted output.

## History Indexing Status

Yes, history indexing is happening in the current code path, and history answers now report exactly which data sources were used.

Health run indexing trigger:

- `agents/planner_agent.py` calls `append_health_run_trace(...)` after each successful health snapshot.
- `rag/trace_store.py` then calls `rebuild_planner_memory_artifacts(...)` by default (`rebuild_artifacts=True`).

History request runtime audit:

- `history/jsonl_service.py` now runs `audit_history_pipeline(...)` during history answers.
- It checks index presence/freshness, optionally rebuilds indexes, chooses recurrence mode (`indexed` or `raw_scan`), and returns explicit source metadata.

Index files tracked by history audit:

- `runs/indexes/trace_chunks.jsonl`
- `runs/indexes/recurring_issues.jsonl`
- `runs/indexes/database_behavior_profiles.jsonl`
- `runs/indexes/history_indexing.jsonl`

Raw run source used for trend metrics and transition analysis:

- `runs/traces/health_run_*.json` (preferred via `read_health_run_traces(...)`)
- `runs/traces/health_runs.jsonl` (fallback expansion path)

When indexing does not run:

- Investigation-only runs (`InvestigationAgent`) write investigation traces but do not rebuild history indexes.
- History-only questions do not create new health-run traces; they audit current index state and may rebuild if stale/missing.
- If `append_health_run_trace(..., rebuild_artifacts=False)` is used, post-run rebuild is skipped.

Current recurrence behavior:

- Preferred mode: `indexed` recurrence from `recurring_issues.jsonl` when usable and fresh.
- Fallback mode: `raw_scan` from loaded health run traces when indexes are missing/stale/unusable.
- Fallback is explicit in response notes (not silent).

History response transparency fields (structured):

- `history_source_used`
- `recurrence_computation_mode`
- `index_usage_summary`
- `runs_scanned`
- `index_records_scanned`
- `history_index_status`
- `history_index_freshness`
- `history_index_rebuilt`
- `history_index_notes`

AWR snapshot mapping/debug fields (structured):

- `AwrSnapshotWindowMapping.matched_snap_id`
- `AwrSnapshotWindowMapping.matched_begin_time`
- `AwrSnapshotWindowMapping.matched_end_time`
- `AwrSnapshotWindowMapping.instance_count`
- `AwrSnapshotWindowMapping.instance_rows_found`
- `AwrRunPairWindowMapping.debug` (previous/current run timestamps, mapped snaps, same-snap flag, per-snap instance row counts)

Historical transition reasoning fields (structured):

- `transition_outcome` (`recovered`, `improved`, `worsened`, `unchanged`, `persisted_but_worsened`, `persisted_but_improved`)
- `recovery_detected`
- `residual_risk_present`
- `recovery_drivers[]`
- `residual_warning_drivers[]`
- `history_source_summary`
- `awr_source_summary`
- `fallback_summary`
- `awr_fallback_info.awr_user_message` (user-safe)
- `awr_fallback_info.awr_debug_message` (internal/debug)

Historical formatter behavior (standard output):

- Clearly separates **Recovery Drivers** from **Residual Warning Drivers**.
- Uses transition-outcome-aware wording (for example, recovered/improved wording when severity drops).
- Keeps raw implementation exceptions out of the user-facing report.
- Shows concise source transparency:
  - `History source: ...`
  - `AWR source: ...`
  - fallback summary line when applicable
- Distinguishes AWR reason states clearly:
  - `AWR disabled`
  - `AWR unavailable`
  - `AWR query failure`
  - `AWR mapping weak / same-window weak`
  - `AWR mapped with partial metrics`

Current historical report section order:

1. Historical Trend Analysis
2. History Source
3. State Transition Summary
4. Recovery Drivers
5. Residual Warning Drivers
6. Change Since Last Report
7. AWR Workload Changes
8. Wait Class Shift
9. SQL Change Summary
10. Event Timeline
11. Learning Features
12. Confidence + Coverage Notes
13. Recurring Patterns
14. Historical Metric Points
15. Metric Trends

## Environment

The app loads `.env` with `python-dotenv`.

Preferred database env keys (with compatibility aliases):

| Purpose | Preferred | Compatible |
| --- | --- | --- |
| Host | `ORACLE_HOST` | `DB_HOST` |
| Port | `ORACLE_PORT` | `DB_PORT` |
| Service/PDB | `ORACLE_SERVICE_NAME` or `ORACLE_SERVICE` | `DB_SERVICE` |
| User | `ORACLE_USER` | `DB_USER` |
| Password | `ORACLE_PASSWORD` or `ORACLE_PASS` | `DB_PASSWORD` |
| DSN | `ORACLE_DSN` | `DB_DSN` |

`ORACLE_*` values take precedence when both styles are present.

Common optional env keys:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ORACLE_SYSDBA` | `false` | Enables SYSDBA auth mode when truthy |
| `ENABLE_HOST_CHECKS` | `true` | Includes host/container signals in health report |
| `ODB_AUTODBA_HEALTH_WINDOW_HOURS` | `24` | Time window for alert/AWR/ASH/plan checks |
| `ODB_AUTODBA_TRACE_DIR` | `odb_autodba/runs/traces` | Health/investigation trace directory |
| `ODB_AUTODBA_HISTORY_INDEX_DIR` | `odb_autodba/runs/indexes` | Derived index directory |
| `ODB_AUTODBA_HISTORY_INDEX_FILE` | `odb_autodba/runs/indexes/history_indexing.jsonl` | Combined history index file |
| `OPENAI_API_KEY` | unset | Optional helper path (`agents/openai_assistant.py`) |
| `OPENAI_MODEL` | `gpt-4o-mini` | Optional helper model |

## Code Structure (Every File and Why It Exists)

### Root package files

- `odb_autodba/__init__.py`: package marker and version.
- `odb_autodba/__main__.py`: module entrypoint; launches Gradio app.
- `odb_autodba/pyproject.toml`: package metadata and dependencies.
- `odb_autodba/agent.md`: maintainer/agent guardrails and workflow notes.
- `odb_autodba/README.md`: operator/developer reference (this file).

### `frontend/`

- `frontend/__init__.py`: package marker.
- `frontend/gradio_app.py`: complete UI wiring, workflow shortcuts, planner/investigation submission, remediation execution, and action-history rendering.

### `agents/`

- `agents/__init__.py`: package marker.
- `agents/planner_agent.py`: central deterministic router for health/history/SQL_ID paths.
- `agents/investigation_agent.py`: read-only SQL investigation planning + execution path.
- `agents/planner_tool_executor.py`: utility executor for planner tool names.
- `agents/planner_tools.py`: tool schema metadata definitions.
- `agents/root_cause_engine.py`: ranked likely-cause summarization helpers, including recovery vs residual historical drivers.
- `agents/symptom_evolution.py`: trend/cause evolution helper for historical context with explicit transition-outcome/recovery/residual phrasing.
- `agents/openai_assistant.py`: optional OpenAI helper, not required in default deterministic planner path.
- `agents/prompts.py`: prompt constants for optional assistant/investigation contexts.

### `db/`

- `db/__init__.py`: package marker.
- `db/connection.py`: connection settings loading and safe query helpers.
- `db/health_checks.py`: primary health snapshot collector and issue derivation.
- `db/extended_health_checks.py`: extended DBA checks (redo/recovery/jobs/cache/etc.).
- `db/running_sessions.py`: active-session and blocking-chain collection/correlation.
- `db/query_deep_dive.py`: SQL_ID deep-dive evidence builder.
- `db/plan_checks.py`: plan history and formatted plan evidence helpers.
- `db/ash_checks.py`: ASH capability checks and ASH state extraction.
- `db/awr_checks.py`: AWR capability checks, logical snapshot mapping (duplicate per-instance SNAP rows collapsed to one logical SNAP interval), run-to-run AWR diff logic, and snapshot-selection debug metadata.
- `db/logs.py`: recent alert-log extraction helpers.
- `db/log_checks.py`: ORA/TNS pattern summarization.
- `db/module_health.py`: module-level summary generation.
- `db/sql_monitor.py`: current top SQL summaries.
- `db/sql_text.py`: SQL text fetch by SQL_ID.
- `db/investigation_sql.py`: investigation SQL guardrail validation (`SELECT`/`WITH` only) and execution.
- `db/remediation_sql.py`: SQL builders for allowlisted remediation actions.

### `models/`

- `models/__init__.py`: package marker.
- `models/schemas.py`: all shared Pydantic contracts.

Important schema groups in `models/schemas.py`:

- Health snapshot models: `HealthSnapshot`, `HealthIssue`, `HealthCheckSection`, session/top-sql/tablespace/host models.
- History models: `HistoricalRun`, `HistoryContext`, `HistoricalStateTransition`, `HistoricalRecoveryDriver`, `HistoricalResidualDriver`, `HistoricalTransitionOutcome`, `AwrFallbackInfo`, plus metric delta/confidence/timeline models.
- AWR mapping models: `AwrSnapshotWindowMapping` (including `matched_snap_id` + instance row counters) and `AwrRunPairWindowMapping.debug`.
- Trace/index models: `TraceHealthRunRecord`, `TraceEvidenceChunk`, `RecurringIssueIndexRecord`, `OraclePlannerMemoryRecord`, `OracleDatabaseBehaviorProfile`.
- Planner/investigation models: `PlannerResponse`, `InvestigationReport`, `InvestigationStep`.
- Remediation models: `RemediationProposal`, `RemediationReview`, `RemediationExecution`, `RemediationRecord`, plus blocking-specific proposal/review payloads.

### `history/`

- `history/__init__.py`: package marker.
- `history/service.py`: thin facade over JSONL history operations, including `audit_history_pipeline(...)` passthrough for debugging.
- `history/jsonl_service.py`: core history comparison, trend series, transition-outcome reasoning (`recovery_drivers` vs `residual_warning_drivers`), and source/index audit logic (index freshness, rebuild, recurrence mode, fallback notes).

### `rag/`

- `rag/__init__.py`: package marker.
- `rag/trace_store.py`: runtime paths, full-trace writes, compact JSONL writes, and index-file I/O (`history_data_source_paths()` is used by history audit).
- `rag/indexer.py`: derived-index rebuild logic (trace chunks, recurring issues, behavior profiles, combined history index entries).
- `rag/retriever.py`: domain-aware retrieval helpers from index files and historical traces (not the primary path for metric trend computation).
- `rag/investigation_trace_store.py`: investigation trace event appends/reads.

### `guardrails/`

- `guardrails/__init__.py`: package marker.
- `guardrails/rules.py`: allowlists, protected users/tokens, and threshold constants.
- `guardrails/models.py`: policy result models.
- `guardrails/policy_engine.py`: enforcement engine for action-type checks, SQL checks, and target safety checks.

### `tools/`

- `tools/__init__.py`: package marker.
- `tools/action_proposals.py`: deterministic remediation proposal generation.
- `tools/action_reviewer.py`: deterministic/Gemini-capable review synthesis from guardrail preview.
- `tools/action_executor.py`: execution SQL resolution and DB execution.
- `tools/action_history.py`: append/load remediation action records from JSONL.

### `host/`

- `host/__init__.py`: package marker.
- `host/health_checks.py`: host CPU/memory/swap/process/filesystem/docker checks and hotspot sections.

### `utils/`

- `utils/__init__.py`: package marker.
- `utils/env_loader.py`: consistent `.env` loading entrypoint.
- `utils/oracle_env.py`: env convenience helpers.
- `utils/sql_analysis.py`: request intent parsing (`history`, `sql_id`, etc.).
- `utils/severity.py`: severity ranking/badge helpers.
- `utils/report_normalizer.py`: report-line normalization utilities.
- `utils/formatter.py`: all markdown/text rendering (health/history/deep-dive/investigation/remediation/action history).

### `verification/`

- `verification/test_smoke.py`: basic package smoke checks.
- `verification/test_connection_settings.py`: env alias and connection-setting behavior.
- `verification/test_health_hotspots.py`: host hotspot/health formatting behavior.
- `verification/test_sql_id_deep_dive.py`: SQL_ID deep-dive report behavior.
- `verification/test_remediation_actions.py`: proposal/review/guardrail/formatter behavior for remediation.
- `verification/test_history_state_diff.py`: historical transition/trend logic plus source transparency tests (indexed recurrence, raw fallback, stale-index handling, recovery-vs-residual ordering, and AWR fallback message sanitization).
- `verification/test_awr_history_mapping.py`: AWR historical mapping tests (duplicate SNAP rows, enclosing timestamp mapping, run-pair debug metadata, partial metric handling, and successful 211→212-style comparison).

## History Source Semantics

Historical trend output uses a mixed strategy by design:

- Run metrics/trend lines and transition logic are derived from loaded historical run traces.
- Recurring findings prefer `recurring_issues.jsonl` when indexes are usable and fresh.
- If recurrence indexes are missing/stale/unusable, recurrence falls back to raw trace scan.

The output explicitly reports source mode, for example:

- `History source: indexed recurrence + raw run metrics.`
- `Recurring issue analysis used raw health_runs.jsonl because recurring_issues.jsonl was missing.`

Planner structured output (`supporting_data.history_data_sources`) now includes the same metadata for API/debug inspection.

AWR mapping semantics:

- Snapshot mapping uses logical per-`SNAP_ID` aggregation over `DBA_HIST_SNAPSHOT` so duplicate rows from multiple instances do not break mapping.
- Each run maps to a `matched_snap_id` (enclosing/nearest interval), with per-snap `instance_count` and `instance_rows_found`.
- Run-pair mapping records internal debug metadata including selected SNAPs and same-snap detection.
- When snapshots map but metrics are incomplete, partial AWR sections are still produced instead of full fallback.

## Runtime Artifacts and File Structures

All runtime files are local under `odb_autodba/runs/`.

### `runs/traces/`

- `health_run_<timestamp>_<db>.json`
  - Full trace record (`TraceHealthRunRecord`), including full `snapshot`, report markdown, and summary metadata.
- `health_runs.jsonl`
  - Compact run summaries, one JSON object per line.
- `investigation_<id>.jsonl`
  - Investigation event stream (`investigation.start`, `investigation.step`, `investigation.done`).

### `runs/indexes/`

- `trace_chunks.jsonl`
  - Flattened evidence chunks for retrieval.
- `recurring_issues.jsonl`
  - Cross-run recurring issue index.
- `database_behavior_profiles.jsonl`
  - Baseline/profile summary per database.
- `history_indexing.jsonl`
  - Combined history entries with typed payloads (`run_history`, `recurring_issue`).

### `runs/history/`

- `action_history.jsonl`
  - Immutable remediation audit trail (`RemediationRecord` lines).

## JSONL Schemas (What Each Structure Means)

### 1) `health_runs.jsonl` (compact run summary)

Key fields:

- `run_id`: stable run identifier.
- `recorded_at` / `completed_at`: write time vs snapshot completion time.
- `database_name`, `database_host`, `instance_name`: source identity.
- `trace_path`: pointer to full `health_run_*.json` file.
- `overall_status`: `OK | WARNING | CRITICAL | INFO`.
- `summary`: human-readable run summary.
- `metrics`: scalar metrics used for trends and retrieval.
- `issues`: issue list with category/title/severity/evidence/recommendation.

Sample line (shape):

```json
{"trace_version":"1","run_id":"odb_autodba_20260422_022514","recorded_at":"2026-04-22T02:25:14.275807+00:00","completed_at":"2026-04-22T02:25:07.687632+00:00","database_name":"FREE","database_host":"localhost","instance_name":"free","trace_path":"/home/neha/projects/agents/odb_autodba/runs/traces/health_run_20260422T022514275807Z_free.json","overall_status":"CRITICAL","summary":"Oracle health check with 8 issue(s).","metrics":{"active_sessions":2,"blocking_count":1,"hottest_tablespace":"USERS","hottest_tablespace_pct":85.02604166666667,"top_cpu_sql_id":"bau4q2a5uujvd"},"issues":[{"category":"blocking","title":"Blocking locks detected","severity":"CRITICAL","description":"1 blocked session(s) found.","evidence":["Blocker SID 175,15994 user=DEVA1 blocking waiter SID 213 wait=80s"],"recommendation":"Review blocker SQL and user before using the guarded remediation flow."}]}
```

### 2) `trace_chunks.jsonl` (retrieval units)

Key fields:

- `chunk_id`: deterministic fingerprint.
- `trace_path`, `recorded_at`, `database_name`: trace linkage.
- `category`, `title`, `summary`, `facts`: retrieval text payload.
- `severity`: chunk severity.
- `metric_names`, `sql_ids`: retrieval hints.

Sample line:

```json
{"chunk_id":"oracle:f847ddd050b2bfb9","trace_path":"/home/neha/projects/agents/odb_autodba/runs/traces/health_run_20260422T022514275807Z_free.json","recorded_at":"2026-04-22T02:25:07.687632+00:00","database_name":"FREE","run_overall_status":"CRITICAL","category":"sql","title":"ASH top CPU SQL concentration","summary":"SQL_ID bau4q2a5uujvd accounts for 27.27% of ON CPU ASH samples in 24h.","facts":["Run SQL_ID deep dive and inspect execution plan, waits, and row-source behavior."],"severity":"WARNING","metric_names":[],"sql_ids":[]}
```

### 3) `recurring_issues.jsonl` (cross-run fingerprints)

Key fields:

- `fingerprint`: stable key for same issue pattern.
- `first_seen` / `last_seen`: recurrence timeline.
- `run_count` / `unhealthy_run_count`: frequency and impact.
- `sample_evidence`: short supporting lines.
- `trace_paths`: recent source traces.

Sample line:

```json
{"fingerprint":"oracle:99ec55ee2dc716ec","database_name":"FREE","category":"plans","title":"SQL plan churn detected","severity":"WARNING","first_seen":"2026-04-20T06:00:45.056636+00:00","last_seen":"2026-04-22T02:25:07.687632+00:00","run_count":20,"unhealthy_run_count":20,"sample_evidence":["{'sql_id': '0fr8zhn4ymu3v', 'plans': 2}","Review plan baselines, bind sensitivity, stats changes, and execution plans."],"latest_summary":"3 SQL_ID sample row(s) had multiple plans in 24h.","trace_paths":["/home/neha/projects/agents/odb_autodba/runs/traces/health_run_20260422T022514275807Z_free.json"]}
```

### 4) `database_behavior_profiles.jsonl` (per-DB baseline)

Key fields:

- `generated_at`, `database_name`, `source_trace_count`.
- `latest_trace_recorded_at`.
- `database_behavior_profile.metric_baselines` for avg/min/max/sample_count.
- issue/sql/host/storage summary lists.

Sample line:

```json
{"generated_at":"2026-04-22T02:25:14.359114+00:00","database_name":"FREE","source_trace_count":20,"latest_trace_recorded_at":"2026-04-22T02:25:07.687632+00:00","database_behavior_profile":{"database_name":"FREE","sampled_run_count":20,"healthy_run_count":0,"warning_run_count":13,"critical_run_count":7,"metric_baselines":{"blocking_count":{"avg":0.3,"min":0.0,"max":1.0,"sample_count":20}},"recurring_issue_summary":["SQL plan churn detected: 20 run(s)"],"sql_behavior_summary":["SQL_ID bau4q2a5uujvd: top CPU in 12 run(s)"],"host_behavior_summary":["host_cpu_pct: avg=1.433, min=0.0, max=19.01"],"storage_behavior_summary":["hottest_tablespace_pct: avg=53.407, min=5.978, max=85.026"]}}
```

### 5) `history_indexing.jsonl` (combined typed index)

Key fields:

- `entry_type`: currently `run_history` or `recurring_issue`.
- `payload`: typed object content.

Sample line (`run_history`):

```json
{"entry_type":"run_history","payload":{"run_id":"odb_autodba_20260422_022514","completed_at":"2026-04-22T02:25:07.687632+00:00","recorded_at":"2026-04-22T02:25:14.275807+00:00","database_name":"FREE","overall_status":"CRITICAL","summary":"Oracle health check with 8 issue(s).","trace_path":"/home/neha/projects/agents/odb_autodba/runs/traces/health_run_20260422T022514275807Z_free.json","metrics":{"active_sessions":2,"blocking_count":1},"issues":[{"category":"blocking","title":"Blocking locks detected","severity":"CRITICAL"}]}}
```

### 6) `action_history.jsonl` (execution audit)

Key fields:

- `created_at`.
- `proposal` (full proposal at execution time).
- `review` (review decision and checks).
- `execution` (status/message/timestamp/validation summary).

Sample line:

```json
{"created_at":"2026-04-21T18:16:27.066846+00:00","proposal":{"action_type":"clear_blocking_lock","title":"Kill idle-in-transaction blocker SID 64","target":{"sid":64,"serial#":12545,"inst_id":1,"username":"DEVA1"},"sql":"ALTER SYSTEM KILL SESSION '64,12545,@1' IMMEDIATE"},"review":{"status":"approved","confidence":"HIGH"},"execution":{"status":"succeeded","message":"Action executed successfully.","executed_at":"2026-04-21T18:16:27.066746+00:00"}}
```

### 7) `investigation_<id>.jsonl` (investigation event stream)

Key fields:

- `event_type`: start/step/done.
- `payload`: event-specific data.
- `recorded_at`.

Sample lines:

```json
{"event_type":"investigation.start","payload":{"investigation_id":"inv_20260421_041249549031","problem_statement":"blocking analysis"},"recorded_at":"2026-04-21T04:12:49.551000+00:00"}
{"event_type":"investigation.step","payload":{"step_number":1,"goal":"Identify blocking sessions","sql":"select ...","status":"success","row_count":1},"recorded_at":"2026-04-21T04:12:49.920000+00:00"}
{"event_type":"investigation.done","payload":{"investigation_id":"inv_20260421_041249549031","step_count":2},"recorded_at":"2026-04-21T04:12:50.004000+00:00"}
```

## Sample JSONL Files Created in This Workspace

The current workspace already has live-generated JSONL artifacts under:

- `odb_autodba/runs/traces/health_runs.jsonl`
- `odb_autodba/runs/indexes/history_indexing.jsonl`
- `odb_autodba/runs/indexes/trace_chunks.jsonl`
- `odb_autodba/runs/indexes/recurring_issues.jsonl`
- `odb_autodba/runs/indexes/database_behavior_profiles.jsonl`
- `odb_autodba/runs/history/action_history.jsonl`

So this is not just schema support; these files are currently being produced/populated.

## Quick Verification Commands

Run from repo root:

```bash
# 1) Trigger a health run (which also triggers indexing)
.venv/bin/python -c "from odb_autodba.agents.planner_agent import PlannerAgent; r=PlannerAgent().handle_message('Check health of my Oracle database'); print(r.supporting_data.get('trace_path'))"

# 2) Confirm compact run history exists
wc -l odb_autodba/runs/traces/health_runs.jsonl

# 3) Confirm derived indexes exist and are populated
wc -l odb_autodba/runs/indexes/trace_chunks.jsonl
wc -l odb_autodba/runs/indexes/recurring_issues.jsonl
wc -l odb_autodba/runs/indexes/database_behavior_profiles.jsonl
wc -l odb_autodba/runs/indexes/history_indexing.jsonl

# 4) Optional manual rebuild
.venv/bin/python -c "from odb_autodba.rag.indexer import rebuild_planner_memory_artifacts; out=rebuild_planner_memory_artifacts(); print({k: len(v) for k,v in out.items()})"

# 5) Inspect history source/index audit directly
.venv/bin/python -c "from odb_autodba.history.service import HistoryService; print(HistoryService().audit_history_pipeline(user_query='show historical trends', database_name='FREE'))"
```

## Current Limits and Notes

- Default planner path is deterministic; OpenAI helper is optional and separate.
- AWR/ASH collection is opportunistic and may degrade based on privileges/licensing/environment.
- Remediation is intentionally narrow and guarded.
- Runtime artifacts can include large evidence payloads; keep `runs/` out of version control.
- You may see older legacy trace filenames in `runs/traces/`; current primary health trace format is `health_run_<timestamp>_<db>.json` + `health_runs.jsonl`.

## Launch

```bash
python -m odb_autodba
```

Workspace venv:

```bash
.venv/bin/python -m odb_autodba
```
