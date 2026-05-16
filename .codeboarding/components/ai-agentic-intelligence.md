---
component_id: 3
component_name: AI Agentic Intelligence
---

# AI Agentic Intelligence

## Component Description

The reasoning engine of the platform, consisting of specialized agents that analyze database traces, plan investigation steps, and identify root causes using LLM-driven workflows.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/agents/planner_agent.py (lines 28-466)
```
class PlannerAgent:
    def __init__(self, db_key: str | None = None) -> None:
        self.history = HistoryService()
        self.db_key = db_key

    def handle_message(
        self,
        user_text: str,
        chat_history: list[dict] | None = None,
        runtime_context: dict | None = None,
        db_key: str | None = None,
    ) -> PlannerResponse:
        resolved_target = get_oracle_target(db_key or self.db_key)
        resolved_db_key = resolved_target.db_key
        self.db_key = resolved_db_key
        chat_history = chat_history or []
        runtime_context = runtime_context or {}
        with db_key_context(resolved_db_key):
            sql_id = extract_queryid_from_text(user_text or "") if wants_sql_id_analysis(user_text or "") else None
            if sql_id:
                try:
                    deep_dive = build_sql_id_deep_dive_report(sql_id)
                    body = render_sql_id_deep_dive_report(deep_dive)
                    return PlannerResponse(mode="focused_domain_report", summary=f"SQL_ID {sql_id} deep dive completed.", body_markdown=body, recommendations=["Review plan hash diversity and child cursor behavior.", "Correlate with current blocking, waits, and AWR deltas."])
                except Exception as exc:
                    return PlannerResponse(mode="focused_domain_report", summary=f"SQL_ID {sql_id} deep dive could not be completed.", body_markdown=f"# SQL_ID Deep Dive\n\nUnable to collect SQL_ID evidence: {exc}", recommendations=["Verify Oracle connectivity and privileges for v$sqlstats, v$sql, and v$sql_plan."])
            if looks_like_active_sessions_request(user_text or ""):
                try:
                    active_rows = [row.model_dump(mode="json") for row in get_running_sessions_inventory()]
                    blocking_rows = [row.model_dump(mode="json") for row in get_blocking_chains()]
                    resource_rows = get_top_session_resource_candidates(limit=10)
                    body = self._render_active_sessions_response(
                        active_rows=active_rows,
                        blocking_rows=blocking_rows,
                        resource_rows=resource_rows,
                    )
                    return PlannerResponse(
                        mode="focused_domain_report",
                        summary=f"Active session snapshot collected ({len(active_rows)} active session(s)).",
                        body_markdown=body,
                        recommendations=[
                            "Use `Analyze SQL_ID <sql_id>` on top active SQL to deep dive plan and wait behavior.",
                            "Investigate blockers first if blocking chains are present.",
                        ],
                        supporting_data={
                            "active_sessions": {
                                "active_count": len(active_rows),
                                "blocking_count": len(blocking_rows),
                                "resource_candidates_count": len(resource_rows),
                            }
                        },
                    )
                except Exception as exc:
                    LOGGER.exception("Active-session snapshot collection failed.")
                    return PlannerResponse(
                        mode="focused_domain_report",
                        summary="Active session check could not be completed.",
                        body_markdown=(
                            "# Active Sessions\n\n"
                            "Unable to collect active-session evidence.\n\n"
                            f"Error: {self._sanitize_message(str(exc))}"
                        ),
                        recommendations=[
                            "Verify Oracle connectivity and privileges for gv$session and gv$process.",
                        ],
                        supporting_data={
                            "failure_stage": "collect_active_sessions",
                            "error_type": type(exc).__name__,
                            "error_message": self._sanitize_message(str(exc)),
                        },
                    )
            if looks_like_history_request(user_text or ""):
                index_status = get_index_status(resolved_db_key)
                use_index = bool(index_status.get("available")) and bool(index_status.get("fresh"))
                answer = self.history.answer_history_question(user_text or "", db_key=resolved_db_key)
                if use_index:
                    answer["history_source_used"] = str(answer.get("history_source_used") or "indexed recurrence + metrics")
                    answer["index_usage_summary"] = str(answer.get("index_usage_summary") or "recurring + chunks")
                    answer["history_index_status"] = str(answer.get("history_index_status") or "active")
                    answer["history_index_freshness"] = str(answer.get("history_index_freshness") or "fresh")
                else:
                    answer["history_source_used"] = str(answer.get("history_source_used") or "raw JSONL fallback")
                    answer["index_usage_summary"] = str(answer.get("index_usage_summary") or "none")
                    answer["history_index_status"] = str(answer.get("history_index_status") or "missing_or_stale")
                body = render_history_answer(answer)
                transition = answer.get("state_transition")
                transition_summary = "Historical Oracle run comparison completed."
                if transition and getattr(transition, "available", False):
                    confidence_reason = ""
                    confidence_block = getattr(transition, "historical_confidence", None)
                    if confidence_block and getattr(confidence_block, "confidence_reason", None):
                        confidence_reason = f" {confidence_block.confidence_reason}"
                    transition_summary = (
                        f"Historical transition {transition.status_transition} analyzed "
                        f"with {transition.confidence} confidence.{confidence_reason}"
                    )
                return PlannerResponse(
                    mode="history_report",
                    summary=transition_summary,
                    body_markdown=body,
                    recommendations=["Compare with current health check if you need live evidence."],
                    supporting_data={
                        "state_transition": transition.model_dump(mode="json") if transition else None,
                        "learning_features": answer.get("learning_features").model_dump(mode="json")
                        if answer.get("learning_features")
                        else None,
                        "history_data_sources": {
                            "path_mode": "per-db runtime",
                            "history_source_used": answer.get("history_source_used"),
                            "history_source_summary": answer.get("history_source_summary"),
                            "awr_source_summary": answer.get("awr_source_summary"),
                            "fallback_summary": answer.get("fallback_summary"),
                            "recurrence_computation_mode": answer.get("recurrence_computation_mode"),
                            "index_usage_summary": answer.get("index_usage_summary"),
                            "runs_scanned": answer.get("runs_scanned"),
                            "index_records_scanned": answer.get("index_records_scanned"),
                            "history_index_status": answer.get("history_index_status"),
                            "history_index_freshness": answer.get("history_index_freshness"),
                            "history_index_rebuilt": answer.get("history_index_rebuilt"),
                            "history_index_notes": answer.get("history_index_notes"),
                        },
                    },
                )
            try:
                snapshot = collect_health_snapshot(db_key=resolved_db_key)
            except Exception as exc:
                LOGGER.exception("Oracle health snapshot collection failed.")
                diagnostics = self._build_health_failure_supporting_data(exc, failure_stage="collect_health_snapshot")
                body = (
                    "# Oracle AutoDBA Report\n\n"
                    "Unable to collect live Oracle health evidence.\n\n"
                    "## Error\n"
                    + diagnostics["error_message"]
                    + "\n\n## Next checks\n"
                    "- Verify ORACLE_* or DB_* environment variables.\n"
                    "- Verify database connectivity and privileges to gv$ / dba_ views."
                )
                return PlannerResponse(
                    mode="full_health_report",
                    summary="Oracle health check could not be completed.",
                    body_markdown=body,
                    recommendations=[
                        "Set ORACLE_HOST/ORACLE_SERVICE_NAME/ORACLE_USER/ORACLE_PASSWORD or DB_HOST/DB_SERVICE/DB_USER/DB_PASSWORD.",
                        "Confirm the connected user can query the required v$ and dba_ views.",
                    ],
                    supporting_data=diagnostics,
                )
            database_name = snapshot.instance_info.db_name or snapshot.instance_info.instance_name or None
            history_context = self.history.compare_recent_runs(limit=10, database_name=database_name, db_key=resolved_db_key)
            proposal = build_remediation_proposal(snapshot)
            review = review_remediation_proposal(proposal)
            body = render_health_snapshot_report(snapshot)
            trace_record = append_health_run_trace(
                snapshot=snapshot,
                report_markdown=body,
                history_context=history_context,
                db_key=resolved_db_key,
            )
            trace_metadata = self._resolve_trace_metadata(
                trace_record=trace_record,
                database_name=database_name,
                runtime_context=runtime_context,
                history_context=history_context,
                db_key=resolved_db_key,
            )
            recommendations = [issue.recommendation for issue in snapshot.issues[:4]] or ["No urgent Oracle issues were detected in the current snapshot."]
            return PlannerResponse(
                mode="full_health_report",
                summary="Oracle health check completed.",
                body_markdown=body,
                issues=snapshot.issues,
                recommendations=recommendations,
                remediation_proposal=proposal,
                supporting_data={
                    "review": review.model_dump(),
                    "host_check": dict(snapshot.raw_evidence.get("host_check") or {}),
                    **trace_metadata,
                    "history_context": history_context.model_dump(mode="json"),
                },
            )

    def _resolve_trace_metadata(self, *, trace_record, database_name: str | None, runtime_context: dict, history_context, db_key: str | None) -> dict:
        trace_path = getattr(trace_record, "trace_path", None)
        run_id = getattr(trace_record, "run_id", None)
        recorded_at = getattr(trace_record, "recorded_at", None)
        completed_at = getattr(trace_record, "completed_at", None)

        latest = self.history.jsonl.get_latest_jsonl_run(database_name=database_name, db_key=db_key)
        if latest and (not run_id or run_id == latest.run_id):
            trace_path = trace_path or latest.trace_path
            run_id = run_id or latest.run_id
            recorded_at = recorded_at or latest.recorded_at
            completed_at = completed_at or latest.completed_at

        payload = {
            "trace_path": trace_path,
            "run_id": run_id,
            "trace_run_id": run_id,
            "recorded_at": recorded_at,
            "completed_at": completed_at,
        }
        if "history_index_rebuilt" in runtime_context:
            payload["history_index_rebuilt"] = bool(runtime_context.get("history_index_rebuilt"))
        elif getattr(history_context, "history_index_rebuilt", False):
            payload["history_index_rebuilt"] = True
        return payload

    def _render_snapshot_response(self, snapshot) -> str:
        return render_health_snapshot_report(snapshot)

    def _render_health_section(self, section) -> list[str]:
        lines = [f"### {section.name}", "", f"Status: {section.status}", "", section.summary or "Evidence captured."]
        if section.notes:
            lines.extend(["", "Notes:"])
            lines.extend(f"- {note}" for note in section.notes[:5])
        if section.rows:
            lines.extend(["", self._render_rows(section.rows[:10])])
        return lines + [""]

    def _render_rows(self, rows: list[dict]) -> str:
        if not rows:
            return ""
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
                if len(keys) >= 8:
                    break
            if len(keys) >= 8:
                break
        columns = [{"header": key.replace("_", " ").lower().replace(" ", "_"), "width": 18, "key": key} for key in keys]
        return "```text\n" + format_dba_table(rows, columns) + "\n```"

    def _cell(self, value) -> str:
        text = "" if value is None else str(value)
        return text.replace("\n", " ").replace("|", "\\|")[:500]

    def _render_history_response(self, context) -> str:
        lines = ["# Oracle Historical Trends", ""]
        for finding in context.recurring_findings or ["No strong recurring pattern found in recent JSONL runs."]:
            lines.append(f"- {finding}")
        lines.extend(["", "## Trend Summaries"])
        for trend in context.trend_summaries:
            lines.append(f"- {trend.metric_name}: {trend.summary}")
        lines.extend(["", "## Recent Runs"])
        for run in context.recent_runs[:5]:
            lines.append(f"- {run.completed_at}: {run.summary}")
        return "\n".join(lines)

    def _render_history_answer(self, answer) -> str:
        return render_history_answer(answer)

    def _render_sql_id_response(self, deep_dive) -> str:
        current_rows = self._mapping_rows(deep_dive.current_stats)
        ash_payload = deep_dive.ash if isinstance(deep_dive.ash, dict) else {}
        awr_payload = deep_dive.awr if isinstance(deep_dive.awr, dict) else {}
        lock_payload = deep_dive.lock_analysis if isinstance(deep_dive.lock_analysis, dict) else {}
        plan_payload = deep_dive.plan_analysis if isinstance(deep_dive.plan_analysis, dict) else {}
        history_payload = deep_dive.history_analysis if isinstance(deep_dive.history_analysis, dict) else {}
        risk_payload = deep_dive.risk_summary if isinstance(deep_dive.risk_summary, dict) else {}

        ash_summary_rows = self._mapping_rows({k: v for k, v in ash_payload.items() if k != "top_waits"})
        ash_wait_rows = ash_payload.get("top_waits") if isinstance(ash_payload.get("top_waits"), list) else []
        awr_summary_rows = self._mapping_rows({k: v for k, v in awr_payload.items() if k != "plan_changes"})
        awr_plan_rows = awr_payload.get("plan_changes") if isinstance(awr_payload.get("plan_changes"), list) else []
        lock_rows = lock_payload.get("blocking_rows") if isinstance(lock_payload.get("blocking_rows"), list) else []
        history_runs = history_payload.get("matched_runs") if isinstance(history_payload.get("matched_runs"), list) else []
        risk_reasons = risk_payload.get("reason_lines") if isinstance(risk_payload.get("reason_lines"), list) else []

        plan_summary_rows = self._mapping_rows(plan_payload)
        history_summary_rows = self._mapping_rows({k: v for k, v in history_payload.items() if k not in {"matched_runs", "cpu_seconds_samples", "elapsed_seconds_samples"}})
        risk_summary_rows = self._mapping_rows({k: v for k, v in risk_payload.items() if k != "reason_lines"})

        lines = [
            f"# SQL_ID Deep Dive — {deep_dive.sql_id}",
            "",
            "## SQL Text",
            "```sql",
            deep_dive.sql_text or "SQL text not found.",
            "```",
            "",
            "## Current Cursor Evidence",
            self._fixed_table(current_rows, [("metric", 28), ("value", 70)]) if current_rows else "No current cursor statistics were captured.",
            "",
            "## Child Cursors",
            self._fixed_table_from_rows(deep_dive.child_cursors[:20]) if deep_dive.child_cursors else "No child cursor rows were captured.",
            "",
            "## Plan Lines",
            self._fixed_table_from_rows(deep_dive.plan_lines[:30]) if deep_dive.plan_lines else "No plan lines were captured.",
            "",
            "## Active Runtime",
            self._fixed_table_from_rows(deep_dive.active_queries[:20]) if deep_dive.active_queries else "No active session currently executing this SQL_ID.",
            "",
            "## Lock Correlation",
            self._fixed_table_from_rows(self._mapping_rows({k: v for k, v in lock_payload.items() if k != "blocking_rows"})) if lock_payload else "Lock analysis unavailable.",
            "",
            self._fixed_table_from_rows(lock_rows[:20]) if lock_rows else "This SQL_ID was not found in current blocking chains.",
            "",
            "## Plan Stability Analysis",
            self._fixed_table(plan_summary_rows, [("metric", 36), ("value", 70)]) if plan_summary_rows else "Plan stability analysis unavailable.",
            "",
            "## Historical Recurrence",
            self._fixed_table(history_summary_rows, [("metric", 36), ("value", 70)]) if history_summary_rows else "Historical recurrence analysis unavailable.",
            "",
            self._fixed_table_from_rows(history_runs[:10]) if history_runs else "No historical runs matched this SQL_ID in saved traces.",
            "",
            "## Risk Verdict",
            self._fixed_table(risk_summary_rows, [("metric", 36), ("value", 70)]) if risk_summary_rows else "Risk summary unavailable.",
            "",
            "### Risk Reasons",
            "\n".join(f"- {reason}" for reason in risk_reasons[:8]) if risk_reasons else "- No risk reasons were captured.",
            "",
            "## ASH",
            self._fixed_table(ash_summary_rows, [("metric", 28), ("value", 70)]) if ash_summary_rows else "No ASH summary rows were captured or ASH was unavailable.",
            "",
            self._fixed_table_from_rows(ash_wait_rows[:10]) if ash_wait_rows else "No ASH wait-profile rows were captured.",
            "",
            "## AWR",
            self._fixed_table(awr_summary_rows, [("metric", 28), ("value", 70)]) if awr_summary_rows else "No AWR summary rows were captured or AWR was unavailable.",
            "",
            self._fixed_table_from_rows(awr_plan_rows[:10]) if awr_plan_rows else "No AWR plan-change rows were captured or AWR was unavailable.",
            "",
            "## Collector Notes",
            "\n".join(f"- {note}" for note in deep_dive.notes[:12]) if deep_dive.notes else "- No collection warnings.",
        ]
        return "\n".join(lines)

    def _build_health_failure_supporting_data(self, exc: Exception, *, failure_stage: str) -> dict:
        target = None
        try:
            target = get_oracle_target(self.db_key)
        except Exception:
            target = None

        db_key = getattr(target, "db_key", None)
        safe_target = self._sanitize_value(target.safe_dict()) if target is not None else None

        return {
            "failure_stage": failure_stage,
            "error_type": type(exc).__name__,
            "error_message": self._sanitize_message(str(exc)),
            "db_key": db_key,
            "target": safe_target,
        }

    def _sanitize_value(self, value):
        if isinstance(value, str):
            return self._sanitize_message(value)
        if isinstance(value, dict):
            return {key: self._sanitize_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._sanitize_value(item) for item in value]
        return value

    def _sanitize_message(self, message: str) -> str:
        text = message or ""
        # Redact common secret patterns while preserving enough diagnostic detail.
        key_value_patterns = [
            r"(?i)(password\s*[:=]\s*)([^,\s;]+)",
            r"(?i)(pass\s*[:=]\s*)([^,\s;]+)",
            r"(?i)(token\s*[:=]\s*)([^,\s;]+)",
            r"(?i)(secret\s*[:=]\s*)([^,\s;]+)",
            r"(?i)(wallet[_\s-]*password\s*[:=]\s*)([^,\s;]+)",
        ]
        for pattern in key_value_patterns:
            text = re.sub(pattern, r"\1***REDACTED***", text)
        # Redact credentialed DSN/URL fragments such as user/pass@host or //user:pass@host.
        text = re.sub(r"(?i)([A-Za-z0-9_.-]+)/([^@\s/]+)@", r"\1/***REDACTED***@", text)
        text = re.sub(r"(?i)(//[^:/@\s]+:)([^@\s]+)@", r"\1***REDACTED***@", text)
        return text

    def _mapping_rows(self, payload):
        if not isinstance(payload, dict):
            return []
        return [{"metric": key, "value": value} for key, value in payload.items()]

    def _render_active_sessions_response(self, *, active_rows: list[dict], blocking_rows: list[dict], resource_rows: list[dict]) -> str:
        sql_ids: list[str] = []
        seen: set[str] = set()
        for row in active_rows + blocking_rows + resource_rows:
            if not isinstance(row, dict):
                continue
            for key in ("sql_id", "blocker_sql_id", "blocked_sql_id"):
                value = str(row.get(key) or "").strip().lower()
                if not value or value in {"-", "n/a", "none"} or value in seen:
                    continue
                seen.add(value)
                sql_ids.append(value)
                if len(sql_ids) >= 5:
                    break
            if len(sql_ids) >= 5:
                break
        lines = [
            "# Active Sessions",
            "",
            f"- Active sessions: {len(active_rows)}",
            f"- Blocking chains: {len(blocking_rows)}",
            f"- High-resource session candidates: {len(resource_rows)}",
            "",
            "## SQL_ID Analysis Hint",
            "To analyze a SQL_ID, ask: `analyze sql_id <sql_id>`",
            (
                "Sample SQL_IDs from this snapshot: " + ", ".join(sql_ids)
                if sql_ids
                else "Sample SQL_IDs from this snapshot: none detected."
            ),
            "",
            "## Active Session Inventory",
            self._fixed_table_from_rows(active_rows[:25]) if active_rows else "No active user sessions were found.",
            "",
            "## Blocking Chains",
            self._fixed_table_from_rows(blocking_rows[:20]) if blocking_rows else "No blocking chains were found.",
            "",
            "## Top Session Resource Candidates",
            self._fixed_table_from_rows(resource_rows[:20]) if resource_rows else "No high-resource session candidates were found.",
        ]
        return "\n".join(lines)

    def _fixed_table_from_rows(self, rows):
        if not rows:
            return ""
        keys = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key, value in row.items():
                if key not in keys and value not in (None, "", []):
                    keys.append(key)
                if len(keys) >= 8:
                    break
            if len(keys) >= 8:
                break
        columns = [(key, 18) for key in keys]
        return self._fixed_table(rows, columns)

    def _fixed_table(self, rows, columns):
        specs = [{"header": header, "width": width, "key": header} for header, width in columns]
        return "```text\n" + format_dba_table(rows, specs) + "\n```"
```

### /home/neha/projects/agents/odb_autodba/agents/investigation_agent.py (lines 11-217)
```
class InvestigationAgent:
    RESULT_ROW_PREVIEW_LIMIT = 20

    def __init__(self, db_key: str | None = None) -> None:
        self.db_key = db_key

    def investigate(self, problem_statement: str, max_steps: int = 4, db_key: str | None = None) -> InvestigationReport:
        resolved_target = get_oracle_target(db_key or self.db_key)
        resolved_db_key = resolved_target.db_key
        self.db_key = resolved_db_key
        intents = self._detect_intents(problem_statement)
        sql_steps = self._plan_steps(problem_statement, intents)[:max_steps]
        steps: list[InvestigationStep] = []
        evidence: list[str] = []
        with db_key_context(resolved_db_key):
            for idx, item in enumerate(sql_steps, start=1):
                validation = validate_investigation_sql(item["sql"])
                if not validation.ok:
                    steps.append(
                        InvestigationStep(
                            step_number=idx,
                            goal=item["goal"],
                            sql=item["sql"],
                            result_preview=validation.reason,
                            status="error",
                        )
                    )
                    break
                result = execute_investigation_sql(validation.normalized_sql or item["sql"], db_key=resolved_db_key)
                preview = result.error if result.status == "error" else f"Returned {result.row_count} row(s). Columns: {', '.join(result.columns[:8])}"
                if result.status == "success" and result.rows:
                    evidence.append(f"Step {idx} {item['goal']}: first row {result.rows[0]}")
                rows_preview = list(result.rows[: self.RESULT_ROW_PREVIEW_LIMIT]) if result.status == "success" else []
                steps.append(
                    InvestigationStep(
                        step_number=idx,
                        goal=item["goal"],
                        sql=validation.normalized_sql or item["sql"],
                        result_preview=preview,
                        row_count=result.row_count,
                        status=result.status,
                        result_columns=list(result.columns or []),
                        result_rows=rows_preview,
                        result_truncated=bool(result.truncated or (result.status == "success" and result.row_count > len(rows_preview))),
                    )
                )
                if result.status == "error":
                    break
        likely_cause = self._derive_cause(problem_statement, intents, steps, evidence)
        report = InvestigationReport(
            problem_statement=problem_statement,
            summary=f"Ran {len(steps)} Oracle investigation step(s).",
            likely_cause=likely_cause,
            evidence=evidence,
            recommended_next_actions=self._recommended_next_actions(intents, steps),
            steps=steps,
        )
        investigation_id = append_investigation_trace(problem_statement, [step.model_dump() for step in steps], db_key=resolved_db_key)
        trace_path = str(investigation_trace_path(investigation_id=investigation_id, db_key=resolved_db_key))
        report.trace_path = trace_path
        return report

    def _plan_steps(self, problem_statement: str, intents: set[str]) -> list[dict[str, str]]:
        lowered = (problem_statement or "").lower()
        sql_id = extract_sql_id(problem_statement)
        steps: list[dict[str, str]] = []

        if sql_id:
            steps.extend(
                [
                {"goal": "Inspect current SQL statistics", "sql": f"select sql_id, plan_hash_value, executions, round(elapsed_time/1e6,3) elapsed_s, round(cpu_time/1e6,3) cpu_s from v$sqlstats where sql_id = '{sql_id}'"},
                {"goal": "Inspect child cursors", "sql": f"select child_number, plan_hash_value, executions from v$sql where sql_id = '{sql_id}' order by child_number"},
                ]
            )
        if "blocking" in intents:
            steps.extend(
                [
                {"goal": "Identify blocking sessions", "sql": "select inst_id, sid, serial#, username, sql_id, blocking_instance, blocking_session, event, wait_class from gv$session where blocking_session is not null"},
                {"goal": "Inspect blocker sessions", "sql": "select inst_id, sid, serial#, username, status, sql_id, event, wait_class, module, program from gv$session where sid in (select blocking_session from gv$session where blocking_session is not null)"},
                ]
            )
        if "errors" in intents:
            steps.append({"goal": "Review recent alert log errors", "sql": "select originating_timestamp, message_text from v$diag_alert_ext where regexp_like(message_text, 'ORA-|TNS-', 'i') order by originating_timestamp desc fetch first 20 rows only"})
        if "user_count" in intents:
            steps.append(
                {
                    "goal": "Count database users",
                    "sql": "select count(*) as total_users, sum(case when nvl(oracle_maintained,'N')='N' then 1 else 0 end) as non_oracle_maintained_users from dba_users",
                }
            )
        if "db_size" in intents:
            steps.append(
                {
                    "goal": "Measure allocated database size",
                    "sql": "select round((select nvl(sum(bytes),0) from dba_data_files)/1024/1024/1024,2) as datafiles_gb, round((select nvl(sum(bytes),0) from dba_temp_files)/1024/1024/1024,2) as tempfiles_gb, round((select nvl(sum(bytes),0) from v$log)/1024/1024/1024,2) as redo_gb, round(((select nvl(sum(bytes),0) from dba_data_files)+(select nvl(sum(bytes),0) from dba_temp_files)+(select nvl(sum(bytes),0) from v$log))/1024/1024/1024,2) as total_allocated_gb from dual",
                }
            )
            steps.append(
                {
                    "goal": "Estimate used segment size",
                    "sql": "select round(nvl(sum(bytes),0)/1024/1024/1024,2) as used_segments_gb from dba_segments",
                }
            )
        if "sessions" in intents:
            steps.append(
                {
                    "goal": "Inspect active sessions",
                    "sql": "select inst_id, sid, serial#, username, status, sql_id, event, wait_class, module, program, machine from gv$session where status = 'ACTIVE' and username is not null fetch first 20 rows only",
                }
            )
        if "top_sql_cpu" in intents:
            steps.append(
                {
                    "goal": "Inspect top SQL by CPU",
                    "sql": "select sql_id, plan_hash_value, round(cpu_time/1e6,3) cpu_s, round(elapsed_time/1e6,3) elapsed_s, executions from v$sqlstats order by cpu_time desc fetch first 10 rows only",
                }
            )

        if steps:
            return self._dedupe_steps(steps)

        if "ora" in lowered or "error" in lowered:
            return [{"goal": "Review recent alert log errors", "sql": "select originating_timestamp, message_text from v$diag_alert_ext where regexp_like(message_text, 'ORA-|TNS-', 'i') order by originating_timestamp desc fetch first 20 rows only"}]
        return [
            {"goal": "Inspect active sessions", "sql": "select inst_id, sid, serial#, username, status, sql_id, event, wait_class, module, program, machine from gv$session where status = 'ACTIVE' and username is not null fetch first 20 rows only"},
            {"goal": "Inspect top SQL by CPU", "sql": "select sql_id, plan_hash_value, round(cpu_time/1e6,3) cpu_s, round(elapsed_time/1e6,3) elapsed_s, executions from v$sqlstats order by cpu_time desc fetch first 10 rows only"},
        ]

    def _derive_cause(self, problem_statement: str, intents: set[str], steps: list[InvestigationStep], evidence: list[str]) -> str:
        if not steps:
            return "No investigation steps were planned from the request."
        if any(step.status == "error" for step in steps):
            return "The investigation hit one or more SQL execution errors; results may be incomplete."
        if not evidence:
            return "The investigation did not gather enough evidence to isolate a finding."
        if "blocking" in intents:
            return "Blocking or lock contention is the leading cause candidate based on the investigation path."
        if "top_sql_cpu" in intents or "sessions" in intents:
            return "Runtime workload evidence was collected for active sessions and SQL resource usage."
        if "user_count" in intents and "db_size" in intents:
            return "Requested inventory metrics were collected: database user count and database size estimates."
        if "user_count" in intents:
            return "Requested inventory metric was collected: database user count."
        if "db_size" in intents:
            return "Requested inventory metric was collected: database size estimate."
        lowered = (problem_statement or "").lower()
        if "cpu" in lowered or "slow" in lowered:
            return "One or more high-cost SQL statements appear to be contributing to the slowdown."
        return "Investigation completed with read-only evidence collection based on your request."

    def _recommended_next_actions(self, intents: set[str], steps: list[InvestigationStep]) -> list[str]:
        if any(step.status == "error" for step in steps):
            return [
                "Review the failed step and verify privileges on referenced v$/dba_ views.",
                "Retry investigation after privilege or connectivity fixes.",
            ]
        if "user_count" in intents and "db_size" in intents:
            return [
                "Use the returned user counts to validate expected account inventory.",
                "Use the size breakdown (datafiles/tempfiles/redo) for capacity planning baselines.",
            ]
        if "user_count" in intents:
            return ["Review user count results and reconcile with expected account inventory."]
        if "db_size" in intents:
            return ["Use the size metrics as a baseline for growth and storage capacity planning."]
        if "blocking" in intents:
            return [
                "Review blocker and waiter SQL_ID/session owners together before intervention.",
                "If blocker termination is necessary, use guarded remediation with operator confirmation.",
            ]
        if "top_sql_cpu" in intents or "sessions" in intents:
            return [
                "Correlate active sessions with top SQL to confirm the dominant workload source.",
                "Run SQL_ID deep dive on the highest-impact SQL_ID for plan and wait analysis.",
            ]
        return ["Review the SQL steps and confirm whether additional targeted investigation is needed."]

    def _detect_intents(self, problem_statement: str) -> set[str]:
        lowered = (problem_statement or "").lower()
        intents: set[str] = set()
        if self._contains_any(lowered, ("block", "blocking", "lock", "locked", "contention")):
            intents.add("blocking")
        if self._contains_any(lowered, ("ora", "tns", "error", "errors", "alert log", "listener")):
            intents.add("errors")
        if self._contains_any(lowered, ("active session", "active sessions", "session")):
            intents.add("sessions")
        if self._contains_any(lowered, ("cpu", "top sql", "slow", "slowness", "performance")):
            intents.add("top_sql_cpu")
        if self._contains_any(lowered, ("how many users", "database users", "user count", "users exist", "schemas", "accounts")):
            intents.add("user_count")
        if self._contains_any(lowered, ("database size", "size of database", "db size", "how big", "storage size", "space used", "size")):
            intents.add("db_size")
        return intents

    def _contains_any(self, text: str, tokens: tuple[str, ...]) -> bool:
        return any(token in text for token in tokens)

    def _dedupe_steps(self, steps: list[dict[str, str]]) -> list[dict[str, str]]:
        seen: set[str] = set()
        deduped: list[dict[str, str]] = []
        for step in steps:
            sql = " ".join((step.get("sql") or "").split()).strip().lower()
            if not sql or sql in seen:
                continue
            seen.add(sql)
            deduped.append(step)
        return deduped
```

### /home/neha/projects/agents/odb_autodba/agents/root_cause_engine.py (lines 143-245)
```
def infer_root_cause(
    *,
    mode: str,
    summary: str,
    supporting_data: dict[str, Any] | None,
    rendered_report: str | None,
) -> dict[str, Any]:
    supporting = supporting_data or {}
    report_text = (rendered_report or "").lower()
    latest_metrics = _extract_latest_metrics(supporting)
    host_check = _extract_host_check_context(supporting=supporting, latest_metrics=latest_metrics)
    state_transition = supporting.get("state_transition") if isinstance(supporting.get("state_transition"), dict) else {}
    learning = _extract_learning_features(supporting, state_transition)
    awr = state_transition.get("awr_state_diff") if isinstance(state_transition.get("awr_state_diff"), dict) else {}
    active_payload = supporting.get("active_sessions") if isinstance(supporting.get("active_sessions"), dict) else {}
    recurring_patterns = _extract_recurring_patterns(supporting, state_transition)
    recurrence_support = _build_recurrence_support(recurring_patterns)

    blocking_signal = _detect_blocking_signal(report_text, latest_metrics, active_payload)
    sql_signal = _detect_sql_regression_signal(learning, awr, latest_metrics)
    sql_pattern_signal = _detect_sql_performance_pattern_signal(report_text, learning, awr, latest_metrics)
    cpu_signal = _detect_cpu_signal(report_text, learning, awr, latest_metrics, host_check)
    memory_signal = _detect_memory_signal(report_text, learning, awr, latest_metrics, host_check)
    storage_signal = _detect_storage_or_alert_signal(report_text, latest_metrics)

    # Priority order: blocking_lock > sql_regression > sql_performance_pattern > cpu_pressure > memory_pressure > storage_or_alert_error > historical_recurrence > inconclusive
    if blocking_signal["present"]:
        category = "blocking_lock"
        signal = blocking_signal
    elif sql_signal["present"]:
        category = "sql_regression"
        signal = sql_signal
    elif sql_pattern_signal["present"]:
        category = "sql_performance_pattern"
        signal = sql_pattern_signal
    elif cpu_signal["present"]:
        category = "cpu_pressure"
        signal = cpu_signal
    elif memory_signal["present"]:
        category = "memory_pressure"
        signal = memory_signal
    elif storage_signal["present"]:
        category = "storage_or_alert_error"
        signal = storage_signal
    elif recurrence_support:
        category = "historical_recurrence"
        signal = {
            "present": True,
            "strength": min(55.0 + len(recurring_patterns) * 5.0, 78.0),
            "primary_evidence": recurrence_support[:3],
            "supporting_evidence": recurrence_support[3:],
            "reasoning": "No stronger current incident signal was detected; recurrence is the strongest available pattern.",
            "impacted_components": ["historical workload stability", "recurrent incident pattern"],
            "next_validation_step": "Run a fresh health check and compare dominant SQL/wait/locking metrics against recurring fingerprints.",
            "current_evidence_count": 0,
        }
    elif mode == "investigation":
        likely_signal = _detect_investigation_likely_cause_signal(supporting)
        if likely_signal["present"]:
            category = likely_signal["category"]
            signal = likely_signal
        else:
            category = "inconclusive"
            signal = _build_inconclusive_signal(latest_metrics, learning, recurring_patterns)
    else:
        category = "inconclusive"
        signal = _build_inconclusive_signal(latest_metrics, learning, recurring_patterns)

    primary_evidence = _dedupe_cap_lines(signal.get("primary_evidence") or [], cap=3)
    supporting_evidence = _dedupe_cap_lines((signal.get("supporting_evidence") or []) + recurrence_support, cap=5)
    if category == "historical_recurrence":
        supporting_evidence = _dedupe_cap_lines(signal.get("supporting_evidence") or [], cap=5)
    if not primary_evidence:
        if supporting_evidence:
            primary_evidence = [supporting_evidence[0]]
            supporting_evidence = supporting_evidence[1:]
        else:
            primary_evidence = [f"Deterministic rule matched category `{category}` with limited explicit metric detail."]

    all_evidence = _dedupe_cap_lines(primary_evidence + supporting_evidence, cap=8)
    current_evidence_count = _to_int(signal.get("current_evidence_count"))
    confidence = _resolve_confidence(
        score=_to_float(signal.get("strength")),
        category=category,
        host_check_scope=str(host_check.get("host_check_scope") or ""),
        current_evidence_count=current_evidence_count,
        recurrence_count=len(recurring_patterns),
        data_completeness=_estimate_data_completeness(latest_metrics, learning, state_transition),
    )
    reasoning = str(signal.get("reasoning") or "").strip() or "Deterministic signal rules identified the most likely contributing category."
    impacted_components = _dedupe_cap_lines(signal.get("impacted_components") or [], cap=6)
    next_validation_step = str(signal.get("next_validation_step") or _default_next_validation_step(category)).strip()

    return {
        "category": category,
        "confidence": confidence,
        "evidence": all_evidence,
        "primary_evidence": primary_evidence,
        "supporting_evidence": supporting_evidence,
        "reasoning": reasoning,
        "impacted_components": impacted_components,
        "next_validation_step": next_validation_step,
    }
```


## Source Files:

- `agents/correlation_engine.py`
- `agents/investigation_agent.py`
- `agents/planner_agent.py`
- `agents/root_cause_engine.py`
- `utils/sql_analysis.py`

