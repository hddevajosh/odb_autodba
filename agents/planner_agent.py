from __future__ import annotations

import logging
import re

from odb_autodba.db.connection import db_key_context
from odb_autodba.db.health_checks import collect_health_snapshot
from odb_autodba.db.query_deep_dive import build_sql_id_deep_dive_report, extract_queryid_from_text
from odb_autodba.db.running_sessions import get_running_sessions_inventory
from odb_autodba.history.service import HistoryService
from odb_autodba.models.schemas import PlannerResponse
from odb_autodba.rag.trace_store import append_health_run_trace
from odb_autodba.rag.indexer import get_index_status
from odb_autodba.target_registry import get_oracle_target
from odb_autodba.tools.action_proposals import build_remediation_proposal
from odb_autodba.tools.action_reviewer import build_guardrail_review
from odb_autodba.utils.formatter import (
    format_dba_table,
    render_health_snapshot_report,
    render_history_answer,
    render_sql_id_deep_dive_report,
)
from odb_autodba.utils.sql_analysis import looks_like_active_sessions_request, looks_like_history_request, wants_sql_id_analysis

LOGGER = logging.getLogger(__name__)


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
                    return PlannerResponse(mode="focused_domain_report", summary=f"SQL_ID {sql_id} deep dive could not be completed.", body_markdown=f"# SQL_ID Deep Dive\n\nUnable to collect SQL_ID evidence: {exc}", recommendations=["Verify Oracle connectivity and privileges for gv$sqlstats, gv$sql, and gv$sql_plan."])
            if looks_like_active_sessions_request(user_text or ""):
                try:
                    active_rows = [row.model_dump(mode="json") for row in get_running_sessions_inventory()]
                    body = self._render_active_sessions_response(active_rows=active_rows)
                    return PlannerResponse(
                        mode="focused_domain_report",
                        summary=f"Active session snapshot collected ({len(active_rows)} active session(s)).",
                        body_markdown=body,
                        recommendations=[
                            "Use `Analyze SQL_ID <sql_id>` on top active SQL to deep dive plan and wait behavior.",
                        ],
                        supporting_data={
                            "active_sessions": {
                                "active_count": len(active_rows),
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
            review = build_guardrail_review(proposal)
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

    def _render_active_sessions_response(self, *, active_rows: list[dict]) -> str:
        sql_ids: list[str] = []
        seen: set[str] = set()
        for row in active_rows:
            if not isinstance(row, dict):
                continue
            for key in ("sql_id",):
                value = str(row.get(key) or "").strip().lower()
                if not value or value in {"-", "n/a", "none"} or value in seen:
                    continue
                seen.add(value)
                sql_ids.append(value)
                if len(sql_ids) >= 5:
                    break
            if len(sql_ids) >= 5:
                break
        sql_hint = "Tip: analyze SQL with `analyze sql_id <sql_id>`."
        if sql_ids:
            sql_hint = f"Tip: analyze SQL with `analyze sql_id <sql_id>` (sample: {', '.join(sql_ids)})."
        lines = [
            "# Active Sessions",
            "",
            f"- Active sessions: {len(active_rows)}",
            "",
            "## Active Session Inventory",
            self._fixed_table_from_rows(
                active_rows[:25],
                preferred_keys=["inst_id", "sid", "serial_num", "username", "status", "sql_id", "sql_text", "event"],
                key_widths={"sql_text": 48},
            )
            if active_rows
            else "No active user sessions were found.",
            "",
            sql_hint,
        ]
        return "\n".join(lines)

    def _fixed_table_from_rows(
        self,
        rows,
        preferred_keys: list[str] | None = None,
        key_widths: dict[str, int] | None = None,
    ):
        if not rows:
            return ""
        if preferred_keys:
            keys = [
                key
                for key in preferred_keys
                if any(isinstance(row, dict) and row.get(key) not in (None, "", []) for row in rows)
            ]
        else:
            keys = []
        if not keys:
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
        width_map = key_widths or {}
        columns = [(key, int(width_map.get(key, 18))) for key in keys[:8]]
        return self._fixed_table(rows, columns)

    def _fixed_table(self, rows, columns):
        specs = [{"header": header, "width": width, "key": header} for header, width in columns]
        return "```text\n" + format_dba_table(rows, specs) + "\n```"
