from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from time import perf_counter
from typing import Any

from pathlib import Path

from odb_autodba.db.connection import db_key_context
from odb_autodba.db.investigation_sql import execute_investigation_sql, validate_investigation_sql
from odb_autodba.models.schemas import InvestigationReport, InvestigationSQLAttemptRecord, InvestigationStep, InvestigationStepDecision
from odb_autodba.rag.investigation_trace_store import (
    append_investigation_event,
    append_investigation_trace,  # backward-compatible symbol for existing tests/mocks
    investigation_trace_path,
    new_investigation_id,
)
from odb_autodba.rag.trace_store import read_health_run_traces
from odb_autodba.target_registry import get_oracle_target
from odb_autodba.utils.sql_analysis import extract_sql_id

LOGGER = logging.getLogger(__name__)


class InvestigationAgent:
    DEFAULT_MAX_STEPS = 6
    DEFAULT_DIAGNOSTIC_MAX_STEPS = 8
    DEFAULT_ROW_PREVIEW_LIMIT = 5
    DEFAULT_EVIDENCE_ROW_LIMIT = 50
    DEFAULT_SQL_MAX_ATTEMPTS = 5  # attempt 1 initial + up to 4 repairs
    DEFAULT_SQL_EXECUTION_CAP = 20
    DEFAULT_DIAGNOSTIC_SQL_EXECUTION_CAP = 25

    def __init__(
        self,
        *,
        ai_service: Any | None = None,
        max_steps: int = DEFAULT_MAX_STEPS,
        sql_validator: Any | None = None,
        sql_executor: Any | None = None,
        trace_root: Path | None = None,
        row_preview_limit: int = DEFAULT_ROW_PREVIEW_LIMIT,
        max_sql_retries_per_step: int = 4,
        db_key: str | None = None,
    ) -> None:
        self.db_key = db_key
        self.ai_service = ai_service
        self.max_steps = max(1, int(max_steps))
        self.sql_validator = sql_validator or validate_investigation_sql
        self.sql_executor = sql_executor or execute_investigation_sql
        self.trace_root = trace_root
        self.row_preview_limit = max(1, int(row_preview_limit))
        self.evidence_row_limit = max(1, int(self.DEFAULT_EVIDENCE_ROW_LIMIT))
        self.max_sql_retries_per_step = max(0, int(max_sql_retries_per_step))

    def run(self, user_question: str, *, db_key: str | None = None) -> InvestigationReport:
        return self.investigate(user_question, db_key=db_key)

    def _resolve_planner_model_config(self) -> tuple[str, str, bool]:
        planner_env = str(os.getenv("ODB_AUTODBA_INVESTIGATION_PLANNER_MODEL") or "").strip()
        openai_model_env = str(os.getenv("OPENAI_MODEL") or "").strip()
        if planner_env:
            model_name = planner_env
            model_source = "ODB_AUTODBA_INVESTIGATION_PLANNER_MODEL"
        elif openai_model_env:
            model_name = openai_model_env
            model_source = "OPENAI_MODEL"
        else:
            model_name = "gpt-4o-mini"
            model_source = "default"
        openai_api_key_present = bool(str(os.getenv("OPENAI_API_KEY") or "").strip())
        return model_name, model_source, openai_api_key_present

    def _start_trace(
        self,
        *,
        problem_statement: str,
        db_key: str | None,
        max_steps: int,
        max_sql_attempts: int,
        plan_meta: dict[str, Any],
    ) -> dict[str, Any]:
        investigation_id = new_investigation_id()
        trace_path = investigation_trace_path(investigation_id=investigation_id, root=self.trace_root, db_key=db_key)
        ctx = {
            "investigation_id": investigation_id,
            "trace_path": trace_path,
            "db_key": db_key,
            "user_question": problem_statement,
            "trace_disabled": False,
            "trace_warning": "",
        }
        self._append_trace_event(
            ctx,
            "investigation.start",
            {
                "problem_statement": problem_statement,
                "question": problem_statement,
            },
        )
        self._append_trace_event(
            ctx,
            "investigation.meta",
            {
                "db_type": "oracle",
                "max_steps": max_steps,
                "max_sql_attempts": max_sql_attempts,
                "planner_provider": str(plan_meta.get("planner_provider") or "unknown"),
                "planner_model": str(plan_meta.get("planner_model") or "unknown"),
                "planner_steps_count": int(plan_meta.get("planner_steps_count") or 0),
                "fallback_used": bool(plan_meta.get("fallback_used")),
                "fallback_reason": str(plan_meta.get("fallback_reason") or ""),
                "model_source": str(plan_meta.get("model_source") or "unknown"),
                "openai_api_key_present": bool(plan_meta.get("openai_api_key_present")),
            },
        )
        return ctx

    def _append_trace_event(self, trace_ctx: dict[str, Any], event_type: str, payload: dict[str, Any]) -> None:
        if bool(trace_ctx.get("trace_disabled")):
            return
        question = str(trace_ctx.get("user_question") or "")
        base_payload = {
            "investigation_id": str(trace_ctx.get("investigation_id") or ""),
            "db_type": "oracle",
            "user_question": question,
            "problem_statement": question,
            "question": question,
        }
        base_payload.update(payload or {})
        try:
            append_investigation_event(
                Path(str(trace_ctx["trace_path"])),
                {
                    "event_type": str(event_type or "").strip(),
                    "payload": base_payload,
                },
            )
        except Exception as exc:
            trace_ctx["trace_disabled"] = True
            trace_ctx["trace_warning"] = (
                f"Trace write failed at event '{str(event_type or '').strip()}': {type(exc).__name__}: {str(exc or '').strip()}"
            )
            LOGGER.warning(
                "investigation_trace_write_failed id=%s db_key=%s trace_path=%s event_type=%s error_type=%s error=%s",
                str(trace_ctx.get("investigation_id") or ""),
                str(trace_ctx.get("db_key") or self.db_key or ""),
                str(trace_ctx.get("trace_path") or ""),
                str(event_type or "").strip(),
                type(exc).__name__,
                str(exc),
                exc_info=True,
            )

    def _append_sql_attempt_event(
        self,
        trace_ctx: dict[str, Any],
        *,
        step_number: int,
        attempt: InvestigationSQLAttemptRecord,
        llm_role: str,
        prompt_type: str,
    ) -> None:
        self._append_trace_event(
            trace_ctx,
            "investigation.sql_attempt",
            {
                "step_no": step_number,
                "attempt_no": int(attempt.attempt_no or 0),
                "sql": str(attempt.sql or ""),
                "repaired": bool(attempt.repaired),
                "recoverable": bool(attempt.recoverable),
                "validation": "ok" if bool(attempt.validation_ok) else "failed",
                "execution": str(attempt.execution_status or ""),
                "error": str(attempt.error or ""),
                "error_code": str(attempt.error_code or ""),
                "repair_reason": str(attempt.repair_reason or ""),
                "model_used": str(os.getenv("ODB_AUTODBA_INVESTIGATION_PLANNER_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o-mini"),
                "llm_role": llm_role,
                "prompt_type": prompt_type,
            },
        )

    def investigate(
        self,
        problem_statement: str,
        max_steps: int | None = None,
        db_key: str | None = None,
        *,
        thread_memory: dict[str, Any] | None = None,
        thread_id: str | None = None,
        thread_continued: bool = False,
    ) -> InvestigationReport:
        resolved_target = get_oracle_target(db_key or self.db_key)
        resolved_db_key = resolved_target.db_key
        self.db_key = resolved_db_key

        normalized_question = " ".join(str(problem_statement or "").strip().split())
        if not normalized_question:
            raise RuntimeError("Please enter an Oracle problem to investigate.")

        profile = self._question_profile(normalized_question)
        diagnostic_mode = bool(profile.get("diagnostic_mode"))
        default_steps = self.DEFAULT_DIAGNOSTIC_MAX_STEPS if diagnostic_mode else self.max_steps
        resolved_max_steps = max(1, int(max_steps if max_steps is not None else default_steps))
        sql_max_attempts = self._sql_max_attempts()
        sql_execution_cap = self._sql_execution_cap(diagnostic_mode=diagnostic_mode)
        required_evidence = self._required_evidence_for_question(normalized_question)
        active_thread_memory: dict[str, Any] = {}

        runtime_meta = self._init_step_runtime(problem_statement=normalized_question, max_steps=resolved_max_steps, profile=profile)
        planner_notes = self._coerce_notes_list(runtime_meta.get("notes"))
        if thread_continued or str(thread_id or "").strip() or bool(thread_memory):
            planner_notes.append("Thread memory is disabled for this run; only current-job evidence was used.")
        compact_context = self._load_recent_context(normalized_question, db_key=resolved_db_key)
        history_context = dict(compact_context.get("historical_context", {}) or {})

        steps: list[InvestigationStep] = []
        evidence: list[str] = []
        decision_notes: list[str] = []
        prior_step_results: list[dict[str, Any]] = []
        failed_sql_attempts: list[dict[str, Any]] = []
        sql_execution_count = 0
        repeated_low_signal = 0
        incomplete_evidence_active = False
        termination_reason = "completed"
        clarification_question = ""
        final_answer = ""

        trace_ctx = self._start_trace(
            problem_statement=normalized_question,
            db_key=resolved_db_key,
            max_steps=resolved_max_steps,
            max_sql_attempts=sql_max_attempts,
            plan_meta=runtime_meta,
        )
        question_text = str(normalized_question or "")
        question_hash = hashlib.sha256(question_text.encode("utf-8")).hexdigest()[:16] if question_text else ""
        planner_model = str(runtime_meta.get("planner_model") or "unknown")
        investigation_model = str(runtime_meta.get("investigation_model") or planner_model)
        model_source = str(runtime_meta.get("model_source") or "unknown")
        openai_api_key_present = bool(runtime_meta.get("openai_api_key_present"))

        LOGGER.info(
            "investigation_start id=%s question_present=%s question_len=%s question_hash=%s max_steps=%s max_sql_attempts=%s sql_execution_cap=%s model=%s investigation_model=%s model_source=%s openai_api_key_present=%s",
            trace_ctx["investigation_id"],
            str(bool(question_text.strip())).lower(),
            len(question_text),
            question_hash,
            resolved_max_steps,
            sql_max_attempts,
            sql_execution_cap,
            planner_model,
            investigation_model,
            model_source,
            str(openai_api_key_present).lower(),
        )

        with db_key_context(resolved_db_key):
            for step_no in range(1, resolved_max_steps + 1):
                if sql_execution_count >= sql_execution_cap:
                    termination_reason = "sql_execution_cap_reached"
                    planner_notes.append(f"Investigation stopped after reaching SQL execution cap ({sql_execution_cap}).")
                    break

                decision_result = self._next_step_decision(
                    problem_statement=normalized_question,
                    step_no=step_no,
                    max_steps=resolved_max_steps,
                    required_evidence=required_evidence,
                    executed_steps=steps,
                    prior_step_results=prior_step_results,
                    failed_sql_attempts=failed_sql_attempts,
                    findings=evidence,
                    runtime_meta=runtime_meta,
                    compact_context=compact_context,
                    history_context=history_context,
                    active_thread_memory=active_thread_memory,
                )
                planner_failure_reason = ""
                if isinstance(decision_result, tuple) and len(decision_result) == 2:
                    decision = decision_result[0]
                    planner_failure_reason = str(decision_result[1] or "").strip()
                else:
                    decision = decision_result

                decision_notes.extend(self._coerce_notes_list(decision.analysis))
                if isinstance(decision.required_evidence_status, dict) and decision.required_evidence_status:
                    for key, value in decision.required_evidence_status.items():
                        if key in required_evidence:
                            required_evidence[key] = bool(value)

                self._append_trace_event(
                    trace_ctx,
                    "investigation.decision",
                    {
                        "step_no": step_no,
                        "next_action": decision.next_action,
                        "goal": decision.goal,
                        "confidence": decision.confidence,
                        "is_final": bool(decision.is_final),
                        "analysis": decision.analysis,
                        "clarification_question": decision.clarification_question or "",
                    },
                )

                if planner_failure_reason:
                    termination_reason = planner_failure_reason
                    planner_notes.append(
                        str(decision.analysis or f"Step {step_no}: planner failure ({planner_failure_reason}).").strip()
                    )
                    break

                if decision.next_action == "clarify":
                    termination_reason = "clarification_required"
                    clarification_question = str(decision.clarification_question or "Please clarify the question scope.").strip()
                    planner_notes.append(clarification_question)
                    break

                if decision.next_action == "conclude" or decision.is_final:
                    if step_no < resolved_max_steps and (incomplete_evidence_active or not self._all_required_evidence_satisfied(required_evidence)):
                        planner_notes.append("Conclusion deferred because required evidence is incomplete.")
                        continue
                    termination_reason = "llm_concluded"
                    final_answer = str(decision.final_answer or "").strip()
                    planner_notes.extend(self._coerce_notes_list(decision.recommended_actions))
                    break

                sql = str(decision.sql or "").strip()
                if not sql:
                    termination_reason = "planner_returned_empty_sql"
                    planner_notes.append(f"Step {step_no}: planner requested run_sql without SQL text.")
                    break

                step, step_notes, executions_used = self._execute_step_sql_with_repairs(
                    step_number=step_no,
                    goal=str(decision.goal or f"Step {step_no} investigation").strip(),
                    initial_sql=sql,
                    problem_statement=normalized_question,
                    db_key=resolved_db_key,
                    max_attempts=sql_max_attempts,
                    trace_ctx=trace_ctx,
                    findings=evidence,
                    prior_step_results=prior_step_results,
                    remaining_sql_executions=max(sql_execution_cap - sql_execution_count, 0),
                )
                sql_execution_count += executions_used
                steps.append(step)
                planner_notes.extend(step_notes)

                self._update_required_evidence(
                    required_evidence=required_evidence,
                    question_profile=profile,
                    step=step,
                    prior_step_results=prior_step_results,
                )

                if step.status == "success":
                    finding_text = step.finding or f"Step {step_no} returned {int(step.row_count or 0)} row(s)."
                    incomplete_reason = self._incomplete_evidence_reason(
                        question=normalized_question,
                        decision=decision,
                        step=step,
                        required_evidence=required_evidence,
                        prior_step_results=prior_step_results,
                    )
                    if incomplete_reason:
                        finding_text = f"{finding_text} Evidence incomplete: {incomplete_reason}"
                        step.finding = finding_text
                        step.confidence = "LOW"
                        step.inference_confidence = "LOW"
                        incomplete_evidence_active = True
                    else:
                        incomplete_evidence_active = False
                    evidence.append(finding_text)
                    prior_step_results.append(
                        {
                            "step_no": step.step_number,
                            "goal": step.goal,
                            "sql": step.sql,
                            "rowcount": int(step.row_count or 0),
                            "columns": list(step.result_columns or []),
                            "result_preview": list(step.result_rows[: self.row_preview_limit]),
                            "finding": finding_text,
                        }
                    )
                else:
                    last_attempt = step.correction_attempts[-1] if step.correction_attempts else None
                    failed_sql_attempts.append(
                        {
                            "step_no": step_no,
                            "goal": step.goal,
                            "sql": step.sql,
                            "error": step.result_preview,
                            "error_code": getattr(last_attempt, "error_code", "") if last_attempt is not None else "",
                        }
                    )
                    if self._step_has_unrecoverable_error(step):
                        termination_reason = "unrecoverable_sql_error"
                    else:
                        termination_reason = "step_failed"
                    break

                if step.row_count == 0:
                    repeated_low_signal += 1
                else:
                    repeated_low_signal = 0
                if repeated_low_signal >= 2 and not self._all_required_evidence_satisfied(required_evidence):
                    termination_reason = "low_signal_results"
                    planner_notes.append("Stopped after repeated low-signal zero-row results while evidence remained incomplete.")
                    break

                if self._all_required_evidence_satisfied(required_evidence):
                    termination_reason = "evidence_complete"
                    break

        plan_type = str(profile.get("plan_type") or "unknown")
        base_inference = final_answer or self._derive_cause(normalized_question, steps, evidence, plan_type=plan_type)
        likely_cause = base_inference
        if termination_reason == "clarification_required":
            likely_cause = clarification_question or "User clarification is required before running SQL safely."
        elif termination_reason == "planner_json_parse_failed":
            likely_cause = "Planner returned invalid JSON and recovery attempts failed."
        else:
            likely_cause = self._compose_dba_inference(
                problem_statement=normalized_question,
                steps=steps,
                historical_context=history_context,
                termination_reason=termination_reason,
                plan_type=plan_type,
                base_inference=base_inference,
            )
        summary = (
            f"Ran {len(steps)} logical investigation step(s) with {sql_execution_count} SQL execution(s)."
            if steps
            else "No SQL steps were executed."
        )

        evidence_metadata = self._resolve_evidence_metadata(
            steps=steps,
            historical_context=history_context,
            summary_fragments=[likely_cause, summary, *evidence],
        )

        confidence = (
            "HIGH"
            if self._all_required_evidence_satisfied(required_evidence) and any(s.status == "success" for s in steps)
            else "MEDIUM"
            if any(s.status == "success" for s in steps)
            else "LOW"
        )
        inference_confidence = (
            "HIGH"
            if self._all_required_evidence_satisfied(required_evidence)
            else "MEDIUM"
            if any(s.status == "success" for s in steps)
            else "LOW"
        )

        if not planner_notes:
            planner_notes = []
        if str(trace_ctx.get("trace_warning") or "").strip():
            planner_notes.append(str(trace_ctx.get("trace_warning") or "").strip())
        planner_notes.append(self._termination_reason_note(termination_reason=termination_reason))
        planner_notes.append(
            self._confidence_reason_note(
                confidence=confidence,
                inference_confidence=inference_confidence,
                required_evidence=required_evidence,
                successful_steps=sum(1 for step in steps if step.status == "success"),
            )
        )
        planner_notes.extend(decision_notes)
        planner_notes = self._dedupe_strings(self._coerce_notes_list(planner_notes))

        if not evidence and termination_reason == "evidence_complete":
            termination_reason = "completed"

        report = InvestigationReport(
            problem_statement=normalized_question,
            summary=summary,
            likely_cause=likely_cause,
            evidence=evidence,
            recommended_next_actions=self._recommended_next_actions(normalized_question, steps, plan_type=plan_type),
            steps=steps,
            plan_type=plan_type,
            planner_provider=str(runtime_meta.get("planner_provider") or "deterministic_fallback"),
            planner_model=str(runtime_meta.get("planner_model") or "deterministic"),
            planner_elapsed_ms=int(runtime_meta.get("planner_elapsed_ms") or 0),
            planner_steps_count=len(steps),
            planner_requested=True,
            fallback_used=bool(runtime_meta.get("fallback_used")),
            fallback_reason=str(runtime_meta.get("fallback_reason") or ""),
            planner_notes=planner_notes,
            evidence_source=str(evidence_metadata.get("evidence_source") or "SQL"),
            historical_context_used=bool(evidence_metadata.get("historical_context_used")),
            investigation_mode=plan_type,
            confidence=confidence,
            inference_confidence=inference_confidence,
            termination_reason=termination_reason,
            required_evidence_status=required_evidence,
            clarification_question=clarification_question,
            sql_execution_count=sql_execution_count,
            sql_execution_cap=sql_execution_cap,
            thread_id="",
            thread_continued=False,
            thread_context_summary={},
        )

        self._append_trace_event(
            trace_ctx,
            "investigation.conclusion",
            {
                "likely_cause": likely_cause,
                "summary": summary,
                "confidence": report.confidence,
                "inference_confidence": report.inference_confidence,
                "termination_reason": report.termination_reason,
                "step_count": len(steps),
                "required_evidence_status": required_evidence,
                "clarification_question": clarification_question,
                "sql_execution_count": sql_execution_count,
                "sql_execution_cap": sql_execution_cap,
                "evidence_source": report.evidence_source,
                "historical_context_used": report.historical_context_used,
                "investigation_mode": report.investigation_mode,
            },
        )

        LOGGER.info(
            "investigation_stop id=%s termination_reason=%s successful_steps=%s total_steps=%s sql_execution_count=%s sql_execution_cap=%s",
            trace_ctx["investigation_id"],
            report.termination_reason,
            sum(1 for step in steps if step.status == "success"),
            len(steps),
            sql_execution_count,
            sql_execution_cap,
        )

        trace_path = str(trace_ctx["trace_path"])
        report.trace_path = trace_path
        return report

    def _init_step_runtime(self, *, problem_statement: str, max_steps: int, profile: dict[str, Any]) -> dict[str, Any]:
        planner_started = perf_counter()
        model_name, model_source, openai_api_key_present = self._resolve_planner_model_config()
        return {
            "planner_provider": "openai_stepwise" if openai_api_key_present else "openai_stepwise_unavailable",
            "planner_model": model_name,
            "investigation_model": model_name,
            "model_source": model_source,
            "openai_api_key_present": openai_api_key_present,
            "planner_elapsed_ms": int((perf_counter() - planner_started) * 1000),
            "planner_steps_count": 0,
            "fallback_used": False,
            "fallback_reason": "",
            "notes": [] if openai_api_key_present else ["AI stepwise planner is unavailable (OPENAI_API_KEY missing)."],
            "fallback_queue": [],
            "plan_type": str(profile.get("plan_type") or "unknown"),
        }

    def _next_decision(
        self,
        *,
        problem_statement: str,
        step_no: int,
        max_steps: int,
        required_evidence: dict[str, bool],
        executed_steps: list[InvestigationStep],
        prior_step_results: list[dict[str, Any]],
        failed_sql_attempts: list[dict[str, Any]],
        findings: list[str],
        runtime_meta: dict[str, Any],
        compact_context: dict[str, Any],
        history_context: dict[str, Any],
        active_thread_memory: dict[str, Any],
    ) -> tuple[InvestigationStepDecision, str]:
        fallback_queue = runtime_meta.get("fallback_queue") if isinstance(runtime_meta.get("fallback_queue"), list) else []
        if fallback_queue:
            item = fallback_queue.pop(0)
            runtime_meta["fallback_queue"] = fallback_queue
            sql = str((item or {}).get("sql") or "").strip()
            goal = str((item or {}).get("goal") or f"Step {step_no} investigation").strip()
            if sql:
                return InvestigationStepDecision(
                    analysis="Fallback step executed because AI stepwise planner was unavailable.",
                    next_action="run_sql",
                    sql=sql,
                    goal=goal,
                    confidence=0.35,
                    required_evidence_status=dict(required_evidence),
                ), ""
            return InvestigationStepDecision(
                analysis="Fallback plan contained an empty SQL statement; concluding.",
                next_action="conclude",
                goal=goal,
                confidence=0.2,
                final_answer="Fallback plan did not contain executable SQL for this request.",
                required_evidence_status=dict(required_evidence),
            ), ""

        if runtime_meta.get("fallback_used"):
            return InvestigationStepDecision(
                analysis="Fallback queue consumed; concluding investigation.",
                next_action="conclude",
                goal="Finalize fallback investigation",
                confidence=0.3,
                final_answer="Investigation finished using fallback SQL steps.",
                required_evidence_status=dict(required_evidence),
            ), ""

        if self._all_required_evidence_satisfied(required_evidence):
            return InvestigationStepDecision(
                analysis="Required evidence checklist is complete; conclude.",
                next_action="conclude",
                goal="Finalize investigation",
                confidence=0.8,
                final_answer="Required evidence was collected for this question.",
                required_evidence_status=dict(required_evidence),
            ), ""

        decision, planner_failure_reason = self._request_next_step_decision(
            problem_statement=problem_statement,
            step_no=step_no,
            max_steps=max_steps,
            required_evidence=required_evidence,
            executed_steps=executed_steps,
            prior_step_results=prior_step_results,
            failed_sql_attempts=failed_sql_attempts,
            findings=findings,
            compact_context=compact_context,
            history_context=history_context,
            active_thread_memory=active_thread_memory,
        )
        if planner_failure_reason:
            should_force_replan = self._should_force_inventory_replan(
                problem_statement=problem_statement,
                active_thread_memory=active_thread_memory,
            ) and self._planner_failure_requires_inventory_replan(planner_failure_reason)
            if should_force_replan:
                forced_decision, forced_failure = self._request_forced_inventory_replan(
                    problem_statement=problem_statement,
                    step_no=step_no,
                    max_steps=max_steps,
                    required_evidence=required_evidence,
                    executed_steps=executed_steps,
                    prior_step_results=prior_step_results,
                    failed_sql_attempts=failed_sql_attempts,
                    findings=findings,
                    compact_context=compact_context,
                    history_context=history_context,
                    active_thread_memory=active_thread_memory,
                )
                if forced_decision is not None:
                    forced_decision.analysis = (
                        f"Initial planner failed with {planner_failure_reason}; "
                        "forced replan used because the request is a clear read-only inventory request. "
                        + str(forced_decision.analysis or "")
                    ).strip()
                    return forced_decision, ""
                combined_failure = str(forced_failure or planner_failure_reason).strip() or "planner_json_parse_failed"
                forced_replan_attempted = True
                json_repair_attempted = planner_failure_reason in {"planner_json_parse_failed", "planner_model_validation_failed"}
                return (
                    InvestigationStepDecision(
                        analysis=(
                            f"Planner failed with {planner_failure_reason}; "
                            f"forced inventory replan also failed with {str(forced_failure or 'unknown').strip() or 'unknown'}. "
                            f"forced_replan_attempted={str(forced_replan_attempted).lower()} "
                            f"json_repair_attempted={str(json_repair_attempted).lower()} "
                            "No SQL was executed."
                        ),
                        next_action="clarify",
                        goal="Planner failure",
                        confidence=0.15,
                        clarification_question=(
                            "The planner failed to produce valid JSON/SQL for a clear read-only request. "
                            "Please retry or check planner model configuration."
                        ),
                        required_evidence_status=dict(required_evidence),
                    ),
                    combined_failure,
                )
            return (
                InvestigationStepDecision(
                    analysis=(
                        (
                            "Planner returned invalid JSON and recovery attempts failed. "
                            "forced_replan_attempted=false json_repair_attempted=true No SQL was executed."
                        )
                        if planner_failure_reason == "planner_json_parse_failed"
                        else f"Stepwise planner failed with {planner_failure_reason}."
                    ),
                    next_action="clarify",
                    goal="Planner failure",
                    confidence=0.2,
                    clarification_question="Planner failed before producing a safe SQL step.",
                    required_evidence_status=dict(required_evidence),
                ),
                planner_failure_reason,
            )

        if decision is not None and decision.next_action == "clarify" and self._should_force_inventory_replan(
            problem_statement=problem_statement,
            active_thread_memory=active_thread_memory,
        ):
            forced_decision, forced_failure = self._request_forced_inventory_replan(
                problem_statement=problem_statement,
                step_no=step_no,
                max_steps=max_steps,
                required_evidence=required_evidence,
                executed_steps=executed_steps,
                prior_step_results=prior_step_results,
                failed_sql_attempts=failed_sql_attempts,
                findings=findings,
                compact_context=compact_context,
                history_context=history_context,
                active_thread_memory=active_thread_memory,
            )
            if forced_decision is not None:
                forced_decision.analysis = (
                    "Clarification was rejected because the request is clear read-only inventory. "
                    + str(forced_decision.analysis or "")
                ).strip()
                return forced_decision, ""
            if forced_failure:
                return (
                    InvestigationStepDecision(
                        analysis=f"Forced inventory replan failed with {forced_failure}.",
                        next_action="clarify",
                        goal="Forced inventory replan failed",
                        confidence=0.2,
                        clarification_question="Planner failed before producing a safe SQL step.",
                        required_evidence_status=dict(required_evidence),
                    ),
                    forced_failure,
                )
            return (
                InvestigationStepDecision(
                    analysis=(
                        "Planner requested clarification for a clear read-only inventory request, "
                        "and forced inventory replan did not return a SQL step."
                    ),
                    next_action="clarify",
                    goal="Forced inventory replan failed",
                    confidence=0.15,
                    clarification_question=(
                        "The planner failed to produce valid JSON/SQL for a clear read-only request. "
                        "Please retry or check planner model configuration."
                    ),
                    required_evidence_status=dict(required_evidence),
                ),
                "planner_returned_clarify",
            )

        if decision is not None:
            return decision, ""

        return (
            InvestigationStepDecision(
                analysis="Stepwise planner request failed before producing a valid decision.",
                next_action="clarify",
                goal="Planner failure",
                confidence=0.2,
                clarification_question="Planner failed before producing a safe SQL step.",
                required_evidence_status=dict(required_evidence),
            ),
            "planner_failed",
        )

    def _next_step_decision(
        self,
        *,
        problem_statement: str,
        step_no: int,
        max_steps: int,
        required_evidence: dict[str, bool],
        executed_steps: list[InvestigationStep],
        prior_step_results: list[dict[str, Any]],
        failed_sql_attempts: list[dict[str, Any]],
        findings: list[str],
        runtime_meta: dict[str, Any],
        history_context: dict[str, Any],
        active_thread_memory: dict[str, Any],
        compact_context: dict[str, Any],
    ) -> tuple[InvestigationStepDecision, str]:
        return self._next_decision(
            problem_statement=problem_statement,
            step_no=step_no,
            max_steps=max_steps,
            required_evidence=required_evidence,
            executed_steps=executed_steps,
            prior_step_results=prior_step_results,
            failed_sql_attempts=failed_sql_attempts,
            findings=findings,
            runtime_meta=runtime_meta,
            compact_context=compact_context if isinstance(compact_context, dict) else {"historical_context": history_context},
            history_context=history_context,
            active_thread_memory=active_thread_memory,
        )

    def _request_next_step_decision(
        self,
        *,
        problem_statement: str,
        step_no: int,
        max_steps: int,
        required_evidence: dict[str, bool],
        executed_steps: list[InvestigationStep],
        prior_step_results: list[dict[str, Any]],
        failed_sql_attempts: list[dict[str, Any]],
        findings: list[str],
        compact_context: dict[str, Any],
        history_context: dict[str, Any],
        active_thread_memory: dict[str, Any],
    ) -> tuple[InvestigationStepDecision | None, str]:
        evidence_status = [{"name": key, "satisfied": bool(value)} for key, value in required_evidence.items()]
        compact_steps = [
            {
                "step_no": step.step_number,
                "goal": step.goal,
                "status": step.status,
                "row_count": int(step.row_count or 0),
                "sql": step.sql,
                "result_preview": step.result_preview,
                "columns": list(step.result_columns or []),
                "rows": list(step.result_rows[: self.row_preview_limit]),
            }
            for step in executed_steps[-6:]
        ]

        discovered = self._extract_discovered_entities(prior_step_results=prior_step_results, executed_steps=executed_steps)
        payload = {
            "investigation_id": "",
            "original_question": problem_statement,
            "step_no": step_no,
            "max_steps": max_steps,
            "remaining_steps": max(max_steps - step_no + 1, 0),
            "required_evidence_status": evidence_status,
            "required_evidence": dict(required_evidence),
            "executed_sqls": [item.get("sql") for item in compact_steps if item.get("sql")],
            "failed_sql_attempts": failed_sql_attempts[-8:],
            "findings": findings[-10:],
            "step_summaries": findings[-10:],
            "prior_step_results": prior_step_results[-6:],
            "executed_step_summaries": compact_steps,
            "recent_read_only_context": compact_context,
            "history_context": history_context,
            "historical_context": history_context,
            "active_investigation_memory": active_thread_memory,
            "oracle_dictionary_guidance": self._oracle_dictionary_guidance(problem_statement),
            "discovered_objects": discovered.get("objects"),
            "discovered_sql_ids": discovered.get("sql_ids"),
            "discovered_sessions": discovered.get("sessions"),
            "stop_guidance": {
                "conclude_when_confident": True,
                "ask_clarification_if_ambiguous": True,
                "avoid_repeated_sql": True,
                "remaining_steps": max(max_steps - step_no + 1, 0),
                "do_not_conclude_if_required_evidence_missing": True,
                "zero_rows_can_be_incomplete": True,
            },
            "instruction": "When prior step results identify owner/object/table values, reuse those exact values in subsequent SQL.",
        }

        if self.ai_service is not None and hasattr(self.ai_service, "create_investigation_decision"):
            try:
                raw = self.ai_service.create_investigation_decision(
                    user_question=problem_statement,
                    investigation_context=payload,
                )
                if isinstance(raw, InvestigationStepDecision):
                    return raw, ""
                if isinstance(raw, dict):
                    parsed = self._normalize_planner_payload_aliases(raw)
                    return InvestigationStepDecision.model_validate(parsed), ""
                return None, "planner_model_validation_failed"
            except Exception:
                return None, "planner_failed"

        model_name, _model_source, _openai_api_key_present = self._resolve_planner_model_config()
        timeout_sec = int(str(os.getenv("ODB_AUTODBA_INVESTIGATION_PLANNER_TIMEOUT_SEC") or "30").strip() or "30")
        openai_api_key = str(os.getenv("OPENAI_API_KEY") or "").strip()
        if not openai_api_key:
            return None, "planner_failed"

        return self._call_openai_planner_for_step_decision(
            model_name=model_name,
            timeout_sec=timeout_sec,
            openai_api_key=openai_api_key,
            payload=payload,
            force_inventory_replan=False,
        )

    def _request_forced_inventory_replan(
        self,
        *,
        problem_statement: str,
        step_no: int,
        max_steps: int,
        required_evidence: dict[str, bool],
        executed_steps: list[InvestigationStep],
        prior_step_results: list[dict[str, Any]],
        failed_sql_attempts: list[dict[str, Any]],
        findings: list[str],
        compact_context: dict[str, Any],
        history_context: dict[str, Any],
        active_thread_memory: dict[str, Any],
    ) -> tuple[InvestigationStepDecision | None, str]:
        model_name, _model_source, _openai_api_key_present = self._resolve_planner_model_config()
        timeout_sec = int(str(os.getenv("ODB_AUTODBA_INVESTIGATION_PLANNER_TIMEOUT_SEC") or "30").strip() or "30")
        openai_api_key = str(os.getenv("OPENAI_API_KEY") or "").strip()
        if not openai_api_key:
            return None, "planner_failed"

        evidence_status = [{"name": key, "satisfied": bool(value)} for key, value in required_evidence.items()]
        compact_steps = [
            {
                "step_no": step.step_number,
                "goal": step.goal,
                "status": step.status,
                "row_count": int(step.row_count or 0),
                "sql": step.sql,
                "result_preview": step.result_preview,
                "columns": list(step.result_columns or []),
                "rows": list(step.result_rows[: self.row_preview_limit]),
            }
            for step in executed_steps[-6:]
        ]

        payload = {
            "original_question": problem_statement,
            "step_no": step_no,
            "max_steps": max_steps,
            "remaining_steps": max(max_steps - step_no + 1, 0),
            "required_evidence_status": evidence_status,
            "executed_sqls": [item.get("sql") for item in compact_steps if item.get("sql")],
            "failed_sql_attempts": failed_sql_attempts[-8:],
            "findings": findings[-10:],
            "prior_step_results": prior_step_results[-6:],
            "executed_step_summaries": compact_steps,
            "recent_read_only_context": compact_context,
            "history_context": {},
            "active_investigation_memory": {},
            "instruction": (
                "The user request is clear, safe, and read-only. Do not ask clarification. "
                "Generate exactly one safe SELECT/WITH SQL step. "
                "Prefer DBA_* for database-wide inventory when privilege exists; fallback conceptually to ALL_* then USER_*. "
                "If USER_* scope is used, disclose current-schema-only scope."
            ),
        }
        return self._call_openai_planner_for_step_decision(
            model_name=model_name,
            timeout_sec=timeout_sec,
            openai_api_key=openai_api_key,
            payload=payload,
            force_inventory_replan=True,
        )

    def _call_openai_planner_for_step_decision(
        self,
        *,
        model_name: str,
        timeout_sec: int,
        openai_api_key: str,
        payload: dict[str, Any],
        force_inventory_replan: bool,
    ) -> tuple[InvestigationStepDecision | None, str]:
        if force_inventory_replan:
            system_content = (
                "You are an Oracle DBA investigation planner. "
                "The user request is clear, safe, and read-only. Do not ask clarification. "
                "Return exactly one valid JSON object and no prose. "
                "Generate exactly one safe run_sql decision with one SELECT/WITH statement. "
                "Prefer DBA_* for database-wide inventory when privilege exists; fallback conceptually to ALL_* then USER_*. "
                "If USER_* scope is used, disclose current-schema-only scope. "
                "For table creation date use *_OBJECTS.CREATED. "
                "For table size use *_SEGMENTS bytes. "
                "Qualify all joined columns with aliases to avoid ORA-00918. "
                "Exclude Oracle-maintained/internal schemas unless explicitly requested. "
                "For RAC live session queries, prefer GV$ where applicable. "
                "No DDL/DML/PLSQL. "
                "Return strict JSON with keys: analysis, next_action, sql, goal, hypothesis, is_final, confidence, required_evidence_status, clarification_question, final_answer, recommended_actions.\n\n"
                + self._oracle_dictionary_guidance()
            )
        else:
            system_content = (
                "You are an Oracle DBA investigation planner working step-by-step. "
                "Never plan a full batch of SQL. Decide only the next best action. "
                "Allowed next_action values: run_sql, conclude, clarify. "
                "For run_sql, output exactly one read-only Oracle SELECT/WITH statement. "
                "Do not output DDL/DML/PLSQL. "
                "Use evidence-driven chaining and reuse known owner/object values from prior results. "
                "Treat zero-row results as a signal, not immediate failure, when fallback lookups exist. "
                "Interpret broad DBA inventory requests generically (not hardcoded): "
                "database-wide wording should prefer DBA_* views, fallback ALL_* then USER_* on privilege errors, "
                "and if USER_* is used you must label scope as current schema only. "
                "For inventory and size requests, prioritize application/user objects first and avoid Oracle-maintained/internal schemas unless explicitly requested. "
                "For huge-table requests, rank by segment size descending and state whether table segment only or total footprint including indexes/LOBs. "
                "Return strict JSON with keys: analysis, next_action, sql, goal, hypothesis, is_final, confidence, required_evidence_status, clarification_question, final_answer, recommended_actions.\n\n"
                + self._oracle_dictionary_guidance()
            )
        try:
            from openai import OpenAI

            client = OpenAI(api_key=openai_api_key, timeout=max(timeout_sec, 1))
            completion = client.chat.completions.create(
                model=model_name,
                temperature=0.0,
                messages=[
                    {
                        "role": "system",
                        "content": system_content,
                    },
                    {
                        "role": "user",
                        "content": json.dumps(payload, ensure_ascii=True),
                    },
                ],
                response_format={"type": "json_object"},
            )
            content = str((completion.choices[0].message.content if completion.choices else "") or "").strip()
        except Exception:
            return None, "planner_failed"

        original_question = str(payload.get("original_question") or "").strip()
        decision, failure_reason = self._parse_planner_decision_content(
            content=content,
            original_question=original_question,
            force_inventory_replan=force_inventory_replan,
        )
        if decision is None and failure_reason in {"planner_json_parse_failed", "planner_model_validation_failed"}:
            LOGGER.warning(
                "planner_json_parse_failed=true parse_error_type=%s raw_response_len=%s raw_response_preview_hash=%s",
                str(failure_reason),
                len(content),
                hashlib.sha256(str(content[:512]).encode("utf-8")).hexdigest()[:16] if content else "",
            )
            repaired = self._request_planner_json_repair(
                model_name=model_name,
                timeout_sec=timeout_sec,
                openai_api_key=openai_api_key,
                payload=payload,
                invalid_response=content,
            )
            if repaired:
                decision, failure_reason = self._parse_planner_decision_content(
                    content=repaired,
                    original_question=original_question,
                    force_inventory_replan=force_inventory_replan,
                )
            if decision is None and self._can_salvage_plain_sql(
                content=content,
                original_question=original_question,
                force_inventory_replan=force_inventory_replan,
            ):
                decision = self._wrap_plain_sql_as_decision(content, original_question=original_question)
                failure_reason = ""
            if decision is None and repaired and self._can_salvage_plain_sql(
                content=repaired,
                original_question=original_question,
                force_inventory_replan=force_inventory_replan,
            ):
                decision = self._wrap_plain_sql_as_decision(repaired, original_question=original_question)
                failure_reason = ""
            if decision is None:
                return None, "planner_json_parse_failed"

        if decision is None:
            return None, str(failure_reason or "planner_failed")

        if decision.next_action == "run_sql" and str(decision.sql or "").strip() == "":
            return None, "planner_returned_empty_sql"
        if force_inventory_replan and decision.next_action != "run_sql":
            return None, "planner_failed"
        return decision, ""

    def _request_planner_json_repair(
        self,
        *,
        model_name: str,
        timeout_sec: int,
        openai_api_key: str,
        payload: dict[str, Any],
        invalid_response: str,
    ) -> str:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=openai_api_key, timeout=max(timeout_sec, 1))
            completion = client.chat.completions.create(
                model=model_name,
                temperature=0.0,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You repair invalid planner JSON for Oracle DBA investigation. "
                            "Return only one valid JSON object. No markdown. No prose."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "original_question": str(payload.get("original_question") or ""),
                                "invalid_planner_response": str(invalid_response or ""),
                                "expected_schema": {
                                    "analysis": "brief reasoning",
                                    "next_action": "run_sql",
                                    "goal": "what SQL will prove",
                                    "sql": "SELECT ...",
                                    "hypothesis": "",
                                    "is_final": False,
                                    "confidence": 0.7,
                                    "required_evidence_status": {},
                                    "clarification_question": "",
                                    "final_answer": "",
                                    "recommended_actions": [],
                                },
                                "allowed_next_action_values": ["run_sql", "conclude", "clarify"],
                                "constraints": [
                                    "read-only SQL only",
                                    "if next_action=run_sql, SQL must start with SELECT or WITH",
                                    "no DDL/DML/PLSQL",
                                ],
                            },
                            ensure_ascii=True,
                        ),
                    },
                ],
                response_format={"type": "json_object"},
            )
            return str((completion.choices[0].message.content if completion.choices else "") or "").strip()
        except Exception:
            return ""

    def _parse_planner_decision_content(
        self,
        *,
        content: str,
        original_question: str,
        force_inventory_replan: bool,
    ) -> tuple[InvestigationStepDecision | None, str]:
        parsed, parse_error_type = self._parse_planner_json_detailed(content)
        if not parsed:
            if self._can_salvage_plain_sql(
                content=content,
                original_question=original_question,
                force_inventory_replan=force_inventory_replan,
            ):
                wrapped = self._wrap_plain_sql_as_decision(content, original_question=original_question)
                if wrapped is not None:
                    return wrapped, ""
            return None, parse_error_type or "planner_json_parse_failed"
        try:
            normalized = self._normalize_planner_payload_aliases(parsed)
            return InvestigationStepDecision.model_validate(normalized), ""
        except Exception:
            return None, "planner_model_validation_failed"

    def _normalize_planner_payload_aliases(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = dict(payload or {})
        if not str(normalized.get("next_action") or "").strip():
            action = str(normalized.get("action") or "").strip()
            if action:
                normalized["next_action"] = action
        if not str(normalized.get("sql") or "").strip():
            for key in ("query", "statement", "sql_text", "next_sql"):
                candidate = str(normalized.get(key) or "").strip()
                if candidate:
                    normalized["sql"] = candidate
                    break
        if not str(normalized.get("analysis") or "").strip():
            for key in ("reason", "thought", "rationale"):
                candidate = str(normalized.get(key) or "").strip()
                if candidate:
                    normalized["analysis"] = candidate
                    break
        if not str(normalized.get("goal") or "").strip():
            for key in ("objective", "description"):
                candidate = str(normalized.get(key) or "").strip()
                if candidate:
                    normalized["goal"] = candidate
                    break
        if not str(normalized.get("final_answer") or "").strip():
            candidate = str(normalized.get("answer") or "").strip()
            if candidate:
                normalized["final_answer"] = candidate
        return normalized

    def _parse_planner_json_detailed(self, content: str) -> tuple[dict[str, Any], str]:
        text = str(content or "").strip()
        if not text:
            return {}, "planner_json_parse_failed"

        candidates: list[str] = []
        candidates.append(text)
        candidates.extend(re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", text, flags=re.IGNORECASE))

        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            candidates.append(text[start : end + 1])

        seen: set[str] = set()
        for raw_candidate in candidates:
            candidate = str(raw_candidate or "").strip()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            for attempt in (candidate, self._strip_trailing_json_commas(candidate)):
                try:
                    parsed = json.loads(attempt)
                except Exception:
                    continue
                if isinstance(parsed, dict):
                    return parsed, ""
        return {}, "planner_json_parse_failed"

    def _strip_trailing_json_commas(self, value: str) -> str:
        return re.sub(r",(\s*[}\]])", r"\1", str(value or ""))

    def _extract_sql_text_candidate(self, content: str) -> str:
        text = str(content or "").strip()
        if not text:
            return ""
        fenced_sql = re.findall(r"```(?:sql)?\s*([\s\S]*?)\s*```", text, flags=re.IGNORECASE)
        if fenced_sql:
            text = str(fenced_sql[0] or "").strip()
        normalized = text.strip().strip("`").strip()
        if not normalized:
            return ""
        if re.match(r"^(select|with)\b", normalized, flags=re.IGNORECASE):
            return normalized
        first = normalized.find("select")
        with_idx = normalized.find("with")
        idx_candidates = [idx for idx in (first, with_idx) if idx >= 0]
        if not idx_candidates:
            return ""
        idx = min(idx_candidates)
        possible_sql = normalized[idx:].strip()
        if re.match(r"^(select|with)\b", possible_sql, flags=re.IGNORECASE):
            return possible_sql
        return ""

    def _can_salvage_plain_sql(self, *, content: str, original_question: str, force_inventory_replan: bool) -> bool:
        sql_candidate = self._extract_sql_text_candidate(content)
        if not sql_candidate:
            return False
        if not (force_inventory_replan or self._is_clear_read_only_inventory_request(original_question)):
            return False
        validation = self.sql_validator(sql_candidate)
        return bool(validation.ok)

    def _wrap_plain_sql_as_decision(self, content: str, *, original_question: str) -> InvestigationStepDecision | None:
        sql_candidate = self._extract_sql_text_candidate(content)
        if not sql_candidate:
            return None
        validation = self.sql_validator(sql_candidate)
        if not validation.ok:
            return None
        normalized_sql = str(validation.normalized_sql or sql_candidate).strip()
        return InvestigationStepDecision(
            analysis="Planner returned plain SQL; wrapped into run_sql decision.",
            next_action="run_sql",
            goal="Answer the read-only investigation request.",
            sql=normalized_sql,
            confidence=0.5,
            required_evidence_status={},
        )

    def _planner_failure_requires_inventory_replan(self, planner_failure_reason: str) -> bool:
        reason = str(planner_failure_reason or "").strip().lower()
        return reason in {
            "planner_json_parse_failed",
            "planner_model_validation_failed",
            "planner_returned_empty_sql",
            "planner_returned_clarify",
            "planner_failed",
        }

    def _plan_steps(self, *, problem_statement: str, max_steps: int) -> dict[str, Any]:
        planner_started = perf_counter()
        if self._is_performance_diagnostic_request(problem_statement):
            return {
                "plan_type": "diagnostic",
                "steps": self._diagnostic_fallback_steps()[:max_steps],
                "planner_provider": "deterministic_fallback",
                "planner_model": "deterministic",
                "planner_elapsed_ms": int((perf_counter() - planner_started) * 1000),
                "planner_steps_count": min(max_steps, len(self._diagnostic_fallback_steps())),
                "fallback_used": True,
                "fallback_reason": "planner_error",
                "notes": ["AI stepwise planner unavailable; fallback diagnostic plan used."],
            }

        if extract_sql_id(problem_statement):
            sql_id = str(extract_sql_id(problem_statement) or "").lower()
            return {
                "plan_type": "inventory_read_only_lookup",
                "steps": [
                    {
                        "goal": "Check SQL_ID in live cursor cache",
                        "sql": f"select sql_id, parsing_schema_name, module, elapsed_time, cpu_time from v$sql where sql_id = '{sql_id}' fetch first 5 rows only",
                    },
                    {
                        "goal": "Inspect SQL_ID objects from plan history",
                        "sql": f"select distinct object_owner, object_name, object_type from dba_hist_sql_plan where sql_id = '{sql_id}' and object_owner is not null and object_name is not null fetch first 20 rows only",
                    },
                ][:max_steps],
                "planner_provider": "deterministic_fallback",
                "planner_model": "deterministic",
                "planner_elapsed_ms": int((perf_counter() - planner_started) * 1000),
                "planner_steps_count": min(max_steps, 2),
                "fallback_used": True,
                "fallback_reason": "planner_error",
                "notes": ["AI stepwise planner unavailable; fallback SQL_ID lookup path used."],
            }

        if self._is_database_size_question(problem_statement):
            return {
                "plan_type": "inventory_read_only_lookup",
                "steps": [
                    {
                        "goal": "Fetch database size",
                        "sql": "select round(sum(bytes)/1024/1024/1024,2) as total_gb from dba_data_files",
                    }
                ][:max_steps],
                "planner_provider": "deterministic_fallback",
                "planner_model": "deterministic",
                "planner_elapsed_ms": int((perf_counter() - planner_started) * 1000),
                "planner_steps_count": 1,
                "fallback_used": True,
                "fallback_reason": "planner_error",
                "notes": ["AI stepwise planner unavailable; fallback lookup used."],
            }

        return {
            "plan_type": "inventory_read_only_lookup",
            "steps": [],
            "planner_provider": "deterministic_fallback",
            "planner_model": "deterministic",
            "planner_elapsed_ms": int((perf_counter() - planner_started) * 1000),
            "planner_steps_count": 0,
            "fallback_used": True,
            "fallback_reason": "planner_error",
            "notes": ["AI planner could not generate safe SQL for this request."],
        }

    def _diagnostic_fallback_steps(self) -> list[dict[str, str]]:
        return [
            {
                "goal": "Inspect active sessions",
                "sql": "select inst_id, sid, serial#, username, status, sql_id, event, wait_class, module, program, machine from gv$session where status = 'ACTIVE' and username is not null fetch first 20 rows only",
            },
            {
                "goal": "Inspect top SQL by CPU",
                "sql": "select sql_id, plan_hash_value, round(cpu_time/1e6,3) cpu_s, round(elapsed_time/1e6,3) elapsed_s, executions from gv$sqlstats order by cpu_time desc fetch first 10 rows only",
            },
        ]

    def _sql_max_attempts(self) -> int:
        configured_total = max(1, int(self.max_sql_retries_per_step) + 1)
        raw = str(
            os.getenv("ODB_AUTODBA_INVESTIGATION_MAX_SQL_ATTEMPTS")
            or os.getenv("ODB_AUTODBA_INVESTIGATION_SQL_MAX_ATTEMPTS")  # legacy alias
            or configured_total
        ).strip()
        try:
            attempts = max(1, int(raw))
        except Exception:
            attempts = configured_total
        return min(attempts, self.DEFAULT_SQL_MAX_ATTEMPTS)

    def _sql_execution_cap(self, *, diagnostic_mode: bool) -> int:
        default_cap = self.DEFAULT_DIAGNOSTIC_SQL_EXECUTION_CAP if diagnostic_mode else self.DEFAULT_SQL_EXECUTION_CAP
        raw = str(os.getenv("ODB_AUTODBA_INVESTIGATION_SQL_EXECUTION_CAP") or default_cap).strip()
        try:
            cap = max(1, int(raw))
        except Exception:
            cap = default_cap
        hard_default = self.DEFAULT_DIAGNOSTIC_SQL_EXECUTION_CAP if diagnostic_mode else self.DEFAULT_SQL_EXECUTION_CAP
        return min(cap, hard_default)

    def _is_recoverable_validation_error(self, message: str) -> bool:
        text = str(message or "").strip().lower()
        if not text:
            return False
        return any(
            marker in text
            for marker in (
                "single statement",
                "must start with select",
                "not allowed in investigation sql",
                "sql is required",
                "dictionary lint",
            )
        )

    def _is_recoverable_execution_error(self, message: str) -> bool:
        text = str(message or "").strip().lower()
        if not text:
            return False
        terminal_markers = (
            "ora-01017",
            "ora-01034",
            "ora-01089",
            "ora-12154",
            "ora-12170",
            "ora-12203",
            "ora-12514",
            "ora-12541",
            "ora-12545",
            "ora-03113",
            "ora-03114",
            "ora-03135",
            "dpi-1010",
            "dpi-1080",
            "connection",
            "network",
            "authentication",
        )
        if any(marker in text for marker in terminal_markers):
            return False
        recoverable_codes = {
            "ora-00904",
            "ora-00942",
            "ora-00918",
            "ora-00933",
            "ora-00936",
            "ora-00907",
            "ora-00979",
            "ora-01722",
            "ora-00937",
            "ora-01427",
            "ora-01031",
        }
        return any(code in text for code in recoverable_codes)

    def _repair_sql_decision(
        self,
        *,
        problem_statement: str,
        goal: str,
        failed_sql: str,
        error_message: str,
        prior_failed_sqls: list[str],
        executed_sqls: list[str],
        findings: list[str],
        step_summaries: list[str],
        prior_step_results: list[dict[str, Any]],
        attempt_number: int,
        max_attempts: int,
        trace_ctx: dict[str, Any],
        step_number: int,
    ) -> dict[str, str] | None:
        repaired = self._request_sql_correction(
            problem_statement=problem_statement,
            goal=goal,
            failed_sql=failed_sql,
            error_message=error_message,
            attempted_sqls=prior_failed_sqls,
            executed_sqls=executed_sqls,
            findings=findings,
            step_summaries=step_summaries,
            prior_step_results=prior_step_results,
            attempt_number=attempt_number,
            max_attempts=max_attempts,
        )
        LOGGER.info(
            "investigation_sql_repair id=%s step_no=%s correction_attempt=%s correction_requested=true correction_sql_validated=%s",
            trace_ctx["investigation_id"],
            step_number,
            attempt_number,
            str(bool(repaired and str(repaired.get("sql") or "").strip())).lower(),
        )
        if repaired:
            self._append_trace_event(
                trace_ctx,
                "investigation.sql_repair",
                {
                    "step_no": step_number,
                    "attempt_no": attempt_number,
                    "failed_sql": failed_sql,
                    "error": error_message,
                    "repaired_sql": str(repaired.get("sql") or ""),
                    "repair_reason": str(repaired.get("reason") or ""),
                    "model_used": str(os.getenv("ODB_AUTODBA_INVESTIGATION_PLANNER_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o-mini"),
                    "llm_role": "repair",
                    "prompt_type": "sql_repair",
                },
            )
        return repaired

    def _step_finding(self, *, goal: str, row_count: int, columns: list[str], corrected: bool, scope_note: str = "") -> str:
        cols = ", ".join(columns[:6]) if columns else "no columns"
        suffix = f" Scope: {scope_note}" if scope_note else ""
        if corrected:
            return f"{goal}: recovered via SQL repair and returned {row_count} row(s) ({cols}).{suffix}"
        return f"{goal}: returned {row_count} row(s) ({cols}).{suffix}"

    def _failed_step_finding(self, *, goal: str, error: str) -> str:
        return f"{goal}: failed after SQL attempts; last error: {error}"

    def _execute_step_sql_with_repairs(
        self,
        *,
        step_number: int,
        goal: str,
        initial_sql: str,
        problem_statement: str,
        db_key: str | None,
        max_attempts: int,
        trace_ctx: dict[str, Any],
        findings: list[str],
        prior_step_results: list[dict[str, Any]],
        remaining_sql_executions: int,
    ) -> tuple[InvestigationStep, list[str], int]:
        notes: list[str] = []
        attempts: list[InvestigationSQLAttemptRecord] = []
        prior_failed_sqls: list[str] = []
        executed_sqls: list[str] = []
        seen_sql_counts: dict[str, int] = {}
        current_sql = str(initial_sql or "").strip()
        last_error = "SQL execution failed."
        final_result = None
        executions_used = 0

        for attempt_number in range(1, max_attempts + 1):
            normalized_sql_key = " ".join(current_sql.split()).strip().lower()
            prior_count = seen_sql_counts.get(normalized_sql_key, 0) if normalized_sql_key else 0
            if normalized_sql_key and prior_count >= 2:
                duplicate_error = "Repeated SQL attempt detected; stopping step to avoid loop."
                attempt = InvestigationSQLAttemptRecord(
                    attempt_no=attempt_number,
                    attempt=attempt_number,
                    sql=current_sql,
                    repaired=attempt_number > 1,
                    validation_ok=False,
                    execution_status="validation_error",
                    status="validation_error",
                    recoverable=True,
                    error=duplicate_error,
                    error_code="duplicate_sql",
                )
                attempts.append(attempt)
                self._append_sql_attempt_event(trace_ctx, step_number=step_number, attempt=attempt, llm_role="executor", prompt_type="repeat_guard")
                last_error = duplicate_error
                notes.append(f"Step {step_number} stopped due to repeated SQL attempt.")
                if attempt_number >= max_attempts:
                    notes.append(f"Step {step_number} attempts exhausted after {max_attempts} SQL attempt(s).")
                break
            if normalized_sql_key:
                seen_sql_counts[normalized_sql_key] = prior_count + 1

            lint = self._dictionary_lint(sql=current_sql, goal=goal)
            if lint.get("fatal"):
                validation_error = f"dictionary lint: {lint.get('message')}"
                recoverable = True
                attempt = InvestigationSQLAttemptRecord(
                    attempt_no=attempt_number,
                    attempt=attempt_number,
                    sql=current_sql,
                    repaired=attempt_number > 1,
                    validation_ok=False,
                    execution_status="validation_error",
                    status="validation_error",
                    recoverable=recoverable,
                    error=validation_error,
                    error_code="dictionary_lint_failed",
                )
                attempts.append(attempt)
                self._append_sql_attempt_event(trace_ctx, step_number=step_number, attempt=attempt, llm_role="validator", prompt_type="dictionary_lint")
                last_error = validation_error
                if attempt_number >= max_attempts:
                    notes.append(f"Step {step_number} attempts exhausted after {max_attempts} SQL attempt(s).")
                    break
                repaired = self._repair_sql_decision(
                    problem_statement=problem_statement,
                    goal=goal,
                    failed_sql=current_sql,
                    error_message=validation_error,
                    prior_failed_sqls=prior_failed_sqls,
                    executed_sqls=executed_sqls,
                    findings=findings,
                    step_summaries=list(findings),
                    prior_step_results=prior_step_results,
                    attempt_number=attempt_number + 1,
                    max_attempts=max_attempts,
                    trace_ctx=trace_ctx,
                    step_number=step_number,
                )
                if not repaired:
                    break
                current_sql = repaired.get("sql") or current_sql
                attempt.repair_reason = str(repaired.get("reason") or "")
                continue
            if lint.get("warning"):
                notes.append(str(lint.get("warning")))

            validation = self.sql_validator(current_sql)
            LOGGER.info(
                "investigation_sql_validation id=%s step_no=%s attempt_no=%s validation_ok=%s",
                trace_ctx["investigation_id"],
                step_number,
                attempt_number,
                str(bool(validation.ok)).lower(),
            )
            if not validation.ok:
                validation_error = str(validation.reason or "SQL validation failed.")
                recoverable = self._is_recoverable_validation_error(validation_error)
                attempt = InvestigationSQLAttemptRecord(
                    attempt_no=attempt_number,
                    attempt=attempt_number,
                    sql=current_sql,
                    repaired=attempt_number > 1,
                    validation_ok=False,
                    execution_status="validation_error",
                    status="validation_error",
                    recoverable=recoverable,
                    error=validation_error,
                    error_code="validation_error",
                )
                attempts.append(attempt)
                self._append_sql_attempt_event(trace_ctx, step_number=step_number, attempt=attempt, llm_role="validator", prompt_type="validation")
                last_error = validation_error
                if not recoverable or attempt_number >= max_attempts:
                    break
                repaired = self._repair_sql_decision(
                    problem_statement=problem_statement,
                    goal=goal,
                    failed_sql=current_sql,
                    error_message=validation_error,
                    prior_failed_sqls=prior_failed_sqls,
                    executed_sqls=executed_sqls,
                    findings=findings,
                    step_summaries=list(findings),
                    prior_step_results=prior_step_results,
                    attempt_number=attempt_number + 1,
                    max_attempts=max_attempts,
                    trace_ctx=trace_ctx,
                    step_number=step_number,
                )
                if not repaired:
                    break
                current_sql = repaired.get("sql") or current_sql
                attempt.repair_reason = str(repaired.get("reason") or "")
                continue

            normalized_sql = validation.normalized_sql or current_sql
            executed_sqls.append(normalized_sql)
            if executions_used >= remaining_sql_executions:
                last_error = "SQL execution cap reached before this step could run further queries."
                notes.append(last_error)
                break

            LOGGER.info(
                "investigation_sql_execution id=%s step_no=%s attempt_no=%s",
                trace_ctx["investigation_id"],
                step_number,
                attempt_number,
            )
            result = self.sql_executor(normalized_sql, db_key=db_key)
            executions_used += 1
            final_result = result
            if result.status == "success":
                preview = f"Returned {result.row_count} row(s). Columns: {', '.join(result.columns[:8])}"
                attempt = InvestigationSQLAttemptRecord(
                    attempt_no=attempt_number,
                    attempt=attempt_number,
                    sql=normalized_sql,
                    repaired=attempt_number > 1,
                    validation_ok=True,
                    execution_status="success",
                    status="success",
                    recoverable=False,
                    error="",
                    error_code="",
                )
                attempts.append(attempt)
                self._append_sql_attempt_event(trace_ctx, step_number=step_number, attempt=attempt, llm_role="executor", prompt_type="execution")
                rows_preview = list(result.rows[: self.evidence_row_limit])
                correction_attempt_payload = [entry.model_dump(mode="json") for entry in attempts]
                previous_failed_attempts = [
                    item
                    for item in correction_attempt_payload
                    if str(item.get("execution_status") or item.get("status") or "").strip().lower() != "success"
                ]
                repair_used = bool(previous_failed_attempts)
                scope_note = self._scope_note_for_sql(problem_statement=problem_statement, sql=normalized_sql)
                finding = self._step_finding(
                    goal=goal,
                    row_count=result.row_count,
                    columns=list(result.columns or []),
                    corrected=attempt_number > 1,
                    scope_note=scope_note,
                )
                step = InvestigationStep(
                    step_number=step_number,
                    goal=goal,
                    sql=normalized_sql,
                    result_preview=preview,
                    row_count=result.row_count,
                    status="success",
                    result_columns=list(result.columns or []),
                    result_rows=rows_preview,
                    result_truncated=bool(result.truncated or (result.row_count > len(rows_preview))),
                    correction_attempts=attempts,
                    final_attempt_count=len(attempts),
                    finding=finding,
                    evidence_source="SQL",
                    historical_context_used=False,
                    investigation_mode="read_only_lookup",
                    confidence="MEDIUM",
                    inference_confidence="MEDIUM",
                    termination_reason="step_completed",
                )
                self._append_trace_event(
                    trace_ctx,
                    "investigation.step",
                    {
                        "step_number": step_number,
                        "step_no": step_number,
                        "goal": goal,
                        "sql": normalized_sql,
                        "final_sql": normalized_sql,
                        "status": "success",
                        "row_count": int(result.row_count or 0),
                        "columns": list(result.columns or []),
                        "rows": rows_preview,
                        "result_columns": list(result.columns or []),
                        "result_rows": rows_preview,
                        "result_truncated": bool(result.truncated or (result.row_count > len(rows_preview))),
                        "result_preview": preview,
                        "finding": finding,
                        "repair_used": repair_used,
                        "previous_failed_attempts": previous_failed_attempts,
                        "correction_attempts": correction_attempt_payload,
                        "final_attempt_count": len(attempts),
                        "attempt_count": len(attempts),
                    },
                )
                if len(attempts) > 1:
                    notes.append(f"Step {step_number} succeeded after {len(attempts)} SQL attempt(s).")
                return step, notes, executions_used

            raw_error = str(result.error or "SQL execution failed.")
            last_error = raw_error
            error_code = self._extract_oracle_error_code(raw_error)
            recoverable = self._is_recoverable_execution_error(raw_error)
            attempt = InvestigationSQLAttemptRecord(
                attempt_no=attempt_number,
                attempt=attempt_number,
                sql=normalized_sql,
                repaired=attempt_number > 1,
                validation_ok=True,
                execution_status="error",
                status="error",
                recoverable=recoverable,
                error=raw_error,
                error_code=error_code,
            )
            attempts.append(attempt)
            prior_failed_sqls.append(normalized_sql)
            self._append_sql_attempt_event(trace_ctx, step_number=step_number, attempt=attempt, llm_role="executor", prompt_type="execution")
            LOGGER.info(
                "investigation_sql_attempt=%s correction_attempt=%s sql_execution_status=error sql_error_code=%s correction_requested=%s max_attempts=%s final_attempt_count=%s",
                attempt_number,
                attempt_number,
                error_code,
                str(recoverable and attempt_number < max_attempts).lower(),
                max_attempts,
                len(attempts),
            )
            if not recoverable or attempt_number >= max_attempts:
                if attempt_number >= max_attempts:
                    notes.append(f"Step {step_number} attempts exhausted after {max_attempts} SQL attempt(s).")
                break
            repaired = self._repair_sql_decision(
                problem_statement=problem_statement,
                goal=goal,
                failed_sql=normalized_sql,
                error_message=raw_error,
                prior_failed_sqls=prior_failed_sqls,
                executed_sqls=executed_sqls,
                findings=findings,
                step_summaries=list(findings),
                prior_step_results=prior_step_results,
                attempt_number=attempt_number + 1,
                max_attempts=max_attempts,
                trace_ctx=trace_ctx,
                step_number=step_number,
            )
            if not repaired:
                notes.append(f"Step {step_number} SQL correction unavailable after attempt {attempt_number}.")
                break
            attempt.repair_reason = str(repaired.get("reason") or "")
            repaired_sql = str(repaired.get("sql") or "").strip()
            if self._repair_sql_still_contains_invalid_tokens(repaired_sql):
                notes.append(f"Step {step_number} repair attempt {attempt_number + 1} still had invalid placeholders/columns; retrying.")
                current_sql = repaired_sql
                continue
            if repaired_sql.lower() == normalized_sql.lower():
                notes.append(f"Step {step_number} repair attempt {attempt_number + 1} repeated the same SQL; stopping.")
                last_error = "Repeated SQL generated after repair."
                break
            current_sql = repaired_sql
            if not current_sql:
                break

        row_count = int(getattr(final_result, "row_count", 0) or 0) if final_result is not None else 0
        finding = self._failed_step_finding(goal=goal, error=last_error)
        step = InvestigationStep(
            step_number=step_number,
            goal=goal,
            sql=(attempts[-1].sql if attempts else current_sql),
            result_preview=last_error,
            row_count=row_count,
            status="error",
            correction_attempts=attempts,
            final_attempt_count=len(attempts) if attempts else 1,
            finding=finding,
            evidence_source="SQL",
            historical_context_used=False,
            investigation_mode="read_only_lookup",
            confidence="LOW",
            inference_confidence="LOW",
            termination_reason="step_failed",
        )
        self._append_trace_event(
            trace_ctx,
            "investigation.step",
            {
                "step_number": step_number,
                "step_no": step_number,
                "goal": goal,
                "sql": (attempts[-1].sql if attempts else current_sql),
                "final_sql": (attempts[-1].sql if attempts else current_sql),
                "status": "error",
                "row_count": row_count,
                "result_preview": last_error,
                "finding": finding,
                "repair_used": len(attempts) > 1,
                "previous_failed_attempts": [entry.model_dump(mode="json") for entry in attempts],
                "correction_attempts": [entry.model_dump(mode="json") for entry in attempts],
                "final_attempt_count": len(attempts),
                "attempt_count": len(attempts),
            },
        )
        return step, notes, executions_used

    def _repair_sql_still_contains_invalid_tokens(self, sql: str) -> bool:
        lowered = str(sql or "").lower()
        invalid_tokens = ("your_owner", "your_table", "<owner>", "<table", "<table_name>")
        if any(token in lowered for token in invalid_tokens):
            return True
        invalid_columns = (
            "v$session.object_id",
            "gv$session.object_id",
            "v$session.sql_text",
            "gv$session.sql_text",
        )
        return any(token in lowered for token in invalid_columns)

    def _request_sql_correction(
        self,
        *,
        problem_statement: str,
        goal: str,
        failed_sql: str,
        error_message: str,
        attempted_sqls: list[str],
        executed_sqls: list[str] | None = None,
        findings: list[str] | None = None,
        step_summaries: list[str] | None = None,
        prior_step_results: list[dict[str, Any]] | None = None,
        attempt_number: int,
        max_attempts: int,
    ) -> dict[str, str] | None:
        discovered = self._extract_discovered_entities(
            prior_step_results=prior_step_results or [],
            executed_steps=[],
        )
        compact_prior_results = []
        for item in (prior_step_results or [])[-6:]:
            if not isinstance(item, dict):
                continue
            compact_prior_results.append(
                {
                    "step_no": int(item.get("step_no") or 0),
                    "goal": str(item.get("goal") or ""),
                    "sql": str(item.get("sql") or ""),
                    "rowcount": int(item.get("rowcount") or 0),
                    "columns": list(item.get("columns") or []),
                    "result_preview": list(item.get("result_preview") or [])[: self.row_preview_limit],
                }
            )
        if self.ai_service is not None and hasattr(self.ai_service, "repair_investigation_sql"):
            try:
                raw = self.ai_service.repair_investigation_sql(
                    user_question=problem_statement,
                    investigation_context={
                        "mode": "repair_sql",
                        "goal": goal,
                        "failed_sql": failed_sql,
                        "oracle_error": error_message,
                        "prior_failed_sqls": attempted_sqls,
                        "executed_sqls": executed_sqls or [],
                        "findings": findings or [],
                        "step_summaries": step_summaries or [],
                        "prior_step_results": compact_prior_results,
                        "discovered_objects": discovered.get("objects"),
                        "discovered_sql_ids": discovered.get("sql_ids"),
                        "discovered_sessions": discovered.get("sessions"),
                        "attempt_number": attempt_number,
                        "max_attempts": max_attempts,
                        "repair_rules": {
                            "same_goal": True,
                            "return_one_select_only": True,
                            "do_not_repeat_failed_sql": True,
                            "do_not_conclude_from_failed_sql": True,
                        },
                    },
                    goal=goal,
                    failed_sql=failed_sql,
                    postgres_error=error_message,
                    prior_failed_sqls=attempted_sqls,
                )
                if isinstance(raw, InvestigationStepDecision):
                    return {"sql": str(raw.sql or "").strip(), "reason": str(raw.analysis or "").strip()}
                if isinstance(raw, dict):
                    repaired_sql = str(raw.get("repaired_sql") or raw.get("sql") or raw.get("query") or "").strip()
                    repair_reason = str(raw.get("repair_reason") or raw.get("reason") or "").strip()
                    if repaired_sql:
                        return {"sql": repaired_sql, "reason": repair_reason}
            except Exception:
                return None

        model_name, _model_source, _openai_api_key_present = self._resolve_planner_model_config()
        timeout_sec = int(str(os.getenv("ODB_AUTODBA_INVESTIGATION_PLANNER_TIMEOUT_SEC") or "30").strip() or "30")
        openai_api_key = str(os.getenv("OPENAI_API_KEY") or "").strip()
        if not openai_api_key:
            return None
        try:
            from openai import OpenAI

            client = OpenAI(api_key=openai_api_key, timeout=max(timeout_sec, 1))
            completion = client.chat.completions.create(
                model=model_name,
                temperature=0.0,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an Oracle SQL repair assistant for read-only investigations. "
                            "Repair the failed SQL using Oracle dictionary metadata knowledge. "
                            "Output strict JSON with keys repaired_sql and repair_reason. "
                            "Use SELECT/WITH statements only; no DDL/DML/PLSQL. "
                            "Do not invent dictionary columns. "
                            + self._oracle_dictionary_guidance()
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            "Database type: Oracle\n"
                            "Read-only requirement: SELECT/WITH only\n"
                            f"Original user question: {problem_statement}\n"
                            f"Current step goal: {goal}\n"
                            f"Attempt: {attempt_number} of {max_attempts}\n"
                            f"Failed SQL: {failed_sql}\n"
                            f"Oracle error or lint reason: {error_message}\n"
                            f"Previous attempts: {attempted_sqls}\n"
                            f"Executed SQLs so far: {executed_sqls or []}\n"
                            f"Findings so far: {findings or []}\n"
                            f"Step summaries so far: {step_summaries or []}\n"
                            f"Prior step results (compact): {compact_prior_results}\n"
                            f"Discovered objects: {discovered.get('objects') or []}\n"
                            f"Discovered SQL_IDs: {discovered.get('sql_ids') or []}\n"
                            f"Discovered sessions: {discovered.get('sessions') or []}\n"
                            "Repair constraints:\n"
                            "- same_goal=true\n"
                            "- return_one_select_only=true\n"
                            "- do_not_repeat_failed_sql=true\n"
                            "- do_not_conclude_from_failed_sql=true\n"
                            "- if owner/object values are already known from prior results, reuse those exact values\n"
                            "- prefer DBA_* views for database-wide scope; fallback ALL_* then USER_* on privilege errors\n"
                        ),
                    },
                ],
                response_format={"type": "json_object"},
            )
            content = str((completion.choices[0].message.content if completion.choices else "") or "").strip()
            parsed = self._parse_planner_json(content)
            repaired_sql = str(parsed.get("repaired_sql") or parsed.get("sql") or "").strip()
            repair_reason = str(parsed.get("repair_reason") or parsed.get("reason") or "").strip()
            if not repaired_sql:
                return None
            return {"sql": repaired_sql, "reason": repair_reason}
        except Exception:
            return None

    def _extract_oracle_error_code(self, message: str) -> str:
        text = str(message or "")
        match = re.search(r"\b(ORA-\d{4,5})\b", text, flags=re.IGNORECASE)
        return match.group(1).upper() if match else "unknown"

    def _coerce_notes_list(self, notes: Any) -> list[str]:
        if notes is None:
            return []
        if isinstance(notes, str):
            text = notes.strip()
            return [text] if text else []
        if isinstance(notes, (list, tuple)):
            return [str(item).strip() for item in notes if str(item).strip()]
        text = str(notes).strip()
        return [text] if text else []

    def _derive_cause(self, problem_statement: str, steps: list[InvestigationStep], evidence: list[str], *, plan_type: str) -> str:
        if not steps:
            return "AI planner could not generate safe SQL for this request."
        if any(step.status == "error" for step in steps):
            return "The investigation hit one or more SQL execution errors; results may be incomplete."
        if not evidence:
            return "The investigation did not gather enough evidence to isolate a finding."
        if plan_type in {"inventory_read_only_lookup", "current_state"}:
            return "Requested read-only lookup evidence was collected successfully."
        lowered = (problem_statement or "").lower()
        if "blocking" in lowered or "lock" in lowered:
            return "Blocking or lock contention is the leading cause candidate based on the investigation path."
        if self._is_performance_diagnostic_request(problem_statement):
            return "Runtime workload evidence was collected for active sessions and SQL resource usage."
        return "Investigation completed with read-only evidence collection based on your request."

    def _resolve_evidence_metadata(
        self,
        *,
        steps: list[InvestigationStep],
        historical_context: dict[str, Any],
        summary_fragments: list[str] | None = None,
    ) -> dict[str, Any]:
        has_runtime = bool(steps)
        has_history_evidence = self._historical_context_has_evidence(historical_context)
        has_history_reference = self._narrative_mentions_historical(*(summary_fragments or []))
        historical_context_used = bool(has_history_evidence and (has_history_reference or not has_runtime))
        evidence_source = "Hybrid" if has_runtime and historical_context_used else "SQL"
        return {
            "evidence_source": evidence_source,
            "historical_context_used": historical_context_used,
        }

    def _historical_context_has_evidence(self, historical_context: dict[str, Any]) -> bool:
        if not isinstance(historical_context, dict):
            return False
        evidence_keys = (
            "db_identity",
            "sql_id_mentions",
            "recent_summaries",
        )
        for key in evidence_keys:
            value = historical_context.get(key)
            if isinstance(value, str) and value.strip():
                return True
            if isinstance(value, dict) and any(v for v in value.values()):
                return True
            if isinstance(value, list) and len(value) > 0:
                return True
        return False

    def _narrative_mentions_historical(self, *fragments: str) -> bool:
        text = " ".join(" ".join(str(item or "").split()) for item in fragments).lower()
        if not text:
            return False
        markers = (
            "historical",
            "history",
            "prior",
            "previous",
            "watch item",
            "trace",
            "recurring",
        )
        return any(token in text for token in markers)

    def _termination_reason_note(self, *, termination_reason: str) -> str:
        reason = str(termination_reason or "").strip().lower() or "completed"
        labels = {
            "evidence_complete": "required evidence checklist satisfied",
            "llm_concluded": "planner concluded after collecting sufficient evidence",
            "clarification_required": "clarification needed before safe SQL execution",
            "low_signal_results": "repeated low-signal zero-row results with incomplete evidence",
            "step_failed": "step failed after SQL attempts",
            "unrecoverable_sql_error": "unrecoverable SQL error encountered",
            "planner_json_parse_failed": "planner JSON parsing and recovery failed before SQL execution",
            "planner_returned_empty_sql": "planner returned run_sql without SQL text",
            "sql_execution_cap_reached": "SQL execution cap reached",
            "completed": "completed",
        }
        return f"Termination detail: {labels.get(reason, reason)}."

    def _confidence_reason_note(
        self,
        *,
        confidence: str,
        inference_confidence: str,
        required_evidence: dict[str, bool],
        successful_steps: int,
    ) -> str:
        completed = sum(1 for value in required_evidence.values() if bool(value))
        total = len(required_evidence)
        return (
            f"Confidence rationale: confidence={confidence}, inference_confidence={inference_confidence}, "
            f"successful_steps={successful_steps}, required_evidence={completed}/{total}."
        )

    def _compose_dba_inference(
        self,
        *,
        problem_statement: str,
        steps: list[InvestigationStep],
        historical_context: dict[str, Any],
        termination_reason: str,
        plan_type: str,
        base_inference: str,
    ) -> str:
        if not steps:
            return base_inference

        text = str(problem_statement or "").lower()
        rows = self._successful_rows(steps)
        inference = str(base_inference or "").strip()

        if "blocking" in text or "lock" in text:
            blocker_sid = ""
            waiter_sid = ""
            object_owner = ""
            object_name = ""
            object_type = ""
            blocker_sql_id = ""
            blocker_sql_text = ""
            wait_event = ""
            for row in rows:
                blocker_sid = blocker_sid or str(
                    self._row_value(row, "blocker_sid", "blocking_session", "blocker_session") or ""
                ).strip()
                waiter_sid = waiter_sid or str(self._row_value(row, "blocked_sid", "waiter_sid", "sid") or "").strip()
                object_owner = object_owner or str(self._row_value(row, "object_owner", "owner") or "").strip()
                object_name = object_name or str(self._row_value(row, "object_name", "segment_name", "table_name") or "").strip()
                object_type = object_type or str(self._row_value(row, "object_type") or "").strip()
                blocker_sql_id = blocker_sql_id or str(self._row_value(row, "blocker_sql_id", "sql_id") or "").strip()
                blocker_sql_text = blocker_sql_text or str(self._row_value(row, "blocker_sql_text", "sql_text") or "").strip()
                wait_event = wait_event or str(self._row_value(row, "event", "wait_event") or "").strip()
            lock_detail_parts: list[str] = []
            if blocker_sid:
                if waiter_sid:
                    lock_detail_parts.append(f"blocker SID {blocker_sid} is blocking waiter SID {waiter_sid}")
                else:
                    lock_detail_parts.append(f"blocker SID {blocker_sid} is present")
            if object_owner and object_name:
                object_label = f"{object_owner}.{object_name}"
                if object_type:
                    object_label += f" ({object_type})"
                lock_detail_parts.append(f"affected object {object_label}")
            if blocker_sql_id:
                lock_detail_parts.append(f"blocker SQL_ID {blocker_sql_id}")
            if blocker_sql_text:
                preview = blocker_sql_text.replace("\n", " ").strip()[:180]
                lock_detail_parts.append(f"blocker SQL text '{preview}'")
            if wait_event:
                lock_detail_parts.append(f"wait event {wait_event}")
            if lock_detail_parts:
                inference = "The collected evidence shows " + ", ".join(lock_detail_parts) + "."
                lowered_sql_text = blocker_sql_text.lower()
                if "tx" in wait_event.lower() or "enq:" in wait_event.lower() or any(
                    token in lowered_sql_text for token in ("update ", "delete ", "insert ", "merge ")
                ):
                    inference += " The leading cause candidate is an uncommitted transactional DML holding row-level locks."
            else:
                inference = "No active blocker is proven from current evidence; treat this as a watch item unless new blocking rows appear."
        elif extract_sql_id(problem_statement):
            requested_sql_id = str(extract_sql_id(problem_statement) or "").strip().lower()
            observed_sql_id = ""
            plan_hash_value = ""
            executions = ""
            elapsed = ""
            cpu = ""
            object_owner = ""
            object_name = ""
            object_type = ""
            for row in rows:
                row_sql_id = str(self._row_value(row, "sql_id") or "").strip().lower()
                if row_sql_id:
                    observed_sql_id = row_sql_id
                plan_hash_value = plan_hash_value or str(self._row_value(row, "plan_hash_value") or "").strip()
                executions = executions or str(self._row_value(row, "executions") or "").strip()
                elapsed = elapsed or str(self._row_value(row, "elapsed_s", "elapsed_time") or "").strip()
                cpu = cpu or str(self._row_value(row, "cpu_s", "cpu_time") or "").strip()
                object_owner = object_owner or str(self._row_value(row, "object_owner", "owner") or "").strip()
                object_name = object_name or str(self._row_value(row, "object_name", "table_name") or "").strip()
                object_type = object_type or str(self._row_value(row, "object_type") or "").strip()
            if not observed_sql_id:
                observed_sql_id = requested_sql_id
            sql_parts: list[str] = []
            if observed_sql_id:
                sql_parts.append(f"SQL_ID {observed_sql_id}")
            if plan_hash_value:
                sql_parts.append(f"plan_hash_value {plan_hash_value}")
            if executions:
                sql_parts.append(f"executions {executions}")
            if elapsed or cpu:
                perf_bits = []
                if elapsed:
                    perf_bits.append(f"elapsed {elapsed}")
                if cpu:
                    perf_bits.append(f"cpu {cpu}")
                sql_parts.append(", ".join(perf_bits))
            if object_owner and object_name:
                object_label = f"{object_owner}.{object_name}"
                if object_type:
                    object_label += f" ({object_type})"
                sql_parts.append(f"object {object_label}")
            if sql_parts:
                inference = "The collected evidence shows " + ", ".join(sql_parts) + "."
                live_hit = any("v$sql" in str(step.sql or "").lower() and int(step.row_count or 0) > 0 for step in steps)
                hist_hit = any("dba_hist" in str(step.sql or "").lower() and int(step.row_count or 0) > 0 for step in steps)
                if live_hit and hist_hit:
                    inference += " Current impact is visible now and corroborated by historical traces."
                elif live_hit:
                    inference += " Current impact is visible in live cache."
                elif hist_hit:
                    inference += " This is currently a historical watch item; live cache evidence was not observed."
            else:
                inference = "No active incident is proven for the requested SQL_ID from current evidence; continue monitoring as a watch item."
        elif self._is_performance_diagnostic_request(problem_statement):
            active_sessions = ""
            wait_class = ""
            wait_event = ""
            top_sql_id = ""
            top_cpu = ""
            top_elapsed = ""
            for row in rows:
                active_sessions = active_sessions or str(self._row_value(row, "active_sessions", "session_count") or "").strip()
                wait_class = wait_class or str(self._row_value(row, "wait_class") or "").strip()
                wait_event = wait_event or str(self._row_value(row, "event") or "").strip()
                top_sql_id = top_sql_id or str(self._row_value(row, "sql_id") or "").strip()
                top_cpu = top_cpu or str(self._row_value(row, "cpu_s", "cpu_time") or "").strip()
                top_elapsed = top_elapsed or str(self._row_value(row, "elapsed_s", "elapsed_time") or "").strip()
            perf_parts: list[str] = []
            if active_sessions:
                perf_parts.append(f"active sessions={active_sessions}")
            if wait_class or wait_event:
                wait_label = ", ".join([item for item in [wait_class, wait_event] if item])
                perf_parts.append(f"dominant wait={wait_label}")
            if top_sql_id:
                top_label = f"top SQL_ID={top_sql_id}"
                if top_cpu or top_elapsed:
                    top_label += f" (cpu={top_cpu or 'n/a'}, elapsed={top_elapsed or 'n/a'})"
                perf_parts.append(top_label)
            if perf_parts:
                inference = "The collected evidence shows " + "; ".join(perf_parts) + "."
                if active_sessions and str(active_sessions).strip() in {"0", "0.0"}:
                    inference += " Current incident is not proven because active workload is low."
            else:
                inference = "No active performance incident is proven from current evidence; treat this as a watch item."
        elif plan_type in {"inventory_read_only_lookup", "current_state"}:
            inference = "The collected evidence answers the requested lookup; no incident root cause is implied by this inventory evidence."

        sql_id_mentions = historical_context.get("sql_id_mentions") if isinstance(historical_context, dict) else []
        if isinstance(sql_id_mentions, list) and sql_id_mentions:
            inference += f" Historical context includes {len(sql_id_mentions)} related trace mention(s)."
        if str(termination_reason or "").strip().lower() in {"step_failed", "unrecoverable_sql_error", "low_signal_results"}:
            inference += " Evidence is incomplete; conclusions should be treated as provisional."
        return inference

    def _successful_rows(self, steps: list[InvestigationStep]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for step in steps:
            if str(step.status or "").lower() != "success":
                continue
            for row in list(step.result_rows or []):
                if isinstance(row, dict):
                    rows.append(row)
        return rows

    def _row_value(self, row: dict[str, Any], *keys: str) -> Any:
        lowered = {str(key).lower(): value for key, value in row.items()}
        for key in keys:
            value = lowered.get(str(key).lower())
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            return value
        return None

    def _recommended_next_actions(self, problem_statement: str, steps: list[InvestigationStep], *, plan_type: str) -> list[str]:
        if any(step.status == "error" for step in steps):
            return [
                "Review the failed step and verify privileges on referenced v$/dba_ views.",
                "Retry investigation after privilege or connectivity fixes.",
            ]
        if not steps:
            return [
                "Rephrase the request with target object names or required fields.",
                "Retry when AI planner connectivity is available.",
            ]
        if plan_type in {"inventory_read_only_lookup", "current_state"}:
            return ["Review the returned rows and request additional filters if needed."]
        lowered = (problem_statement or "").lower()
        if "blocking" in lowered or "lock" in lowered:
            return [
                "Review blocker and waiter SQL_ID/session owners together before intervention.",
                "If blocker termination is necessary, use guarded remediation with operator confirmation.",
            ]
        if self._is_performance_diagnostic_request(problem_statement):
            return [
                "Correlate active sessions with top SQL to confirm the dominant workload source.",
                "Run SQL_ID deep dive on the highest-impact SQL_ID for plan and wait analysis.",
            ]
        return ["Review the SQL steps and confirm whether additional targeted investigation is needed."]

    def _is_performance_diagnostic_request(self, problem_statement: str) -> bool:
        lowered = (problem_statement or "").lower()
        diagnostic_tokens = (
            "root cause",
            "diagnose",
            "why",
            "slow",
            "slowness",
            "performance",
            "bottleneck",
            "high cpu",
            "wait",
            "regressed",
            "tune",
            "latency",
        )
        if any(token in lowered for token in diagnostic_tokens):
            return True
        sql_id = extract_sql_id(problem_statement)
        if not sql_id:
            return False
        metadata_tokens = (
            "tables involved",
            "objects involved",
            "stats analyzed",
            "last analyzed",
            "plan objects",
            "sql text",
            "show plan",
        )
        if any(token in lowered for token in metadata_tokens):
            return False
        return any(token in lowered for token in ("why", "slow", "performance", "root cause", "bottleneck"))

    def _question_profile(self, problem_statement: str) -> dict[str, Any]:
        text = str(problem_statement or "").strip().lower()
        diagnostic_mode = self._is_performance_diagnostic_request(problem_statement)
        if diagnostic_mode:
            plan_type = "diagnostic"
        elif any(token in text for token in ("blocking", "blocked session", "lock")):
            plan_type = "current_state"
        else:
            plan_type = "inventory_read_only_lookup"
        return {
            "diagnostic_mode": diagnostic_mode,
            "plan_type": plan_type,
            "sql_id": extract_sql_id(problem_statement),
            "question_text": text,
        }

    def _required_evidence_for_question(self, question: str) -> dict[str, bool]:
        text = str(question or "").lower()
        sql_id = str(extract_sql_id(question) or "").strip().lower()
        diagnostic_mode = self._is_performance_diagnostic_request(question)

        if diagnostic_mode:
            return {
                "active_sessions_checked": False,
                "top_waits_checked": False,
                "top_sql_checked": False,
                "blocking_checked": False,
                "current_vs_history_correlated_if_available": False,
            }

        if sql_id and any(token in text for token in ("tables involved", "objects involved", "stats", "last analyzed", "plan objects", "sql text", "show plan")):
            required = {
                "sql_id_source_checked": False,
                "plan_objects_fetched": False,
                "plan_objects_identified": False,
                "table_stats_fetched": False,
            }
            if "index" in text or "indexes" in text:
                required["indexes_or_plan_indexes_fetched"] = False
            return required

        if ("schema wise total size" in text or "schema-wise total size" in text or "schema size" in text) and any(
            token in text for token in ("tables inside", "tables in schema", "table size")
        ):
            return {
                "schema_total_size_fetched": False,
                "table_size_by_schema_fetched": False,
            }

        if any(token in text for token in ("creation date", "created", "size")) and "table" in text:
            needs_inventory = any(token in text for token in ("what all tables", "list all tables", "which tables", "all tables in database"))
            required: dict[str, bool] = {}
            if needs_inventory:
                required["table_inventory_fetched"] = False
            if any(token in text for token in ("creation date", "created")):
                required["table_creation_fetched"] = False
            if "size" in text:
                required["table_size_fetched"] = False
            if required:
                return required

        if "lock_test" in text and any(token in text for token in ("creation", "size", "stats", "indexes", "sessions", "locks")):
            return {
                "object_owner_creation_fetched": False,
                "object_size_fetched": False,
                "table_stats_fetched": False,
                "indexes_fetched": False,
                "active_sessions_checked": False,
                "locks_checked": False,
            }

        if any(token in text for token in ("blocking", "blocker", "blocked", "lock")):
            return {
                "current_blocking_checked": False,
                "blocker_waiter_details_fetched_if_exists": False,
                "locked_object_checked_if_blockers_exist": False,
                "blocker_sql_text_checked_if_blockers_exist": False,
            }

        if self._is_database_size_question(question):
            return {"database_size_fetched": False}

        if "tablespace" in text:
            return {"tablespace_usage_fetched": False}

        return {"requested_lookup_evidence_collected": False}

    def _derive_required_evidence(self, question: str, *, profile: dict[str, Any]) -> dict[str, bool]:
        del profile
        return self._required_evidence_for_question(question)

    def _update_required_evidence(
        self,
        *,
        required_evidence: dict[str, bool],
        question_profile: dict[str, Any],
        step: InvestigationStep,
        prior_step_results: list[dict[str, Any]],
    ) -> None:
        if step.status != "success":
            return
        sql = str(step.sql or "").lower()
        row_count = int(step.row_count or 0)
        cols = [str(c).lower() for c in (step.result_columns or [])]

        if "database_size_fetched" in required_evidence and row_count >= 1:
            required_evidence["database_size_fetched"] = True

        if "tablespace_usage_fetched" in required_evidence and row_count >= 1:
            required_evidence["tablespace_usage_fetched"] = True

        if "sql_id_source_checked" in required_evidence and ("v$sql" in sql or "dba_hist_sql" in sql):
            required_evidence["sql_id_source_checked"] = True

        if "plan_objects_fetched" in required_evidence and row_count > 0 and ("sql_plan" in sql or "object_name" in " ".join(cols)):
            required_evidence["plan_objects_fetched"] = True

        if "plan_objects_identified" in required_evidence and row_count > 0 and ("sql_plan" in sql or "object_name" in " ".join(cols)):
            required_evidence["plan_objects_identified"] = True

        if "table_stats_fetched" in required_evidence and "tab_statistics" in sql:
            if row_count > 0:
                required_evidence["table_stats_fetched"] = True

        if "indexes_or_plan_indexes_fetched" in required_evidence and (
            "dba_indexes" in sql or "all_indexes" in sql or "user_indexes" in sql or "index" in " ".join(cols)
        ):
            required_evidence["indexes_or_plan_indexes_fetched"] = row_count > 0

        if "schema_total_size_fetched" in required_evidence and "segments" in sql and "group by" in sql and "owner" in sql:
            required_evidence["schema_total_size_fetched"] = row_count > 0
        if "table_size_by_schema_fetched" in required_evidence and "segments" in sql and ("table_name" in " ".join(cols) or "segment_name" in " ".join(cols)):
            required_evidence["table_size_by_schema_fetched"] = row_count > 0

        if "table_inventory_fetched" in required_evidence and ("dba_tables" in sql or "all_tables" in sql or "user_tables" in sql):
            required_evidence["table_inventory_fetched"] = row_count >= 0
        if "table_creation_fetched" in required_evidence and ("dba_objects" in sql or "all_objects" in sql or "user_objects" in sql) and "created" in " ".join(cols):
            required_evidence["table_creation_fetched"] = row_count > 0
        if "table_size_fetched" in required_evidence and ("dba_segments" in sql or "all_segments" in sql or "user_segments" in sql):
            required_evidence["table_size_fetched"] = row_count > 0

        if "object_owner_creation_fetched" in required_evidence and ("objects" in sql and "created" in " ".join(cols)):
            required_evidence["object_owner_creation_fetched"] = row_count > 0
        if "object_size_fetched" in required_evidence and "segments" in sql:
            required_evidence["object_size_fetched"] = row_count > 0
        if "indexes_fetched" in required_evidence and "index" in sql:
            required_evidence["indexes_fetched"] = row_count >= 0
        if "locks_checked" in required_evidence and ("gv$lock" in sql or "gv$locked_object" in sql or "v$lock" in sql):
            required_evidence["locks_checked"] = True

        if "current_blocking_checked" in required_evidence and (
            "blocking_session" in sql or "dba_waiters" in sql or "gv$session" in sql or "v$session" in sql
        ):
            required_evidence["current_blocking_checked"] = True

        if "blocker_waiter_details_fetched_if_exists" in required_evidence:
            if row_count == 0 and required_evidence.get("current_blocking_checked"):
                required_evidence["blocker_waiter_details_fetched_if_exists"] = True
                if "locked_object_checked_if_blockers_exist" in required_evidence:
                    required_evidence["locked_object_checked_if_blockers_exist"] = True
                if "blocker_sql_text_checked_if_blockers_exist" in required_evidence:
                    required_evidence["blocker_sql_text_checked_if_blockers_exist"] = True
            elif row_count > 0 and any(token in cols for token in ("blocker_sid", "blocking_session", "blocked_sid", "sid")):
                required_evidence["blocker_waiter_details_fetched_if_exists"] = True
        if "locked_object_checked_if_blockers_exist" in required_evidence and ("locked_object" in sql or "object_id" in " ".join(cols)):
            required_evidence["locked_object_checked_if_blockers_exist"] = row_count >= 0
        if "blocker_sql_text_checked_if_blockers_exist" in required_evidence and "sql_text" in " ".join(cols):
            required_evidence["blocker_sql_text_checked_if_blockers_exist"] = row_count >= 0

        if "active_sessions_checked" in required_evidence and "gv$session" in sql and "active" in sql:
            required_evidence["active_sessions_checked"] = True
        if "top_waits_checked" in required_evidence and ("gv$system_event" in sql or "wait" in sql):
            required_evidence["top_waits_checked"] = True
        if "top_sql_checked" in required_evidence and ("gv$sql" in sql or "dba_hist_sqlstat" in sql):
            required_evidence["top_sql_checked"] = True
        if "blocking_checked" in required_evidence and ("blocking_session" in sql or "dba_waiters" in sql):
            required_evidence["blocking_checked"] = True
        if "current_vs_history_correlated_if_available" in required_evidence:
            has_live = any("v$" in str(item.get("sql") or "").lower() for item in prior_step_results + [{"sql": step.sql}])
            has_hist = any("dba_hist_" in str(item.get("sql") or "").lower() for item in prior_step_results + [{"sql": step.sql}])
            if has_live and has_hist:
                required_evidence["current_vs_history_correlated_if_available"] = True

        if "requested_lookup_evidence_collected" in required_evidence and row_count >= 0:
            required_evidence["requested_lookup_evidence_collected"] = True

    def _all_required_evidence_satisfied(self, required_evidence: dict[str, bool]) -> bool:
        return bool(required_evidence) and all(bool(value) for value in required_evidence.values())

    def _dictionary_lint(self, *, sql: str, goal: str) -> dict[str, str]:
        text = str(sql or "")
        lowered = text.lower()

        placeholder_tokens = ("your_owner", "your_table", "<owner>", "<table>", "<table_name>", "<schema>")
        for token in placeholder_tokens:
            if token in lowered:
                return {"fatal": "true", "message": f"Placeholder token `{token}` is not allowed in executable SQL."}

        invalid_rules = [
            (r"v\$sql_plan\s*\.\s*table_name", "V$SQL_PLAN.TABLE_NAME is invalid; use OBJECT_OWNER/OBJECT_NAME/OBJECT_TYPE."),
            (r"dba_hist_sql_plan\s*\.\s*table_name", "DBA_HIST_SQL_PLAN.TABLE_NAME is invalid; use OBJECT_OWNER/OBJECT_NAME/OBJECT_TYPE."),
            (r"user_tables\s*\.\s*created", "USER_TABLES.CREATED is invalid; use USER_OBJECTS.CREATED."),
            (r"all_tables\s*\.\s*created", "ALL_TABLES.CREATED is invalid; use ALL_OBJECTS.CREATED."),
            (r"dba_tables\s*\.\s*created", "DBA_TABLES.CREATED is invalid; use DBA_OBJECTS.CREATED."),
            (r"v\$session\s*\.\s*object_id", "V$SESSION.OBJECT_ID is invalid; use ROW_WAIT_OBJ# or GV$LOCKED_OBJECT joins."),
            (r"gv\$session\s*\.\s*object_id", "GV$SESSION.OBJECT_ID is invalid; use ROW_WAIT_OBJ# or GV$LOCKED_OBJECT joins."),
            (r"v\$session\s*\.\s*sql_text", "V$SESSION.SQL_TEXT is invalid; join GV$SQL on INST_ID + SQL_ID."),
            (r"gv\$session\s*\.\s*sql_text", "GV$SESSION.SQL_TEXT is invalid; join GV$SQL on INST_ID + SQL_ID."),
            (r"\btable_name\b[\s,\n\r]+from[\s,\n\r]+v\$sql_plan\b", "V$SQL_PLAN does not expose TABLE_NAME; use OBJECT_OWNER/OBJECT_NAME/OBJECT_TYPE."),
            (r"\btable_name\b[\s,\n\r]+from[\s,\n\r]+dba_hist_sql_plan\b", "DBA_HIST_SQL_PLAN does not expose TABLE_NAME; use OBJECT_OWNER/OBJECT_NAME/OBJECT_TYPE."),
            (r"(?<!\.)\bobject_id\b[\s,\n\r]+from[\s,\n\r]+v\$session\b", "V$SESSION does not expose OBJECT_ID; use ROW_WAIT_OBJ# or GV$LOCKED_OBJECT join."),
            (r"(?<!\.)\bobject_id\b[\s,\n\r]+from[\s,\n\r]+gv\$session\b", "GV$SESSION does not expose OBJECT_ID; use ROW_WAIT_OBJ# or GV$LOCKED_OBJECT join."),
            (r"(?<!\.)\bsql_text\b[\s,\n\r]+from[\s,\n\r]+v\$session\b", "V$SESSION does not expose SQL_TEXT; join GV$SQL on INST_ID + SQL_ID."),
            (r"(?<!\.)\bsql_text\b[\s,\n\r]+from[\s,\n\r]+gv\$session\b", "GV$SESSION does not expose SQL_TEXT; join GV$SQL on INST_ID + SQL_ID."),
        ]
        for pattern, message in invalid_rules:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                return {"fatal": "true", "message": message}

        if "created" in lowered and "user_tables" in lowered and "user_objects" not in lowered:
            return {"fatal": "true", "message": "USER_TABLES.CREATED is invalid; use USER_OBJECTS.CREATED."}
        if "created" in lowered and "all_tables" in lowered and "all_objects" not in lowered:
            return {"fatal": "true", "message": "ALL_TABLES.CREATED is invalid; use ALL_OBJECTS.CREATED."}
        if "created" in lowered and "dba_tables" in lowered and "dba_objects" not in lowered:
            return {"fatal": "true", "message": "DBA_TABLES.CREATED is invalid; use DBA_OBJECTS.CREATED."}

        warning = ""
        if any(token in lowered for token in ("blocking_session", "sid", "serial#", "wait_class")) and "v$session" in lowered and "gv$session" not in lowered:
            warning = "Dictionary lint warning: for RAC-sensitive live session checks, prefer GV$SESSION."

        if "dba_objects" in lowered and "dba_tables" in lowered and "owner" not in lowered:
            warning = "Dictionary lint warning: join DBA_OBJECTS and DBA_TABLES with OWNER to avoid ambiguity."

        if (" join " in lowered and "dba_tables" in lowered and "dba_segments" in lowered) or (
            " join " in lowered and "dba_objects" in lowered and "dba_tables" in lowered
        ):
            ambiguous_columns = ("owner", "table_name", "object_name", "created", "bytes")
            offenders = [column for column in ambiguous_columns if re.search(rf"(?<!\.)\b{column}\b", lowered)]
            if offenders:
                names = ", ".join(offenders)
                return {
                    "fatal": "true",
                    "message": f"Potential ORA-00918 risk: qualify ambiguous columns with table aliases ({names}).",
                }
        del goal
        return {"fatal": "", "message": "", "warning": warning}

    def _oracle_dictionary_guidance(self, question: str | None = None) -> str:
        del question
        return (
            "Oracle dictionary guidance:\n"
            "- Scope interpretation: wording like 'in database', 'all tables', 'all schemas', or 'database-wide' should use DBA_* first.\n"
            "- Privilege fallback: if DBA_* is unavailable, fallback to ALL_*, then USER_*; if USER_* is used, clearly label scope as current schema only.\n"
            "- Application-first inventory: for inventory/size questions, prioritize non-Oracle-maintained schemas by default unless user requests internal/system objects.\n"
            "- Prefer DBA_USERS.ORACLE_MAINTAINED='N' when available to focus on application schemas.\n"
            "- SQL_ID lookup: live SQL text in V$SQL, historical SQL text in DBA_HIST_SQLTEXT.\n"
            "- SQL plan objects: V$SQL_PLAN and DBA_HIST_SQL_PLAN use OBJECT_OWNER, OBJECT_NAME, OBJECT_TYPE (not TABLE_NAME).\n"
            "- For SQL_ID missing in V$SQL, check DBA_HIST_SQLTEXT / DBA_HIST_SQL_PLAN.\n"
            "- Table stats: use DBA_TAB_STATISTICS / ALL_TAB_STATISTICS / USER_TAB_STATISTICS with OWNER + TABLE_NAME; LAST_ANALYZED is here.\n"
            "- Include NUM_ROWS, BLOCKS, and STALE_STATS when available for table stats checks.\n"
            "- Table creation date: CREATED exists in *_OBJECTS, not *_TABLES.\n"
            "- Table size: use *_SEGMENTS views and clarify whether you report table segment only vs total footprint with indexes/LOBs.\n"
            "- Table-only size should use TABLE/TABLE PARTITION/TABLE SUBPARTITION segment types.\n"
            "- Schema size should group *_SEGMENTS by OWNER.\n"
            "- For 'huge tables', order by size descending and include units.\n"
            "- Qualify columns with aliases in joins to avoid ORA-00918 (e.g., OWNER, TABLE_NAME, OBJECT_NAME, CREATED, BYTES).\n"
            "- RAC live session/lock SQL should prefer GV$ views.\n"
            "- V$SESSION/GV$SESSION does not expose SQL_TEXT; join GV$SQL using INST_ID + SQL_ID when needed.\n"
            "- V$SESSION/GV$SESSION does not expose OBJECT_ID; use ROW_WAIT_OBJ# and/or GV$LOCKED_OBJECT.OBJECT_ID joined to DBA_OBJECTS.OBJECT_ID.\n"
            "- CDB/PDB scope should mention container context when relevant.\n"
            "- Tablespace usage: DBA_TABLESPACE_USAGE_METRICS for pct_used/pct_free.\n"
            "- AWR: use DBA_HIST_* structured views when available."
        )

    def _build_relevant_context(self, *, problem_statement: str, db_key: str | None) -> dict[str, Any]:
        sql_id = str(extract_sql_id(problem_statement) or "").strip().lower()
        try:
            traces = read_health_run_traces(limit=20, db_key=db_key)
        except Exception:
            traces = []
        if not traces:
            return {}

        latest = traces[0]
        db_identity = {
            "db_name": str(getattr(latest, "database_name", "") or ""),
            "db_key": str(db_key or ""),
            "instance_name": str(getattr(latest, "instance_name", "") or ""),
            "database_role": str(getattr(latest, "database_role", "") or ""),
            "open_mode": str(getattr(latest, "open_mode", "") or ""),
        }

        related_sql_mentions: list[dict[str, Any]] = []
        if sql_id:
            for trace in traces:
                metrics = getattr(trace, "metrics", {}) if isinstance(getattr(trace, "metrics", {}), dict) else {}
                metric_blob = json.dumps(metrics, ensure_ascii=True).lower()
                if sql_id in metric_blob:
                    related_sql_mentions.append(
                        {
                            "recorded_at": str(getattr(trace, "recorded_at", "") or ""),
                            "summary": str(getattr(trace, "summary", "") or ""),
                            "top_sql_id": str(metrics.get("top_cpu_sql_id") or metrics.get("top_elapsed_sql_id") or ""),
                        }
                    )
                if len(related_sql_mentions) >= 5:
                    break

        return {
            "db_identity": db_identity,
            "sql_id": sql_id,
            "sql_id_mentions": related_sql_mentions,
            "recent_summaries": [str(getattr(item, "summary", "") or "") for item in traces[:3]],
        }

    def _load_recent_context(self, user_question: str, db_key: str | None = None) -> dict[str, Any]:
        historical = self._build_relevant_context(problem_statement=user_question, db_key=db_key)
        return {
            "historical_context": historical,
            "recent_read_only_context": historical,
            "context_refs": [],
        }

    def _extract_discovered_entities(
        self,
        *,
        prior_step_results: list[dict[str, Any]],
        executed_steps: list[InvestigationStep],
    ) -> dict[str, list[str]]:
        objects: set[str] = set()
        sql_ids: set[str] = set()
        sessions: set[str] = set()
        for item in prior_step_results:
            rows = item.get("result_preview") if isinstance(item.get("result_preview"), list) else []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                owner = str(row.get("owner") or row.get("object_owner") or "").strip()
                table_name = str(row.get("table_name") or row.get("object_name") or row.get("segment_name") or "").strip()
                if owner and table_name:
                    objects.add(f"{owner}.{table_name}")
                sql_id = str(row.get("sql_id") or "").strip()
                if sql_id:
                    sql_ids.add(sql_id.lower())
                sid = str(row.get("sid") or "").strip()
                if sid:
                    sessions.add(sid)
        for step in executed_steps:
            for row in list(step.result_rows or [])[: self.row_preview_limit]:
                if not isinstance(row, dict):
                    continue
                owner = str(row.get("owner") or row.get("object_owner") or "").strip()
                table_name = str(row.get("table_name") or row.get("object_name") or "").strip()
                if owner and table_name:
                    objects.add(f"{owner}.{table_name}")
        return {
            "objects": sorted(objects)[:40],
            "sql_ids": sorted(sql_ids)[:20],
            "sessions": sorted(sessions)[:20],
        }

    def _incomplete_evidence_reason(
        self,
        *,
        question: str,
        decision: InvestigationStepDecision,
        step: InvestigationStep,
        required_evidence: dict[str, bool],
        prior_step_results: list[dict[str, Any]],
    ) -> str | None:
        if not self._all_required_evidence_satisfied(required_evidence):
            missing = [key for key, value in required_evidence.items() if not bool(value)]
            if missing:
                return f"required evidence still missing: {', '.join(missing[:4])}"

        sql_text = str(step.sql or "").lower()
        if any(token in sql_text for token in ("your_owner", "your_table", "<owner>", "<table", "<table_name>")):
            return "placeholder tokens were used instead of discovered owner/table values"

        if step.row_count == 0 and any(token in str(question or "").lower() for token in ("creation", "size", "stats", "indexes", "tables")):
            return "zero rows for a multi-part inventory/metadata request; additional evidence is needed"

        discovered = self._extract_discovered_entities(prior_step_results=prior_step_results, executed_steps=[step])
        if discovered.get("objects") and any(token in sql_text for token in ("your_owner", "your_table")):
            return "discovered owner/object values were not reused"

        if "lock_test" in str(question or "").lower() and any(token in str(question or "").lower() for token in ("creation", "size", "stats", "indexes")):
            has_metadata_sql = any(
                marker in sql_text
                for marker in ("dba_objects", "all_objects", "user_objects", "dba_segments", "all_segments", "user_segments", "tab_statistics", "dba_indexes", "all_indexes", "user_indexes")
            )
            if not has_metadata_sql:
                return "sessions/locks-only result does not satisfy requested LOCK_TEST metadata"
        del decision
        return None

    def _step_has_unrecoverable_error(self, step: InvestigationStep) -> bool:
        attempts = step.correction_attempts if isinstance(step.correction_attempts, list) else []
        for attempt in attempts:
            text = str(getattr(attempt, "error", "") or "").lower()
            if text and not self._is_recoverable_execution_error(text) and "dictionary lint" not in text:
                if any(marker in text for marker in ("ora-01017", "ora-12154", "connection", "network", "authentication", "dpi-")):
                    return True
        return False

    def _is_database_size_question(self, question: str) -> bool:
        text = str(question or "").lower()
        return "database size" in text or "size of database" in text or "size of this database" in text

    def _should_force_inventory_replan(self, *, problem_statement: str, active_thread_memory: dict[str, Any]) -> bool:
        if self._is_ambiguous_follow_up_request(problem_statement, active_thread_memory=active_thread_memory):
            return False
        return self._is_clear_read_only_inventory_request(problem_statement)

    def _is_clear_read_only_inventory_request(self, question: str) -> bool:
        text = str(question or "").strip().lower()
        if not text:
            return False
        destructive_tokens = (
            "kill",
            "fix",
            "resolve",
            "take action",
            "terminate",
            "drop",
            "delete",
            "update",
            "insert",
            "truncate",
            "alter",
            "create",
            "grant",
            "revoke",
        )
        if any(token in text for token in destructive_tokens):
            return False

        intent_tokens = (
            "list",
            "show",
            "check",
            "find",
            "display",
            "help me find",
            "what all",
            "what are",
            "what is",
            "which",
        )
        inventory_tokens = (
            "schema",
            "schemas",
            "table",
            "tables",
            "users",
            "user",
            "tablespace",
            "tablespaces",
            "size",
            "sizes",
            "created",
            "creation date",
            "database size",
            "huge tables",
            "top tables",
            "segments",
            "objects",
            "indexes",
            "active sessions",
            "sessions",
            "blockers",
            "blocking locks",
            "locks",
            "inventory",
        )
        has_intent = any(token in text for token in intent_tokens)
        has_inventory_topic = any(token in text for token in inventory_tokens)
        return bool(has_intent and has_inventory_topic)

    def _is_ambiguous_follow_up_request(self, question: str, *, active_thread_memory: dict[str, Any]) -> bool:
        text = str(question or "").strip().lower()
        if not text:
            return True
        explicit_ambiguous_phrases = (
            "check that one",
            "fix it",
            "compare with previous",
            "show details for them",
            "kill the blocker",
        )
        if any(phrase in text for phrase in explicit_ambiguous_phrases):
            return True

        pronoun_tokens = ("that", "it", "them", "those", "one", "previous")
        has_pronouns = any(re.search(rf"\b{token}\b", text) for token in pronoun_tokens)
        has_entity_context = bool(
            (active_thread_memory.get("known_sql_ids") or [])
            or (active_thread_memory.get("known_tables") or [])
            or ((active_thread_memory.get("entities") or {}).get("tables") or [])
            or ((active_thread_memory.get("entities") or {}).get("sql_ids") or [])
        )
        if has_pronouns and not has_entity_context:
            return True
        return False

    def _scope_note_for_sql(self, *, problem_statement: str, sql: str) -> str:
        question = str(problem_statement or "").lower()
        statement = f" {str(sql or '').lower()} "
        database_wide_tokens = ("in database", "database-wide", "all tables", "all schemas", "entire database")
        asks_database_wide = any(token in question for token in database_wide_tokens)
        if asks_database_wide and (" user_" in statement or "\nuser_" in statement):
            return "current schema only (USER_* fallback)"
        return ""

    def _parse_planner_json(self, content: str) -> dict[str, Any]:
        parsed, _error_type = self._parse_planner_json_detailed(content)
        if not parsed:
            return {}
        return self._normalize_planner_payload_aliases(parsed)

    def _dedupe_strings(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(text)
        return deduped

    def _sql_hash(self, sql: str | None) -> str:
        text = str(sql or "").strip()
        if not text:
            return ""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
