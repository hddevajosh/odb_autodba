from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from odb_autodba.models.schemas import InvestigationReport, InvestigationSQLAttemptRecord, InvestigationStep
from odb_autodba.rag.trace_store import traces_root
from odb_autodba.utils.formatter import render_investigation_final_report


def new_investigation_id(recorded_at: datetime | None = None) -> str:
    timestamp = (recorded_at or datetime.now(UTC)).strftime("%Y%m%d_%H%M%S%f")
    return f"inv_{timestamp}"


def investigation_trace_path(*, investigation_id: str, root: Path | None = None, db_key: str | None = None) -> Path:
    safe_id = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in investigation_id)
    return (root or traces_root(db_key=db_key)) / f"investigation_{safe_id}.jsonl"


def append_investigation_event(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(event)
    payload.setdefault("recorded_at", datetime.now(UTC).isoformat())
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")


def read_investigation_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                events.append(payload)
    return events


def append_investigation_trace(problem_statement: str, steps: list[dict[str, Any]], db_key: str | None = None) -> str:
    investigation_id = new_investigation_id()
    path = investigation_trace_path(investigation_id=investigation_id, db_key=db_key)
    append_investigation_event(
        path,
        {
            "event_type": "investigation.start",
            "payload": {
                "investigation_id": investigation_id,
                "problem_statement": problem_statement,
            },
        },
    )
    for ordinal, step in enumerate(steps, start=1):
        append_investigation_event(
            path,
            {
                "event_type": "investigation.step",
                "payload": {"step_number": ordinal, **step},
            },
        )
    append_investigation_event(
        path,
        {
            "event_type": "investigation.done",
            "payload": {"investigation_id": investigation_id, "step_count": len(steps)},
        },
    )
    return investigation_id


def hydrate_investigation_report_from_trace(trace_path: str) -> str:
    events = _load_trace_events(trace_path)
    if not events:
        return "# AI Investigation Result\n\nNo investigation trace events were available for hydration."
    report = _build_report_from_trace(events)
    return render_investigation_final_report(report).strip() + "\n"


def _build_report_from_trace(events: list[dict[str, Any]]) -> InvestigationReport:
    question = _extract_question(events)
    done_payload = _extract_done_payload(events)
    step_payloads = _extract_steps(events)
    attempts_by_step = _extract_step_attempts(events)
    steps: list[InvestigationStep] = []
    sql_execution_count = int(done_payload.get("sql_execution_count") or 0)
    for index, payload in enumerate(step_payloads, start=1):
        step_number = int(payload.get("step_number") or payload.get("step_no") or index)
        goal = str(payload.get("goal") or "").strip() or f"Investigation step {step_number}"
        status = str(payload.get("status") or "").strip() or "unknown"
        sql = str(payload.get("final_sql") or payload.get("sql") or "").strip()
        row_values = payload.get("result_rows")
        if not isinstance(row_values, list):
            row_values = payload.get("rows")
        result_rows = [dict(item) for item in row_values if isinstance(item, dict)] if isinstance(row_values, list) else []
        col_values = payload.get("result_columns")
        if not isinstance(col_values, list):
            col_values = payload.get("columns")
        result_columns = [str(item) for item in col_values if str(item).strip()] if isinstance(col_values, list) else []
        correction_source = payload.get("correction_attempts")
        if isinstance(correction_source, list) and correction_source:
            correction_attempts = correction_source
        else:
            correction_attempts = attempts_by_step.get(step_number, [])
        attempt_models: list[InvestigationSQLAttemptRecord] = []
        for item in correction_attempts:
            if isinstance(item, dict):
                try:
                    attempt_models.append(InvestigationSQLAttemptRecord.model_validate(item))
                except Exception:
                    continue
        if sql_execution_count <= 0:
            sql_execution_count += sum(
                1
                for entry in attempt_models
                if str(entry.execution_status or entry.status or "").strip().lower() in {"success", "error"}
            )
        row_count = int(payload.get("row_count") or len(result_rows))
        result_truncated = bool(payload.get("result_truncated") or (row_count > len(result_rows)))
        steps.append(
            InvestigationStep(
                step_number=step_number,
                goal=goal,
                sql=sql,
                result_preview=str(payload.get("result_preview") or "").strip() or ("Returned 0 row(s)." if row_count == 0 else ""),
                row_count=row_count,
                status=status,
                result_columns=result_columns,
                result_rows=result_rows,
                result_truncated=result_truncated,
                correction_attempts=attempt_models,
                final_attempt_count=int(payload.get("final_attempt_count") or len(attempt_models) or 1),
                finding=str(payload.get("finding") or "").strip(),
                evidence_source=str(payload.get("evidence_source") or done_payload.get("evidence_source") or "SQL"),
                historical_context_used=bool(payload.get("historical_context_used") or done_payload.get("historical_context_used")),
                investigation_mode=str(payload.get("investigation_mode") or done_payload.get("investigation_mode") or "read_only_lookup"),
                confidence=str(payload.get("confidence") or done_payload.get("confidence") or "MEDIUM"),
                inference_confidence=str(payload.get("inference_confidence") or done_payload.get("inference_confidence") or done_payload.get("confidence") or "MEDIUM"),
                termination_reason=str(payload.get("termination_reason") or done_payload.get("termination_reason") or ""),
            )
        )

    if sql_execution_count <= 0:
        sql_execution_count = sum(1 for step in steps if str(step.status or "").lower() in {"success", "error"})
    summary = str(done_payload.get("summary") or "").strip()
    if not summary:
        summary = (
            f"Ran {len(steps)} logical investigation step(s) with {sql_execution_count} SQL execution(s)."
            if steps
            else "No SQL steps were executed."
        )

    return InvestigationReport(
        problem_statement=question or "Not provided.",
        summary=summary,
        likely_cause=_extract_likely_cause(events, done_payload),
        recommended_next_actions=_extract_actions(events, done_payload),
        steps=steps,
        evidence=[],
        evidence_source=str(done_payload.get("evidence_source") or "SQL"),
        historical_context_used=bool(done_payload.get("historical_context_used") or False),
        investigation_mode=str(done_payload.get("investigation_mode") or "read_only_lookup"),
        confidence=str(done_payload.get("confidence") or "MEDIUM"),
        inference_confidence=str(done_payload.get("inference_confidence") or done_payload.get("confidence") or "MEDIUM"),
        termination_reason=str(done_payload.get("termination_reason") or ("completed" if steps else "no_events")),
        clarification_question=str(done_payload.get("clarification_question") or "").strip(),
        required_evidence_status=done_payload.get("required_evidence_status") if isinstance(done_payload.get("required_evidence_status"), dict) else {},
        sql_execution_count=sql_execution_count,
        sql_execution_cap=int(done_payload.get("sql_execution_cap") or 0),
    )


def _load_trace_events(trace_path: str) -> list[dict[str, Any]]:
    path = Path(str(trace_path or "").strip())
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix.lower() == ".json":
        return _coerce_json_payload(json.loads(text))

    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    if events:
        return events

    try:
        payload = json.loads(text)
    except Exception:
        return []
    return _coerce_json_payload(payload)


def _coerce_json_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("events"), list):
        return [item for item in payload.get("events", []) if isinstance(item, dict)]

    steps = payload.get("steps")
    question = payload.get("question") or payload.get("problem_statement")
    if isinstance(steps, list):
        synthetic: list[dict[str, Any]] = [
            {
                "event_type": "investigation.start",
                "payload": {"problem_statement": question},
            }
        ]
        for idx, step in enumerate(steps, start=1):
            if isinstance(step, dict):
                synthetic.append(
                    {
                        "event_type": "investigation.step",
                        "payload": {"step_number": step.get("step_number") or idx, **step},
                    }
                )
        synthetic.append(
            {
                "event_type": "investigation.done",
                "payload": {
                    "likely_cause": payload.get("likely_cause"),
                    "recommended_next_actions": payload.get("recommended_next_actions"),
                    "confidence": payload.get("confidence"),
                    "termination_reason": payload.get("termination_reason"),
                },
            }
        )
        return synthetic
    return [payload]


def _extract_question(events: list[dict[str, Any]]) -> str:
    for event in events:
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        for key in ("problem_statement", "question", "prompt", "user_question"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _extract_steps(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for event in events:
        event_type = str(event.get("event_type") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if event_type == "investigation.step":
            steps.append(dict(payload))
        elif "sql" in payload and ("goal" in payload or "result_preview" in payload):
            steps.append(dict(payload))
    return steps


def _extract_step_attempts(events: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    attempts_by_step: dict[int, list[dict[str, Any]]] = {}
    for event in events:
        event_type = str(event.get("event_type") or "")
        if event_type != "investigation.sql_attempt":
            continue
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        step_no = int(payload.get("step_number") or payload.get("step_no") or 0)
        if step_no <= 0:
            continue
        attempts_by_step.setdefault(step_no, []).append(dict(payload))
    for step_no in attempts_by_step:
        attempts_by_step[step_no].sort(key=lambda item: int(item.get("attempt_no") or item.get("attempt") or 0))
    return attempts_by_step


def _extract_done_payload(events: list[dict[str, Any]]) -> dict[str, Any]:
    for event in reversed(events):
        event_type = str(event.get("event_type") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if event_type in {"investigation.done", "investigation.conclusion"}:
            return dict(payload)
    return {}


def _extract_likely_cause(events: list[dict[str, Any]], done_payload: dict[str, Any]) -> str:
    value = done_payload.get("likely_cause")
    if isinstance(value, str) and value.strip():
        return value.strip()
    for event in reversed(events):
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        candidate = payload.get("likely_cause") or payload.get("conclusion")
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def _extract_actions(events: list[dict[str, Any]], done_payload: dict[str, Any]) -> list[str]:
    for source in (done_payload,):
        items = source.get("recommended_next_actions") if isinstance(source, dict) else None
        if isinstance(items, list):
            clean = [str(item).strip() for item in items if str(item).strip()]
            if clean:
                return clean
    actions: list[str] = []
    for event in events:
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        items = payload.get("recommended_next_actions")
        if isinstance(items, list):
            actions.extend(str(item).strip() for item in items if str(item).strip())
    return _dedupe_lines(actions)


def _dedupe_lines(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for line in lines:
        normalized = " ".join(str(line or "").split()).strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(str(line).strip())
    return output
