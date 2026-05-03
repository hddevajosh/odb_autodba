from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from odb_autodba.rag.trace_store import traces_root


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

    question = _extract_question(events)
    steps = _extract_steps(events)
    done_payload = _extract_done_payload(events)

    sql_sections: list[str] = []
    result_sections: list[str] = []
    observations: list[str] = []
    for step in steps:
        step_number = step.get("step_number")
        goal = str(step.get("goal") or "").strip()
        label = f"Step {step_number}" if step_number is not None else "Step"
        if goal:
            label = f"{label} - {goal}"
        sql_text = str(step.get("sql") or "").strip()
        if sql_text:
            sql_sections.extend([f"### {label}", "```sql", sql_text, "```", ""])

        rows = step.get("result_rows")
        row_count = int(step.get("row_count") or 0)
        preview = str(step.get("result_preview") or "").strip()
        status = str(step.get("status") or "").strip() or "unknown"
        result_sections.append(f"### {label}")
        result_sections.append(f"Status: `{status}`")
        if preview:
            result_sections.append(preview)
        if isinstance(rows, list) and rows:
            rendered_rows = _render_result_rows(rows)
            if rendered_rows:
                result_sections.extend(["```json", rendered_rows, "```"])
        elif row_count == 0:
            result_sections.append("No rows returned.")
        result_sections.append("")

        if preview:
            observations.append(f"{label}: {preview}")
        if isinstance(rows, list) and rows:
            observations.append(f"{label}: captured {len(rows)} preview row(s).")

    likely_cause = _extract_likely_cause(events, done_payload)
    actions = _extract_actions(events, done_payload)
    confidence_line = _extract_confidence(done_payload, steps)
    conclusion_heading = _investigation_heading_for_question(question)

    lines: list[str] = ["# AI Investigation Result", "", "## Question", question or "Not provided.", ""]
    lines.append("## SQL Executed")
    if sql_sections:
        lines.extend(sql_sections)
    else:
        lines.append("No SQL statements were captured in the trace.")
    lines.append("")

    lines.append("## Result")
    if result_sections:
        lines.extend(result_sections)
    else:
        lines.append("No step results were captured in the trace.")
    lines.append("")

    lines.append("## Observation")
    if observations:
        lines.extend([f"- {item}" for item in _dedupe_lines(observations)])
    else:
        lines.append("- No observations captured.")
    lines.append("")

    lines.append(conclusion_heading)
    lines.append(likely_cause or "No likely cause/conclusion was captured.")
    lines.append("")

    if actions:
        lines.append("## Actions")
        lines.extend([f"- {item}" for item in actions])
        lines.append("")

    lines.append("## Confidence / Termination")
    lines.append(confidence_line)
    lines.append("")
    return "\n".join(lines).strip() + "\n"


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
        for key in ("question", "problem_statement"):
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


def _extract_done_payload(events: list[dict[str, Any]]) -> dict[str, Any]:
    for event in reversed(events):
        event_type = str(event.get("event_type") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if event_type == "investigation.done":
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


def _extract_confidence(done_payload: dict[str, Any], steps: list[dict[str, Any]]) -> str:
    confidence = str(done_payload.get("confidence") or "").strip()
    termination = str(done_payload.get("termination_reason") or "").strip()
    if confidence and termination:
        return f"Confidence: {confidence}. Termination: {termination}."
    if confidence:
        return f"Confidence: {confidence}."
    if termination:
        return f"Termination: {termination}."
    step_count = len(steps)
    return f"Completed with {step_count} investigative step(s)."


def _render_result_rows(rows: list[Any]) -> str:
    preview = rows[:10]
    normalized: list[Any] = []
    for row in preview:
        if isinstance(row, dict):
            normalized.append(row)
        else:
            normalized.append({"value": str(row)})
    return json.dumps(normalized, ensure_ascii=True, indent=2, default=str)


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


def _investigation_heading_for_question(question: str) -> str:
    text = (question or "").strip().lower()
    diagnostic_tokens = (
        "why",
        "caused",
        "cause",
        "slow",
        "blocking",
        "lock contention",
        "cpu high",
        "memory high",
        "ora-",
        "error",
        "failed",
        "failure",
    )
    if any(token in text for token in diagnostic_tokens):
        return "## 🔴 Root Cause Analysis"
    return "## 🔵 Investigation Conclusion"
