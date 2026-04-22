from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from odb_autodba.rag.trace_store import traces_root


def new_investigation_id(recorded_at: datetime | None = None) -> str:
    timestamp = (recorded_at or datetime.now(UTC)).strftime("%Y%m%d_%H%M%S%f")
    return f"inv_{timestamp}"


def investigation_trace_path(*, investigation_id: str, root: Path | None = None) -> Path:
    safe_id = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in investigation_id)
    return (root or traces_root()) / f"investigation_{safe_id}.jsonl"


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


def append_investigation_trace(problem_statement: str, steps: list[dict[str, Any]]) -> str:
    investigation_id = new_investigation_id()
    path = investigation_trace_path(investigation_id=investigation_id)
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
