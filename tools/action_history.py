from __future__ import annotations

import json
from pathlib import Path

from odb_autodba.models.schemas import RemediationRecord
from odb_autodba.utils.formatter import render_action_history_markdown

BASE_DIR = Path(__file__).resolve().parent.parent
HISTORY_FILE = BASE_DIR / "runs" / "history" / "action_history.jsonl"
HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)


def append_action_record(record: RemediationRecord) -> None:
    with HISTORY_FILE.open("a", encoding="utf-8") as fh:
        fh.write(record.model_dump_json() + "\n")


def load_action_records(limit: int = 20) -> list[RemediationRecord]:
    if not HISTORY_FILE.exists():
        return []
    records = []
    for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(RemediationRecord.model_validate_json(line))
        except Exception:
            continue
    return records[-limit:]


__all__ = ["append_action_record", "load_action_records", "render_action_history_markdown"]
