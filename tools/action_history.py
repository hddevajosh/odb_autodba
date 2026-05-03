from __future__ import annotations

import json
from pathlib import Path

from odb_autodba.config import get_default_oracle_target
from odb_autodba.db.connection import active_db_key
from odb_autodba.models.schemas import RemediationRecord
from odb_autodba.runtime_paths import get_exports_dir
from odb_autodba.utils.formatter import render_action_history_markdown

BASE_DIR = Path(__file__).resolve().parent.parent
LEGACY_HISTORY_FILES = [
    BASE_DIR / "runs" / "history" / "action_history.jsonl",
    BASE_DIR.parent / "runs" / "history" / "action_history.jsonl",
]


def append_action_record(record: RemediationRecord, *, db_key: str | None = None) -> None:
    path = _history_file_path(db_key=db_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(record.model_dump_json() + "\n")


def load_action_records(limit: int = 20, *, db_key: str | None = None) -> list[RemediationRecord]:
    records: list[RemediationRecord] = []
    for path in _history_read_paths(db_key=db_key):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(RemediationRecord.model_validate_json(line))
            except Exception:
                continue
    return records[-limit:]


def _history_file_path(db_key: str | None = None) -> Path:
    resolved_key = (db_key or "").strip() or (active_db_key() or "").strip() or get_default_oracle_target().db_key
    return get_exports_dir(resolved_key) / "action_history.jsonl"


def _history_read_paths(db_key: str | None = None) -> list[Path]:
    primary = _history_file_path(db_key=db_key)
    paths = [primary]
    seen = {primary.resolve()}
    for candidate in LEGACY_HISTORY_FILES:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        paths.append(candidate)
    return paths


__all__ = ["append_action_record", "load_action_records", "render_action_history_markdown"]
