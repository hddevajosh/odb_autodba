from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from odb_autodba.config import get_default_oracle_target
from odb_autodba.utils.env_loader import load_project_dotenv


PACKAGE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parent
DEFAULT_RUNTIME_ROOT = REPO_ROOT / "runtime" / "databases"

JSONL_FILENAMES = {
    "health_runs.jsonl",
    "trace_chunks.jsonl",
    "recurring_issues.jsonl",
    "database_behavior_profiles.jsonl",
    "history_indexing.jsonl",
    "action_history.jsonl",
}


def migrate_legacy_runtime_to_db_runtime(
    db_key: str | None = None,
    copy: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    resolved_db_key = _resolve_db_key(db_key)
    runtime_root = _runtime_root()
    db_runtime = runtime_root / resolved_db_key
    traces_dest = db_runtime / "traces"
    indexes_dest = db_runtime / "indexes"
    exports_dest = db_runtime / "exports"

    summary: dict[str, Any] = {
        "ok": True,
        "db_key": resolved_db_key,
        "dry_run": bool(dry_run),
        "sources_found": [],
        "planned": 0,
        "copied": 0,
        "merged": 0,
        "skipped": 0,
        "warnings": [],
        "errors": [],
    }

    should_write = bool(copy) and not bool(dry_run)
    if should_write:
        traces_dest.mkdir(parents=True, exist_ok=True)
        indexes_dest.mkdir(parents=True, exist_ok=True)
        exports_dest.mkdir(parents=True, exist_ok=True)

    destination_by_kind = {
        "traces": traces_dest,
        "indexes": indexes_dest,
        "exports": exports_dest,
    }

    for source_dir, kind in _legacy_sources():
        if not source_dir.exists() or not source_dir.is_dir():
            continue
        summary["sources_found"].append(str(source_dir))
        destination_root = destination_by_kind[kind]
        for source_file in sorted(source_dir.rglob("*")):
            if not source_file.is_file():
                continue
            relative = source_file.relative_to(source_dir)
            destination = destination_root / relative
            try:
                if source_file.name in JSONL_FILENAMES:
                    changed, warning_list = _merge_jsonl_file(
                        source=source_file,
                        destination=destination,
                        dry_run=dry_run,
                        copy_enabled=copy,
                    )
                    if changed:
                        summary["planned"] += 1
                        if should_write:
                            summary["merged"] += 1
                    else:
                        summary["skipped"] += 1
                    summary["warnings"].extend(warning_list)
                else:
                    operation = _copy_file_non_destructive(
                        source=source_file,
                        destination=destination,
                        dry_run=dry_run,
                        copy_enabled=copy,
                    )
                    if operation == "planned":
                        summary["planned"] += 1
                        if should_write:
                            summary["copied"] += 1
                    elif operation == "skipped":
                        summary["skipped"] += 1
            except Exception as exc:
                summary["errors"].append(f"{source_file} -> {destination}: {exc}")

    if summary["errors"]:
        summary["ok"] = False
    summary["warnings"] = _dedupe_preserve_order(summary["warnings"])
    summary["errors"] = _dedupe_preserve_order(summary["errors"])
    return summary


def _legacy_sources() -> list[tuple[Path, str]]:
    entries: list[tuple[Path, str]] = []
    candidates: list[tuple[Path, str]] = [
        (PACKAGE_ROOT / "runs" / "traces", "traces"),
        (PACKAGE_ROOT / "runs" / "indexes", "indexes"),
        (REPO_ROOT / "runtime" / "traces", "traces"),
        (REPO_ROOT / "runtime" / "indexes", "indexes"),
        (REPO_ROOT / "runtime" / "exports", "exports"),
        (REPO_ROOT / "runs" / "traces", "traces"),
        (REPO_ROOT / "runs" / "indexes", "indexes"),
        (REPO_ROOT / "runs" / "exports", "exports"),
    ]
    seen: set[tuple[str, str]] = set()
    for path, kind in candidates:
        key = (str(path.resolve()), kind)
        if key in seen:
            continue
        seen.add(key)
        entries.append((path, kind))
    return entries


def _copy_file_non_destructive(
    *,
    source: Path,
    destination: Path,
    dry_run: bool,
    copy_enabled: bool,
) -> str:
    if destination.exists() and destination.stat().st_size > 0:
        return "skipped"
    if not copy_enabled:
        return "planned"
    if dry_run:
        return "planned"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return "planned"


def _merge_jsonl_file(
    *,
    source: Path,
    destination: Path,
    dry_run: bool,
    copy_enabled: bool,
) -> tuple[bool, list[str]]:
    warnings: list[str] = []
    destination_lines: list[str] = []
    destination_set: set[str] = set()
    destination_record_keys: set[str] = set()

    if destination.exists():
        with destination.open("r", encoding="utf-8") as handle:
            for line_no, raw_line in enumerate(handle, 1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    warnings.append(f"Malformed JSONL line skipped in destination {destination}:{line_no}")
                    continue
                record_key = _jsonl_record_identity_key(source_name=destination.name, payload=payload)
                if record_key:
                    destination_record_keys.add(record_key)
                if line not in destination_set:
                    destination_set.add(line)
                    destination_lines.append(line)

    missing_lines: list[str] = []
    source_seen: set[str] = set()
    with source.open("r", encoding="utf-8") as handle:
        for line_no, raw_line in enumerate(handle, 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                warnings.append(f"Malformed JSONL line skipped in source {source}:{line_no}")
                continue
            record_key = _jsonl_record_identity_key(source_name=source.name, payload=payload)
            if line in source_seen:
                continue
            source_seen.add(line)
            if record_key and record_key in destination_record_keys:
                continue
            if line in destination_set:
                continue
            missing_lines.append(line)
            if record_key:
                destination_record_keys.add(record_key)

    changed = len(missing_lines) > 0
    if changed and copy_enabled and not dry_run:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("a", encoding="utf-8") as handle:
            for line in missing_lines:
                handle.write(line + "\n")
    return changed, warnings


def _jsonl_record_identity_key(*, source_name: str, payload: dict[str, Any]) -> str:
    name = str(source_name or "")
    if name == "health_runs.jsonl":
        run_id = str(payload.get("run_id") or "").strip()
        if run_id:
            return f"run_id::{run_id}"
        trace_path = str(payload.get("trace_path") or "").strip()
        if trace_path:
            return f"trace_path::{trace_path}"
        completed_at = str(payload.get("completed_at") or payload.get("recorded_at") or "").strip()
        database_name = str(payload.get("database_name") or "").strip()
        summary = str(payload.get("summary") or "").strip()
        if completed_at or database_name or summary:
            return f"fallback::{completed_at}::{database_name}::{summary}"
    return ""


def _runtime_root() -> Path:
    load_project_dotenv()
    configured = (os.getenv("ODB_AUTODBA_RUNTIME_ROOT") or "").strip()
    if configured:
        root = Path(configured)
        if not root.is_absolute():
            root = Path.cwd() / root
        return root
    return DEFAULT_RUNTIME_ROOT


def _resolve_db_key(db_key: str | None) -> str:
    raw = (db_key or "").strip()
    if not raw:
        raw = get_default_oracle_target().db_key
    safe = re.sub(r"[^a-z0-9_-]+", "-", raw.strip().lower())
    safe = re.sub(r"-{2,}", "-", safe).strip("-_")
    return safe or "default"


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
