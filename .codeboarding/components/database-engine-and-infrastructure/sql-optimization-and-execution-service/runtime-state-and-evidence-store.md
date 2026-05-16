---
component_id: 4.3.4
component_name: Runtime State & Evidence Store
---

# Runtime State & Evidence Store

## Component Description

Manages the physical lifecycle of diagnostic data. It handles directory structures for traces, exports, and the migration of JSONL state files between different execution environments to ensure continuity of evidence.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/runtime_paths.py (lines 24-27)
```
def get_traces_dir(db_key: str | None = None) -> Path:
    path = get_database_runtime_dir(db_key=db_key) / "traces"
    path.mkdir(parents=True, exist_ok=True)
    return path
```

### /home/neha/projects/agents/odb_autodba/runtime_migration.py (lines 28-110)
```
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
```


## Source Files:

- `migrate_runtime.py`
- `runtime_migration.py`
- `runtime_paths.py`

