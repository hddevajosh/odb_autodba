from __future__ import annotations

import argparse
import json

from odb_autodba.runtime_migration import migrate_legacy_runtime_to_db_runtime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Migrate legacy runtime history into per-database runtime layout.")
    parser.add_argument("--db-key", default=None, help="Target database key. Defaults to config-derived db_key.")
    parser.add_argument("--dry-run", action="store_true", help="Plan migration actions without writing files.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--copy", dest="copy", action="store_true", default=True, help="Write copied/merged files (default).")
    group.add_argument("--no-copy", dest="copy", action="store_false", help="Do not write files; report actions only.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    result = migrate_legacy_runtime_to_db_runtime(
        db_key=args.db_key,
        copy=args.copy,
        dry_run=args.dry_run,
    )

    print(f"db_key: {result.get('db_key')}")
    print(f"dry_run: {result.get('dry_run')}")
    print(f"sources_found: {len(result.get('sources_found') or [])}")
    for src in result.get("sources_found") or []:
        print(f"  - {src}")
    print(f"planned: {result.get('planned')}")
    print(f"copied: {result.get('copied')}")
    print(f"merged: {result.get('merged')}")
    print(f"skipped: {result.get('skipped')}")
    warnings = result.get("warnings") or []
    errors = result.get("errors") or []
    print(f"warnings: {len(warnings)}")
    for warning in warnings:
        print(f"  - {warning}")
    print(f"errors: {len(errors)}")
    for err in errors:
        print(f"  - {err}")
    if errors:
        print("result_json:")
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
