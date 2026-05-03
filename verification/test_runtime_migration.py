from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from odb_autodba.runtime_migration import migrate_legacy_runtime_to_db_runtime


class RuntimeMigrationTests(unittest.TestCase):
    def _write(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _patch_roots(self, root: Path):
        package_root = root / "odb_autodba"
        repo_root = root
        return patch.multiple(
            "odb_autodba.runtime_migration",
            PACKAGE_ROOT=package_root,
            REPO_ROOT=repo_root,
            DEFAULT_RUNTIME_ROOT=repo_root / "runtime" / "databases",
        )

    def test_dry_run_reports_planned_actions_but_copies_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "odb_autodba" / "runs" / "traces" / "health_run_old.json"
            self._write(src, '{"ok": true}\n')
            with self._patch_roots(root):
                result = migrate_legacy_runtime_to_db_runtime(db_key="unitdb", dry_run=True)
            dest = root / "runtime" / "databases" / "unitdb" / "traces" / "health_run_old.json"
            self.assertTrue(result["ok"])
            self.assertGreaterEqual(result["planned"], 1)
            self.assertEqual(result["copied"], 0)
            self.assertEqual(result["merged"], 0)
            self.assertFalse(dest.exists())

    def test_copy_mode_copies_legacy_trace_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "runs" / "traces" / "health_run_old.json"
            self._write(src, '{"run": 1}\n')
            with self._patch_roots(root):
                result = migrate_legacy_runtime_to_db_runtime(db_key="mydb", dry_run=False)
            dest = root / "runtime" / "databases" / "mydb" / "traces" / "health_run_old.json"
            self.assertTrue(result["ok"])
            self.assertTrue(dest.exists())
            self.assertEqual(dest.read_text(encoding="utf-8"), '{"run": 1}\n')
            self.assertGreaterEqual(result["copied"], 1)

    def test_jsonl_merge_deduplicates_identical_lines(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "runs" / "indexes" / "history_indexing.jsonl"
            dest = root / "runtime" / "databases" / "mydb" / "indexes" / "history_indexing.jsonl"
            line_a = json.dumps({"entry_type": "run_history", "payload": {"run_id": "r1"}})
            line_b = json.dumps({"entry_type": "run_history", "payload": {"run_id": "r2"}})
            self._write(src, f"{line_a}\n{line_a}\n\n{line_b}\n")
            self._write(dest, f"{line_a}\n")
            with self._patch_roots(root):
                result = migrate_legacy_runtime_to_db_runtime(db_key="mydb", dry_run=False)
            lines = [line.strip() for line in dest.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(result["ok"])
            self.assertIn(line_a, lines)
            self.assertIn(line_b, lines)
            self.assertEqual(lines.count(line_a), 1)
            self.assertEqual(lines.count(line_b), 1)
            self.assertGreaterEqual(result["merged"], 1)

    def test_destination_non_empty_file_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "runtime" / "exports" / "report.md"
            dest = root / "runtime" / "databases" / "mydb" / "exports" / "report.md"
            self._write(src, "old report")
            self._write(dest, "new report")
            with self._patch_roots(root):
                result = migrate_legacy_runtime_to_db_runtime(db_key="mydb", dry_run=False)
            self.assertTrue(result["ok"])
            self.assertEqual(dest.read_text(encoding="utf-8"), "new report")
            self.assertGreaterEqual(result["skipped"], 1)

    def test_db_key_none_uses_default_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "runs" / "exports" / "report.md"
            self._write(src, "legacy")
            with self._patch_roots(root), patch(
                "odb_autodba.runtime_migration.get_default_oracle_target",
                return_value=SimpleNamespace(db_key="PROD__Ora-Host01__1521__PDB1"),
            ):
                result = migrate_legacy_runtime_to_db_runtime(db_key=None, dry_run=True)
            self.assertEqual(result["db_key"], "prod__ora-host01__1521__pdb1")

    def test_malformed_jsonl_line_is_skipped_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "runs" / "traces" / "health_runs.jsonl"
            dest = root / "runtime" / "databases" / "mydb" / "traces" / "health_runs.jsonl"
            valid = json.dumps({"run_id": "r1", "database_name": "X"})
            self._write(src, f"{valid}\n{{bad json\n")
            self._write(dest, "")
            with self._patch_roots(root):
                result = migrate_legacy_runtime_to_db_runtime(db_key="mydb", dry_run=False)
            lines = [line.strip() for line in dest.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(result["ok"])
            self.assertIn(valid, lines)
            self.assertTrue(any("Malformed JSONL line skipped in source" in item for item in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
