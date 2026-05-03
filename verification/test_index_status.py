from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from odb_autodba.rag.indexer import get_index_status


class IndexStatusTests(unittest.TestCase):
    def test_index_status_available_and_fresh(self) -> None:
        db_key = "unit_db"
        with tempfile.TemporaryDirectory() as td:
            os.environ["ODB_AUTODBA_RUNTIME_ROOT"] = td
            try:
                base = Path(td) / db_key
                traces = base / "traces"
                indexes = base / "indexes"
                traces.mkdir(parents=True, exist_ok=True)
                indexes.mkdir(parents=True, exist_ok=True)

                trace_at = datetime.now(UTC) - timedelta(minutes=5)
                trace_file = traces / "health_run_20260501T000000000000Z_unitdb.json"
                trace_payload = {
                    "run_id": "run-1",
                    "recorded_at": trace_at.isoformat(),
                    "completed_at": trace_at.isoformat(),
                    "database_name": "UNITDB",
                    "overall_status": "OK",
                    "summary": "ok",
                    "metrics": {},
                    "issues": [],
                }
                trace_file.write_text(json.dumps(trace_payload), encoding="utf-8")

                now = datetime.now(UTC).timestamp()
                for name in ("trace_chunks.jsonl", "recurring_issues.jsonl", "history_indexing.jsonl"):
                    path = indexes / name
                    path.write_text("{}", encoding="utf-8")
                    os.utime(path, (now, now))

                status = get_index_status(db_key)
            finally:
                os.environ.pop("ODB_AUTODBA_RUNTIME_ROOT", None)

        self.assertTrue(status["available"])
        self.assertTrue(status["fresh"])
        self.assertIsNotNone(status["last_updated"])
        self.assertTrue(status["exists"]["trace_chunks"])
        self.assertTrue(status["exists"]["recurring_issues"])
        self.assertTrue(status["exists"]["history_indexing"])


if __name__ == "__main__":
    unittest.main()
