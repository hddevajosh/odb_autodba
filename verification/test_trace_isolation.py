from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from odb_autodba.rag.indexer import rebuild_planner_memory_artifacts
from odb_autodba.rag.trace_store import read_health_run_traces, read_trace_evidence_chunks
from odb_autodba.runtime_paths import get_indexes_dir, get_traces_dir


@contextmanager
def _temp_runtime_env() -> None:
    with tempfile.TemporaryDirectory() as td:
        env = {
            "ODB_AUTODBA_RUNTIME_ROOT": td,
            "ODB_AUTODBA_ENVIRONMENT": "unit",
            "ORACLE_HOST": "db-host",
            "ORACLE_PORT": "1521",
            "ORACLE_SERVICE_NAME": "freepdb1",
            "ORACLE_USER": "system",
            "ORACLE_PASSWORD": "unit-secret",
        }
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            yield
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


class TraceIsolationTests(unittest.TestCase):
    def _append_trace(self, *, db_key: str, run_id: str, completed_at: str, metric_value: int) -> None:
        from odb_autodba.rag.trace_store import append_health_run_trace

        append_health_run_trace(
            {
                "run_id": run_id,
                "completed_at": completed_at,
                "database_name": "UNITDB",
                "summary": f"run {run_id}",
                "overall_status": "OK",
                "metrics": {"active_sessions": metric_value},
                "issues": [],
            },
            rebuild_artifacts=False,
            db_key=db_key,
        )

    def test_trace_and_index_reads_are_db_key_isolated(self) -> None:
        db_a = "unit_a__db__1521__freepdb1"
        db_b = "unit_b__db__1521__freepdb1"
        now = datetime.now(UTC)
        with _temp_runtime_env():
            self._append_trace(
                db_key=db_a,
                run_id="run_a_1",
                completed_at=(now - timedelta(minutes=3)).isoformat(),
                metric_value=11,
            )
            self._append_trace(
                db_key=db_b,
                run_id="run_b_1",
                completed_at=(now - timedelta(minutes=2)).isoformat(),
                metric_value=22,
            )

            traces_a = read_health_run_traces(db_key=db_a, limit=None)
            traces_b = read_health_run_traces(db_key=db_b, limit=None)

            self.assertTrue(traces_a)
            self.assertTrue(traces_b)
            self.assertTrue(all(f"/{db_a}/traces/" in str(item.trace_path or "") for item in traces_a))
            self.assertTrue(all(f"/{db_b}/traces/" in str(item.trace_path or "") for item in traces_b))
            self.assertFalse(any(item.run_id == "run_b_1" for item in traces_a))
            self.assertFalse(any(item.run_id == "run_a_1" for item in traces_b))

            rebuild_planner_memory_artifacts(db_key=db_a)
            rebuild_planner_memory_artifacts(db_key=db_b)

            chunks_a = read_trace_evidence_chunks(db_key=db_a, limit=None)
            chunks_b = read_trace_evidence_chunks(db_key=db_b, limit=None)
            self.assertTrue(chunks_a)
            self.assertTrue(chunks_b)
            self.assertTrue(all(f"/{db_a}/traces/" in str(item.trace_path or "") for item in chunks_a))
            self.assertTrue(all(f"/{db_b}/traces/" in str(item.trace_path or "") for item in chunks_b))

            self.assertTrue(get_traces_dir(db_a).exists())
            self.assertTrue(get_traces_dir(db_b).exists())
            self.assertTrue(get_indexes_dir(db_a).exists())
            self.assertTrue(get_indexes_dir(db_b).exists())


if __name__ == "__main__":
    unittest.main()
