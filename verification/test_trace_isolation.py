from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from odb_autodba.rag.indexer import rebuild_planner_memory_artifacts
from odb_autodba.rag.trace_store import health_run_trace_path, read_health_run_traces, read_trace_evidence_chunks
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

    def test_malformed_jsonl_line_does_not_crash_history_reads(self) -> None:
        db_key = "unit_a__db__1521__freepdb1"
        with _temp_runtime_env():
            path = health_run_trace_path(db_key=db_key)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                '{"run_id":"good","recorded_at":"2026-05-01T00:00:00+00:00","completed_at":"2026-05-01T00:00:00+00:00","database_name":"UNITDB","overall_status":"OK","summary":"ok","metrics":{"active_sessions":1},"issues":[]}\n'
                'this is not json\n',
                encoding="utf-8",
            )
            traces = read_health_run_traces(db_key=db_key, limit=None)
        self.assertEqual([trace.run_id for trace in traces], ["good"])

    def test_legacy_trace_read_fallback_is_opt_in(self) -> None:
        db_key = "unit__db-host__1521__freepdb1"
        with tempfile.TemporaryDirectory() as td:
            runtime_root = os.path.join(td, "runtime", "databases")
            legacy_dir = os.path.join(td, "legacy", "traces")
            os.makedirs(legacy_dir, exist_ok=True)
            legacy_file = os.path.join(legacy_dir, "health_runs.jsonl")
            with open(legacy_file, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"run_id":"legacy","recorded_at":"2026-05-01T00:00:00+00:00","completed_at":"2026-05-01T00:00:00+00:00","database_name":"UNITDB","overall_status":"OK","summary":"legacy","metrics":{},"issues":[]}\n'
                )
            env = {
                "ODB_AUTODBA_RUNTIME_ROOT": runtime_root,
                "ODB_AUTODBA_TRACE_DIR": legacy_dir,
                "ODB_AUTODBA_ENVIRONMENT": "unit",
                "ORACLE_HOST": "db-host",
                "ORACLE_PORT": "1521",
                "ORACLE_SERVICE_NAME": "freepdb1",
                "ORACLE_USER": "system",
                "ORACLE_PASSWORD": "unit-secret",
            }
            unused_legacy_dir = Path(td) / "unused_legacy"
            with patch("odb_autodba.rag.trace_store._legacy_trace_dirs", return_value=[unused_legacy_dir]):
                with patch.dict(os.environ, env, clear=False):
                    self.assertEqual(read_health_run_traces(db_key=db_key, limit=None), [])
            with patch("odb_autodba.rag.trace_store._legacy_trace_dirs", return_value=[unused_legacy_dir]):
                with patch.dict(os.environ, {**env, "ODB_AUTODBA_ALLOW_LEGACY_READ_FALLBACK": "true"}, clear=False):
                    self.assertEqual(read_health_run_traces(db_key=db_key, limit=None), [])
            with patch("odb_autodba.rag.trace_store._legacy_trace_dirs", return_value=[Path(legacy_dir)]):
                with patch.dict(os.environ, env, clear=False):
                    self.assertEqual(read_health_run_traces(db_key=db_key, limit=None), [])
            with patch("odb_autodba.rag.trace_store._legacy_trace_dirs", return_value=[Path(legacy_dir)]):
                with patch.dict(os.environ, {**env, "ODB_AUTODBA_ALLOW_LEGACY_READ_FALLBACK": "true"}, clear=False):
                    traces = read_health_run_traces(db_key=db_key, limit=None)
        self.assertEqual([trace.run_id for trace in traces], ["legacy"])


if __name__ == "__main__":
    unittest.main()
