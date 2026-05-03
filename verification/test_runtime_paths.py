from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager

from odb_autodba.config import get_default_oracle_target
from odb_autodba.rag.trace_store import (
    append_health_run_trace,
    history_indexing_path,
    trace_chunk_index_path,
    write_history_index_entries,
    write_trace_evidence_chunks,
)
from odb_autodba.runtime_paths import (
    get_database_runtime_dir,
    get_exports_dir,
    get_indexes_dir,
    get_locks_dir,
    get_traces_dir,
)


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
            "ORACLE_PASSWORD": "super-secret",
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


def test_runtime_path_resolver_creates_per_db_dirs() -> None:
    with _temp_runtime_env():
        target = get_default_oracle_target()
        db_runtime = get_database_runtime_dir(target.db_key)
        traces = get_traces_dir(target.db_key)
        indexes = get_indexes_dir(target.db_key)
        exports = get_exports_dir(target.db_key)
        locks = get_locks_dir(target.db_key)

        assert db_runtime.exists()
        assert traces.exists()
        assert indexes.exists()
        assert exports.exists()
        assert locks.exists()
        assert target.db_key in str(db_runtime)


def test_runtime_path_resolver_uses_default_target_when_db_key_none() -> None:
    with _temp_runtime_env():
        target = get_default_oracle_target()
        resolved = get_database_runtime_dir()
        assert target.db_key in str(resolved)


def test_runtime_path_does_not_include_password() -> None:
    with _temp_runtime_env():
        path_text = str(get_database_runtime_dir())
        assert "super-secret" not in path_text


def test_trace_writer_uses_per_db_trace_dir() -> None:
    with _temp_runtime_env():
        target = get_default_oracle_target()
        record = append_health_run_trace(
            {"database_name": "UNITDB", "summary": "unit test trace"},
            rebuild_artifacts=False,
        )
        trace_dir = get_traces_dir(target.db_key)
        assert str(trace_dir) in str(record.trace_path)


def test_index_writers_use_per_db_index_dir() -> None:
    with _temp_runtime_env():
        target = get_default_oracle_target()
        write_trace_evidence_chunks([])
        write_history_index_entries([
            {
                "entry_type": "run_history",
                "payload": {
                    "database_name": "UNITDB",
                    "completed_at": "2026-01-01T00:00:00+00:00",
                },
            }
        ])

        assert trace_chunk_index_path().exists()
        assert history_indexing_path().exists()
        assert str(get_indexes_dir(target.db_key)) in str(trace_chunk_index_path())
        assert str(get_indexes_dir(target.db_key)) in str(history_indexing_path())
