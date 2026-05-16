from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.mcp.jobs import create_job, get_job, run_job
from odb_autodba.models.schemas import InvestigationReport, InvestigationStep
from odb_autodba.services.autodba_service import run_ai_investigation


class InvestigationThreadMemoryDisabledFlowTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key
            self.pdb_name = "FREEPDB1"
            self.service_name = "FREEPDB1"
            self.sid = None

    @staticmethod
    def _report(problem: str) -> InvestigationReport:
        return InvestigationReport(
            problem_statement=problem,
            summary="Ran 1 logical investigation step(s) with 1 SQL execution(s).",
            likely_cause="Requested read-only lookup evidence was collected successfully.",
            steps=[
                InvestigationStep(
                    step_number=1,
                    goal="Collect evidence",
                    sql="select owner, table_name from dba_tables fetch first 5 rows only",
                    result_preview="Returned 1 row(s).",
                    row_count=1,
                    status="success",
                    result_columns=["owner", "table_name"],
                    result_rows=[{"owner": "APP", "table_name": "ORDERS"}],
                )
            ],
        )

    def test_direct_investigation_ignores_thread_context_and_writes_no_thread_memory_files(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {"ODB_AUTODBA_RUNTIME_ROOT": td},
            clear=False,
        ), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=self._report("List all schemas and tables"),
        ):
            payload = run_ai_investigation(
                "List all schemas and tables",
                db_key="db1",
                thread_id="invth_legacy",
                continue_context=True,
                user_id="u1",
            )

        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("thread_memory_enabled"), False)
        self.assertEqual(str(payload.get("thread_id") or ""), "invth_legacy")
        supporting = payload.get("supporting_data") or {}
        self.assertEqual(supporting.get("thread_memory_enabled"), False)
        self.assertNotIn("thread_memory_path", supporting)
        self.assertNotIn("thread_turns_path", supporting)

    def test_mcp_investigation_ignores_thread_context_and_does_not_create_investigation_thread_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_RUNTIME_ROOT": td,
                "ODB_AUTODBA_JOBS_DIR": str(Path(td) / "jobs"),
            },
            clear=False,
        ), patch(
            "odb_autodba.services.autodba_service.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.mcp.jobs.get_oracle_target",
            return_value=self._Target("db1"),
        ), patch(
            "odb_autodba.services.autodba_service.InvestigationAgent.investigate",
            return_value=self._report("List all schemas and tables"),
        ):
            job = create_job(
                "investigation",
                db_key="db1",
                payload={"question": "List all schemas and tables", "thread_id": "invth_legacy", "continue_context": True},
            )
            run_job(job["job_id"])
            payload = get_job(job["job_id"]) or {}

        self.assertEqual(payload.get("status"), "completed")
        result = payload.get("result") or {}
        self.assertEqual(result.get("thread_memory_enabled"), False)
        investigations_dir = Path(td) / "db1" / "investigations"
        self.assertFalse(investigations_dir.exists())


if __name__ == "__main__":
    unittest.main()
