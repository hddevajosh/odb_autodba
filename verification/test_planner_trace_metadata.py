from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from odb_autodba.agents.planner_agent import PlannerAgent
from odb_autodba.models.schemas import HealthSnapshot, HistoryContext, InstanceInfo, RemediationProposal, RemediationReview
from odb_autodba.rag.trace_store import (
    health_run_trace_path,
    read_health_run_traces,
    read_history_index_entries,
)


@contextmanager
def _temp_runtime_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        trace_dir = os.path.join(tmp, "traces")
        index_dir = os.path.join(tmp, "indexes")
        index_file = os.path.join(index_dir, "history_indexing.jsonl")
        old_trace = os.environ.get("ODB_AUTODBA_TRACE_DIR")
        old_index = os.environ.get("ODB_AUTODBA_HISTORY_INDEX_DIR")
        old_index_file = os.environ.get("ODB_AUTODBA_HISTORY_INDEX_FILE")
        os.environ["ODB_AUTODBA_TRACE_DIR"] = trace_dir
        os.environ["ODB_AUTODBA_HISTORY_INDEX_DIR"] = index_dir
        os.environ["ODB_AUTODBA_HISTORY_INDEX_FILE"] = index_file
        try:
            yield
        finally:
            if old_trace is None:
                os.environ.pop("ODB_AUTODBA_TRACE_DIR", None)
            else:
                os.environ["ODB_AUTODBA_TRACE_DIR"] = old_trace
            if old_index is None:
                os.environ.pop("ODB_AUTODBA_HISTORY_INDEX_DIR", None)
            else:
                os.environ["ODB_AUTODBA_HISTORY_INDEX_DIR"] = old_index
            if old_index_file is None:
                os.environ.pop("ODB_AUTODBA_HISTORY_INDEX_FILE", None)
            else:
                os.environ["ODB_AUTODBA_HISTORY_INDEX_FILE"] = old_index_file


class PlannerTraceMetadataTests(unittest.TestCase):
    def test_health_response_includes_trace_metadata_and_matches_latest_record(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-23T00:00:00Z",
            instance_info=InstanceInfo(db_name="UNITDB", instance_name="unitdb"),
        )
        proposal = RemediationProposal(
            action_type="none",
            title="No action",
            description="No remediation required.",
            rationale="No critical issue.",
        )
        review = RemediationReview(status="not_needed", confidence="LOW", rationale="No action required.")

        with _temp_runtime_dirs():
            with patch("odb_autodba.agents.planner_agent.collect_health_snapshot", return_value=snapshot), patch(
                "odb_autodba.agents.planner_agent.render_health_snapshot_report",
                return_value="# Oracle AutoDBA Report",
            ), patch(
                "odb_autodba.agents.planner_agent.build_remediation_proposal",
                return_value=proposal,
            ), patch(
                "odb_autodba.agents.planner_agent.review_remediation_proposal",
                return_value=review,
            ), patch(
                "odb_autodba.agents.planner_agent.HistoryService.compare_recent_runs",
                return_value=HistoryContext(),
            ):
                response = PlannerAgent().handle_message("Check health of my Oracle database")

            supporting = response.supporting_data or {}
            self.assertIsNotNone(supporting.get("trace_path"))
            self.assertTrue(str(supporting.get("trace_path")).strip())
            self.assertTrue(str(supporting.get("run_id") or "").strip())
            self.assertTrue(str(supporting.get("recorded_at") or "").strip())
            self.assertTrue(str(supporting.get("completed_at") or "").strip())

            latest = read_health_run_traces(database_name="UNITDB", limit=1)
            self.assertTrue(latest)
            self.assertEqual(supporting.get("trace_path"), latest[0].trace_path)
            self.assertEqual(supporting.get("run_id"), latest[0].run_id)

            # No regression in trace/indexing flow: compact history and run_history index are still written.
            self.assertTrue(health_run_trace_path().exists())
            history_entries = read_history_index_entries(database_name="UNITDB", entry_type="run_history", limit=5)
            self.assertTrue(history_entries)
            latest_payload = history_entries[0].get("payload") or {}
            self.assertEqual(latest_payload.get("trace_path"), supporting.get("trace_path"))


if __name__ == "__main__":
    unittest.main()
