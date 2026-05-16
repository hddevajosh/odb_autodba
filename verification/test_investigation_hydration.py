from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from odb_autodba.rag.investigation_trace_store import hydrate_investigation_report_from_trace


class InvestigationHydrationTests(unittest.TestCase):
    def test_hydrate_trace_renders_table_results_not_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_sample.jsonl"
            events = [
                {
                    "event_type": "investigation.start",
                    "payload": {
                        "problem_statement": "What is the size of the database?",
                    },
                },
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 1,
                        "goal": "Measure allocated database size",
                        "sql": "select 1 as total_gb from dual",
                        "status": "success",
                        "row_count": 1,
                        "result_preview": "Returned 1 row(s).",
                        "result_columns": ["total_gb"],
                        "result_rows": [{"total_gb": 12.5}],
                    },
                },
                {
                    "event_type": "investigation.done",
                    "payload": {
                        "likely_cause": "Requested inventory metric was collected: database size estimate.",
                        "recommended_next_actions": ["Use size metric for capacity baseline."],
                        "confidence": "HIGH",
                        "termination_reason": "Inventory request completed successfully.",
                    },
                },
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))

        self.assertIn("# AI Investigation Result", report)
        self.assertIn("## Question", report)
        self.assertIn("## Summary", report)
        self.assertIn("## Result", report)
        self.assertIn("## SQL Evidence Collected", report)
        self.assertIn("select 1 as total_gb from dual", report)
        self.assertIn("### Step 1 — Measure allocated database size", report)
        self.assertIn("Output:", report)
        self.assertIn("total_gb", report)
        self.assertIn("12.5", report)
        self.assertNotIn("```json", report)
        self.assertIn("## Observation", report)
        self.assertIn("## DBA Inference", report)
        self.assertIn("## Evidence Source", report)
        self.assertIn("## Confidence / Termination", report)

    def test_hydrate_missing_trace_returns_fallback_message(self) -> None:
        report = hydrate_investigation_report_from_trace("/tmp/does-not-exist-investigation.jsonl")
        self.assertIn("AI Investigation Result", report)
        self.assertIn("No investigation trace events", report)

    def test_hydrate_json_trace_payload_renders_actions_and_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_payload.json"
            payload = {
                "question": "What is the size of the database?",
                "steps": [
                    {
                        "step_number": 1,
                        "goal": "Measure allocated database size",
                        "sql": "select 1 as total_gb from dual",
                        "status": "success",
                        "row_count": 1,
                        "result_preview": "Returned 1 row(s).",
                        "result_rows": [{"total_gb": 10.0}],
                    }
                ],
                "likely_cause": "Requested inventory metric was collected.",
                "recommended_next_actions": ["Use this for capacity planning."],
                "confidence": "HIGH",
                "termination_reason": "Inventory request complete.",
            }
            trace_path.write_text(json.dumps(payload), encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))

        self.assertIn("## Result", report)
        self.assertIn("total_gb", report)
        self.assertIn("10", report)
        self.assertIn("confidence: HIGH", report)
        self.assertIn("termination_reason: Inventory request complete.", report)

    def test_hydrate_preserves_specific_dba_inference_text(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_inference.jsonl"
            events = [
                {"event_type": "investigation.start", "payload": {"problem_statement": "Investigate blocking lock"}},
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 1,
                        "goal": "Collect blocker details",
                        "sql": "select blocker_sid, blocked_sid from gv$session",
                        "status": "success",
                        "row_count": 1,
                        "result_rows": [{"blocker_sid": 601, "blocked_sid": 812}],
                    },
                },
                {
                    "event_type": "investigation.conclusion",
                    "payload": {
                        "likely_cause": "The collected evidence shows blocker SID 601 is blocking waiter SID 812.",
                        "termination_reason": "evidence_complete",
                    },
                },
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))

        self.assertIn("The collected evidence shows blocker SID 601 is blocking waiter SID 812.", report)
        self.assertIn("termination_reason: evidence_complete", report)

    def test_hydrate_empty_result_rows_prints_no_rows_message(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_empty.jsonl"
            events = [
                {"event_type": "investigation.start", "payload": {"problem_statement": "list tables"}},
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 1,
                        "goal": "List tables",
                        "sql": "select table_name from user_tables where 1=0",
                        "status": "success",
                        "row_count": 0,
                        "result_preview": "Returned 0 row(s).",
                        "result_rows": [],
                    },
                },
                {"event_type": "investigation.done", "payload": {"likely_cause": "No matching rows."}},
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))
        self.assertIn("Returned 0 rows.", report)
        self.assertNotIn("[]", report)

    def test_hydrate_multistep_renders_each_step_and_failed_error_text(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_multistep.jsonl"
            events = [
                {"event_type": "investigation.start", "payload": {"problem_statement": "multi-step"}},
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 1,
                        "goal": "Step one",
                        "sql": "select 'A' as marker from dual",
                        "status": "success",
                        "row_count": 1,
                        "result_preview": "Returned 1 row(s).",
                        "result_rows": [{"marker": "A"}],
                    },
                },
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 2,
                        "goal": "Step two",
                        "sql": "select bad from dual",
                        "status": "error",
                        "row_count": 0,
                        "result_preview": 'ORA-00904: "BAD": invalid identifier',
                        "result_rows": [],
                    },
                },
                {"event_type": "investigation.done", "payload": {"likely_cause": "Step two failed."}},
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))
        self.assertIn("Step 1 (Step one): status=success", report)
        self.assertIn("Step 2 (Step two): status=error", report)
        self.assertIn("### Step 1 — Step one", report)
        self.assertIn("ORA-00904", report)
        self.assertNotIn("```json", report)

    def test_hydrate_uses_user_question_alias_from_trace_events(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_user_question.jsonl"
            events = [
                {"event_type": "investigation.meta", "payload": {"user_question": "Check all schema and its size please list it out?"}},
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_no": 1,
                        "goal": "List schema size",
                        "sql": "select owner, sum(bytes) bytes from dba_segments group by owner",
                        "status": "success",
                        "row_count": 1,
                        "result_preview": "Returned 1 row(s).",
                        "result_rows": [{"owner": "APP1", "bytes": 1024}],
                    },
                },
                {"event_type": "investigation.conclusion", "payload": {"likely_cause": "Lookup complete."}},
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))
        self.assertIn("Check all schema and its size please list it out?", report)
        self.assertIn("Step 1", report)
        self.assertIn("owner", report.lower())

    def test_hydrate_clarification_required_not_rendered_as_completed_zero_steps(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_clarify.jsonl"
            events = [
                {"event_type": "investigation.start", "payload": {"problem_statement": "Check that one"}},
                {
                    "event_type": "investigation.conclusion",
                    "payload": {
                        "termination_reason": "clarification_required",
                        "clarification_question": "Which object should I inspect?",
                        "likely_cause": "Need clarification before SQL execution.",
                    },
                },
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))
        self.assertIn("termination_reason: clarification_required", report)
        self.assertIn("clarification: Which object should I inspect?", report)
        self.assertNotIn("Completed with 0 investigative step(s).", report)

    def test_hydrate_three_success_steps_renders_three_tables(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_three_steps.jsonl"
            events = [
                {"event_type": "investigation.start", "payload": {"problem_statement": "help me investigate blocking lock which is present in this database?"}},
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 1,
                        "goal": "Identify current blocking sessions",
                        "sql": "select blocking_session, sid as blocked_sid from v$session where blocking_session is not null",
                        "status": "success",
                        "row_count": 1,
                        "result_columns": ["blocking_session", "blocked_sid"],
                        "result_rows": [{"blocking_session": 601, "blocked_sid": 812}],
                    },
                },
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 2,
                        "goal": "Identify locked object",
                        "sql": "select owner, object_name from dba_objects where object_id = 42",
                        "status": "success",
                        "row_count": 1,
                        "result_columns": ["owner", "object_name"],
                        "result_rows": [{"owner": "APP", "object_name": "ORDERS"}],
                    },
                },
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 3,
                        "goal": "Retrieve SQL text for blocker",
                        "sql": "select sql_id, sql_text from v$sql where sql_id = 'abcd1234'",
                        "status": "success",
                        "row_count": 1,
                        "result_columns": ["sql_id", "sql_text"],
                        "result_rows": [{"sql_id": "abcd1234", "sql_text": "select * from orders"}],
                    },
                },
                {"event_type": "investigation.conclusion", "payload": {"likely_cause": "Blocking lock evidence collected.", "sql_execution_count": 3}},
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))
        self.assertIn("### Step 1 — Identify current blocking sessions", report)
        self.assertIn("### Step 2 — Identify locked object", report)
        self.assertIn("### Step 3 — Retrieve SQL text for blocker", report)
        self.assertGreaterEqual(report.count("<div style=\"overflow-x:auto;\"><pre>"), 3)

    def test_hydrate_repaired_success_shows_correction_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_repair.jsonl"
            events = [
                {"event_type": "investigation.start", "payload": {"problem_statement": "Retrieve blocker SQL text"}},
                {
                    "event_type": "investigation.sql_attempt",
                    "payload": {
                        "step_no": 1,
                        "attempt_no": 1,
                        "sql": "select sql_text from v$session where sid = 601",
                        "execution_status": "error",
                        "status": "error",
                        "error": "ORA-00904: invalid identifier",
                        "repair_reason": "Use V$SQL SQL_ID join instead.",
                    },
                },
                {
                    "event_type": "investigation.sql_attempt",
                    "payload": {
                        "step_no": 1,
                        "attempt_no": 2,
                        "sql": "select sql_id, sql_text from v$sql where sql_id = 'abcd1234'",
                        "execution_status": "success",
                        "status": "success",
                        "repaired": True,
                    },
                },
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 1,
                        "goal": "Retrieve SQL text for blocker",
                        "sql": "select sql_id, sql_text from v$sql where sql_id = 'abcd1234'",
                        "status": "success",
                        "row_count": 1,
                        "result_columns": ["sql_id", "sql_text"],
                        "result_rows": [{"sql_id": "abcd1234", "sql_text": "select * from orders"}],
                    },
                },
                {"event_type": "investigation.conclusion", "payload": {"likely_cause": "Repaired SQL succeeded.", "sql_execution_count": 2}},
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))
        self.assertIn("Status: success after repair", report)
        self.assertIn("Repaired from failed attempt: yes", report)
        self.assertIn("## Correction Attempts", report)
        self.assertIn("Attempt 1 failed:", report)
        self.assertIn("Output:", report)
        self.assertIn("sql_id", report.lower())

    def test_hydrate_large_result_truncates_at_50_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "investigation_large_rows.jsonl"
            rows = [{"n": i, "txt": "x" * 120} for i in range(60)]
            events = [
                {"event_type": "investigation.start", "payload": {"problem_statement": "large"}},
                {
                    "event_type": "investigation.step",
                    "payload": {
                        "step_number": 1,
                        "goal": "Large output",
                        "sql": "select level as n from dual connect by level <= 60",
                        "status": "success",
                        "row_count": 60,
                        "result_columns": ["n", "txt"],
                        "result_rows": rows,
                        "result_truncated": True,
                    },
                },
                {"event_type": "investigation.conclusion", "payload": {"likely_cause": "Large output check."}},
            ]
            trace_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            report = hydrate_investigation_report_from_trace(str(trace_path))
        self.assertIn("Displayed first 50 row(s); output truncated.", report)
        self.assertNotIn("```json", report)


if __name__ == "__main__":
    unittest.main()
