from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from odb_autodba.rag.investigation_trace_store import hydrate_investigation_report_from_trace


class InvestigationHydrationTests(unittest.TestCase):
    def test_hydrate_trace_renders_sql_results_and_conclusion(self) -> None:
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
        self.assertIn("## SQL Executed", report)
        self.assertIn("select 1 as total_gb from dual", report)
        self.assertIn("## Result", report)
        self.assertIn("\"total_gb\": 12.5", report)
        self.assertIn("## Observation", report)
        self.assertIn("## 🔵 Investigation Conclusion", report)
        self.assertNotIn("## 🔴 Root Cause Analysis", report)
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

        self.assertIn("## SQL Executed", report)
        self.assertIn("## Result", report)
        self.assertIn("## Actions", report)
        self.assertIn("Use this for capacity planning.", report)
        self.assertIn("Confidence: HIGH", report)
        self.assertIn("Termination: Inventory request complete.", report)


if __name__ == "__main__":
    unittest.main()
