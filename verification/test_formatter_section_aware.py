from __future__ import annotations

import unittest

from odb_autodba.agents.root_cause_engine import rank_root_causes
from odb_autodba.models.schemas import HealthCheckSection, HealthSnapshot, TopSqlRow
from odb_autodba.utils.formatter import render_health_snapshot_report, render_history_answer


class FormatterCleanupTests(unittest.TestCase):
    def test_health_report_has_single_supporting_evidence_section(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-23T00:00:00Z",
            issues=[],
            health_sections=[HealthCheckSection(name="Locks And Blocking", status="OK", summary="No blockers.", rows=[])],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertEqual(rendered.count("## 🔵 Supporting Evidence"), 1)
        self.assertNotIn("#### Supporting Evidence", rendered)

    def test_ai_header_not_duplicated(self) -> None:
        snapshot = HealthSnapshot(generated_at="2026-04-23T00:00:00Z")
        rendered = render_health_snapshot_report(snapshot)
        self.assertEqual(rendered.count("## 🔵 AI Investigation Summary"), 1)
        self.assertEqual(rendered.count("### AI Investigation Summary"), 0)

    def test_ai_reasoning_dedupes_repeated_lines(self) -> None:
        repeated = "Lock-related waits were observed, but no active blocker was present at collection time."
        snapshot = HealthSnapshot(
            generated_at="2026-04-23T00:00:00Z",
            health_sections=[
                HealthCheckSection(name="Locks And Blocking", status="WARNING", summary="Lock snapshot.", rows=[{"waiter_sid": 42}], notes=[repeated]),
                HealthCheckSection(name="Current Wait Profile", status="WARNING", summary="Wait snapshot.", rows=[{"event": "enq: TX - row lock contention"}], notes=[repeated]),
            ],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertEqual(rendered.count(repeated), 1)

    def test_tablespace_storage_conversion_uses_realistic_units(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-23T00:00:00Z",
            health_sections=[
                HealthCheckSection(
                    name="Tablespace Usage",
                    status="WARNING",
                    summary="Tablespace summary.",
                    rows=[
                        {
                            "tablespace_name": "USERS",
                            "used_pct": 2.51,
                            "used_mb": 843008,
                            "free_mb": 32711424,
                            "total_mb": 33554432,
                        }
                    ],
                )
            ],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("823.25 MB", rendered)
        self.assertIn("31.20 GB", rendered)
        self.assertIn("32.00 GB", rendered)
        self.assertNotIn("32.00 TB", rendered)

    def test_top_sql_tables_remain_tabular_but_narrower(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-23T00:00:00Z",
            top_sql_by_cpu=[
                TopSqlRow(
                    sql_id="b6usrg82hwsa3",
                    parsing_schema_name="DEVA1",
                    module="batch_loader",
                    program="java",
                    cpu_s=180.0,
                    cpu_per_exec_s=2.3,
                    ela_per_exec_s=2.9,
                    executions=77,
                    sql_classification="application_sql",
                    workload_interpretation="likely CPU-heavy",
                )
            ],
            top_sql_by_elapsed=[TopSqlRow(sql_id="b6usrg82hwsa3", parsing_schema_name="DEVA1", module="batch_loader", program="java", elapsed_s=200.0)],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("module_prog", rendered)
        self.assertNotIn("rows_exec", rendered)
        self.assertNotIn("lio_exec", rendered)
        self.assertNotIn("pio_exec", rendered)
        self.assertNotIn("last_active", rendered)

    def test_awr_workload_all_unavailable_collapses_to_compact_note(self) -> None:
        answer = {
            "summary_lines": [],
            "awr_state_diff": {
                "workload_metrics": [
                    {
                        "metric_name": "DB Time",
                        "previous_value": None,
                        "current_value": None,
                        "delta_value": None,
                        "percent_delta": None,
                        "significance": "LOW",
                        "interpretation": "Unavailable.",
                    },
                    {
                        "metric_name": "DB CPU",
                        "previous_value": None,
                        "current_value": None,
                        "delta_value": None,
                        "percent_delta": None,
                        "significance": "LOW",
                        "interpretation": "Unavailable.",
                    },
                ]
            },
        }
        rendered = render_history_answer(answer)
        self.assertIn("AWR workload metrics were unavailable in the mapped comparison window.", rendered)
        self.assertNotIn("pctdelta", rendered)

    def test_wait_and_sql_awr_sections_collapse_when_unavailable(self) -> None:
        answer = {
            "summary_lines": [],
            "awr_state_diff": {
                "wait_shift_summary": {
                    "previous_dominant_wait_class": None,
                    "current_dominant_wait_class": None,
                    "previous_top_event": None,
                    "current_top_event": None,
                },
                "sql_change_summary": {
                    "dominant_sql_id_previous": None,
                    "dominant_sql_id_current": None,
                    "dominant_sql_schema_previous": None,
                    "dominant_sql_schema_current": None,
                },
            },
        }
        rendered = render_history_answer(answer)
        self.assertIn("AWR wait-class shift details were unavailable", rendered)
        self.assertIn("AWR SQL-change details were unavailable", rendered)

    def test_awr_text_summary_sections_are_stable_and_no_raw_dump(self) -> None:
        answer = {
            "summary_lines": [],
            "awr_state_diff": {
                "window_mapping": {
                    "previous": {"begin_snap_id": 210, "end_snap_id": 211, "mapping_quality": "HIGH"},
                    "current": {"begin_snap_id": 211, "end_snap_id": 212, "mapping_quality": "HIGH"},
                },
                "awr_report_text_summary": {
                    "available": True,
                    "source": "DBMS_WORKLOAD_REPOSITORY.AWR_REPORT_TEXT",
                    "begin_snap_id": 211,
                    "end_snap_id": 212,
                    "load_profile_summary": ["DB Time: low workload (2.00 mins total)", "DB CPU: moderate usage (1.25 mins total)"],
                    "main_bottlenecks": ["enq: TX - row lock contention\n  -> application/concurrency wait\n  -> impact: contention-sensitive"],
                    "sql_contributors": ["SQL_ID: 3nkd7x4r8w1pb\n  -> elapsed: 1.59 mins\n  -> classification: SQL contributor from AWR text"],
                    "recommended_follow_up": ["Review blocking chains for transient row-lock contention."],
                    "interpretation_summary": ["Workload is low overall with no clear system-level saturation in the AWR window."],
                    "notes": ["RAW_AWR_DUMP_THIS_SHOULD_NOT_APPEAR"],
                },
            },
        }
        rendered = render_history_answer(answer)
        self.assertIn("AWR Snapshot Window", rendered)
        self.assertIn("Load Profile Summary", rendered)
        self.assertIn("Main Bottlenecks", rendered)
        self.assertIn("SQL Contributors", rendered)
        self.assertIn("Recommended Follow-up", rendered)
        self.assertIn("AWR Interpretation Summary", rendered)
        self.assertNotIn("RAW_AWR_DUMP_THIS_SHOULD_NOT_APPEAR", rendered)

    def test_same_window_awr_uses_single_window_mode_not_workload_changes(self) -> None:
        answer = {
            "summary_lines": [],
            "awr_state_diff": {
                "awr_mode": "single_window_interpretation",
                "window_mapping": {
                    "previous": {"begin_snap_id": 216, "end_snap_id": 217, "mapping_quality": "MEDIUM"},
                    "current": {"begin_snap_id": 216, "end_snap_id": 217, "mapping_quality": "MEDIUM"},
                },
                "awr_report_text_summary": {
                    "available": True,
                    "load_profile_summary": ["DB Time: low workload (0.60 mins total)"],
                    "main_bottlenecks": ["db file sequential read\n  -> dominant User I/O wait\n  -> avg latency: 177 us\n  -> impact: moderate"],
                    "sql_contributors": [],
                    "recommended_follow_up": ["Validate storage latency and top I/O SQL plans for the AWR window."],
                    "interpretation_summary": ["Dominant waits are I/O-related; impact should be judged with latency and SQL plan context."],
                },
            },
        }
        rendered = render_history_answer(answer)
        self.assertIn("AWR Analysis Mode: Single-window interpretation (historical context applied)", rendered)
        self.assertNotIn("AWR Workload Changes", rendered)
        self.assertIn("AWR source: single-window analysis with report-text enrichment (comparison not applicable)", rendered)
        self.assertIn("AWR mode: Single-window interpretation", rendered)
        self.assertNotIn("Window-based mapping used", rendered)

    def test_awr_sql_contributors_fallback_message_when_empty(self) -> None:
        answer = {
            "summary_lines": [],
            "awr_state_diff": {
                "awr_report_text_summary": {
                    "available": True,
                    "load_profile_summary": ["DB Time: low workload (0.60 mins total)"],
                    "main_bottlenecks": [],
                    "sql_contributors": [],
                    "recommended_follow_up": [],
                },
            },
        }
        rendered = render_history_answer(answer)
        self.assertIn("SQL contributor details were not available for this snapshot window.", rendered)
        self.assertNotIn("SQL ordered by", rendered)

    def test_historical_summary_does_not_repeat_transition_line(self) -> None:
        answer = {
            "summary_lines": [
                "Status transition: warning -> warning (outcome=unchanged, confidence=LOW).",
                "Status transition: warning -> warning (outcome=unchanged, confidence=LOW).",
                "No significant change detected.",
            ],
            "state_transition": {
                "available": True,
                "status_transition": "warning -> warning",
                "transition_outcome": "unchanged",
                "confidence": "LOW",
            },
        }
        rendered = render_history_answer(answer)
        self.assertEqual(rendered.count("Status transition: warning -> warning"), 1)

    def test_learning_features_display_friendly_labels(self) -> None:
        answer = {
            "summary_lines": [],
            "learning_features": {
                "state_persisted_but_worsened_flag": True,
                "incident_driver_category": "locking",
                "residual_driver_category": "storage",
            },
        }
        rendered = render_history_answer(answer)
        lowered = rendered.lower()
        self.assertIn("State persisted but worsened", rendered)
        self.assertIn("incident driver category", lowered)
        self.assertIn("residual driver category", lowered)
        self.assertNotIn("state_persisted_but_worsened_flag", rendered)

    def test_ai_section_stays_after_detailed_evidence(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-23T00:00:00Z",
            health_sections=[HealthCheckSection(name="Locks And Blocking", status="OK", summary="No blockers.", rows=[])],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertGreater(rendered.find("AI Investigation Summary"), rendered.find("Detailed Evidence"))

    def test_root_cause_uses_tablespace_name_from_alert_log_not_unknown(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-23T00:00:00Z",
            raw_evidence={
                "tablespace_allocation_anomaly": {
                    "tablespace_allocation_failure_with_low_pct": True,
                    "tablespace_name": None,
                },
                "alert_log": [
                    {
                        "code": "ORA-01653",
                        "message": "ORA-01653: unable to extend table DEVA1.CPU_MEM_TEST in tablespace USERS",
                    }
                ],
            },
        )
        causes = rank_root_causes(snapshot)
        joined = " ".join(causes)
        self.assertIn("USERS", joined)
        self.assertNotIn("unknown tablespace", joined)


if __name__ == "__main__":
    unittest.main()
