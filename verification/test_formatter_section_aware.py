from __future__ import annotations

import unittest

from odb_autodba.agents.root_cause_engine import rank_root_causes
from odb_autodba.models.schemas import HealthCheckSection, HealthSnapshot, HistoricalRun, HistoryContext, TopSqlRow
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

    def test_tablespace_headline_section_shows_pct_only(self) -> None:
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
        self.assertIn("tablespace_name  pct_used  pct_free", rendered)
        self.assertIn("USERS            2.51%", rendered)
        self.assertNotIn("used_mb", rendered)
        self.assertNotIn("total_mb", rendered)

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
        self.assertIn("AWR Workload Delta", rendered)
        self.assertIn("AWR workload delta rows were unavailable.", rendered)

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
        self.assertIn("AWR wait class shift rows were unavailable.", rendered)
        self.assertIn("AWR SQL delta rows were unavailable.", rendered)

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
        self.assertIn("AWR Snapshot Chain Diagnostic", rendered)
        self.assertIn("AWR Snapshot Quality", rendered)
        self.assertIn("AWR Workload Delta", rendered)
        self.assertIn("AWR Top Wait Events", rendered)
        self.assertIn("AWR SQL Delta", rendered)
        self.assertIn("AWR DBA Recommendations", rendered)
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
        self.assertIn("AWR Snapshot Quality", rendered)
        self.assertIn("context_only", rendered.lower())
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
        self.assertIn("AWR SQL Delta", rendered)
        self.assertIn("AWR SQL delta rows were unavailable.", rendered)
        self.assertNotIn("SQL ordered by", rendered)

    def test_awr_sections_render_table_style(self) -> None:
        answer = {
            "summary_lines": [],
            "awr_state_diff": {
                "structured_sections": {
                    "snapshot_chain_diagnostic": [{"DBID": 1234, "Instance": 1, "Startup Time": "2026-04-22T00:00:00", "Snap Min": 210, "Snap Max": 212, "Begin Time": "2026-04-22T02:00:00", "End Time": "2026-04-22T04:00:00", "Rows": 3, "Selected": "yes"}],
                    "snapshot_windows": [{"Window": "current", "DBID": 1234, "Instance": 1, "Startup Time": "2026-04-22T00:00:00", "Begin Snap": 211, "End Snap": 212, "Begin Time": "2026-04-22T03:00:00", "End Time": "2026-04-22T04:00:00", "Duration Min": 60, "Quality": "HIGH", "Use": "rca"}],
                    "workload_delta": [{"Metric": "DB Time", "Previous": 40, "Current": 80, "Delta": 40, "Per Min": 1.33, "Interpretation": "up"}],
                    "wait_class_shift": [{"Wait Class": "Application", "Previous Wait s": 1, "Current Wait s": 10, "Delta s": 9, "Current % DB Time": 12.5, "Interpretation": "growth"}],
                    "top_wait_events": [{"Event": "enq: TX - row lock contention", "Wait Class": "Application", "Prev Wait s": 0, "Curr Wait s": 10, "Delta s": 10, "Waits": 100, "Avg Latency": 0.1, "Impact": "negligible", "DBA Interpretation": "watch"}],
                    "sql_delta": [{"SQL_ID": "abc", "Plan": 123, "Schema": "APP", "Module": "SQL*Plus", "Execs": 1, "Elapsed s": 40, "Elapsed/Exec s": 40, "CPU s": 10, "I/O Wait s": 5, "App Wait s": 3, "Conc Wait s": 2, "Gets/Exec": 1000, "Reads/Exec": 20, "DB Time %": 50, "Classification": "significant_contributor"}],
                    "plan_stability": [{"SQL_ID": "abc", "Plans": 1, "Previous Plan": 123, "Current Plan": 123, "Plan Changed": False, "Prev Elapsed/Exec": 10, "Curr Elapsed/Exec": 40, "Regression Evidence": "worse"}],
                    "ash_blocking": [{"Event": "enq: TX - row lock contention", "Wait Class": "Application", "Samples": 12, "Distinct Waiters": 3, "Blocking Inst": 1, "Blocking SID": 218, "Top SQL_ID": "abc", "Object": 12345, "Interpretation": "blocking"}],
                    "object_hotspots": [{"Object": "DEVA1.LOCK_TEST", "Object Type": "TABLE", "Event": "enq: TX - row lock contention", "Wait Class": "Application", "Samples": 12, "Top SQL_ID": "abc", "Interpretation": "hotspot"}],
                    "redo_commit_profile": [{"Metric": "redo size", "Previous": 1000, "Current": 1200, "Delta": 200, "Interpretation": "context"}],
                    "dba_recommendations": [{"Priority": 1, "Recommendation": "Validate blocker ownership", "Reason": "row-lock signal"}],
                    "confidence_coverage": [{"Item": "AWR mode", "Value": "structured DBA_HIST comparison"}],
                },
                "snapshot_quality": {"window_quality": "HIGH", "usage": "rca", "reason": "ok"},
            },
        }
        rendered = render_history_answer(answer)
        self.assertIn("AWR Snapshot Chain Diagnostic", rendered)
        self.assertIn("dbid      instance", rendered.lower())
        self.assertIn("AWR SQL Delta", rendered)

    def test_awr_correlation_uses_historical_transient_wording_when_current_blocking_zero(self) -> None:
        answer = {
            "summary_lines": [],
            "context": HistoryContext(
                latest_run=HistoricalRun(
                    run_id="r2",
                    completed_at="2026-05-08T09:00:00Z",
                    summary="latest",
                    metrics={"blocking_count": 0},
                )
            ),
            "awr_state_diff": {
                "structured_sections": {
                    "ash_blocking": [
                        {
                            "Event": "enq: TX - row lock contention",
                            "Wait Class": "Application",
                            "Samples": 467,
                            "Distinct Waiters": 10,
                            "Blocking Inst": 1,
                            "Blocking SID": 218,
                            "Top SQL_ID": "0m92022d1yzhs",
                            "Object": "DEVA1.LOCK_TEST",
                            "Interpretation": "blocking/concurrency sample",
                        }
                    ]
                }
            },
        }
        rendered = render_history_answer(answer)
        self.assertIn("blocking_count=0 in latest health run", rendered)
        self.assertIn("historical/transient", rendered)
        self.assertIn("AWR confirms row-lock contention occurr", rendered)

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
