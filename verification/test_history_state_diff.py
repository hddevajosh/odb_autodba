from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.history.jsonl_service import JsonlHistoryService
from odb_autodba.models.schemas import (
    AwrMetricDelta,
    AwrMemoryState,
    AwrRunPairWindowMapping,
    AwrSnapshotQuality,
    AwrSnapshotWindowMapping,
    AwrSqlChangeSummary,
    AwrSqlChangeIntelligence,
    AwrStateDiff,
    AwrTimeModelState,
    AwrWaitShiftSummary,
    AwrWaitClassShift,
    HealthIssue,
    HistoryContext,
    RecurringIssueIndexRecord,
    TraceHealthRunRecord,
)
from odb_autodba.utils.formatter import render_history_answer


def _trace(
    *,
    run_id: str,
    completed_at: str,
    status: str,
    summary: str,
    metrics: dict | None = None,
    issues: list[HealthIssue] | None = None,
) -> TraceHealthRunRecord:
    return TraceHealthRunRecord(
        run_id=run_id,
        recorded_at=completed_at,
        completed_at=completed_at,
        database_name="FREE",
        overall_status=status,
        summary=summary,
        metrics=metrics or {},
        issues=issues or [],
        report_markdown="",
    )


class HistoryStateDiffTests(unittest.TestCase):
    def test_warning_to_critical_transition(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="CRITICAL",
                summary="Blocking and alerts increased",
                metrics={"blocking_count": 2, "alert_log_count": 2},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="Moderate pressure",
                metrics={"blocking_count": 0, "alert_log_count": 0},
            ),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)

        self.assertIsNotNone(context.state_transition)
        self.assertTrue(context.state_transition.available)
        self.assertEqual(context.state_transition.status_transition, "warning -> critical")
        self.assertEqual(context.state_transition.learning_features.status_delta, 1.0)
        self.assertIn(context.state_transition.learning_features.sql_regression_severity, {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})

    def test_blocker_appearance_is_primary_driver(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="WARNING",
                summary="New blockers",
                metrics={"blocking_count": 3, "alert_log_count": 0},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="No blockers",
                metrics={"blocking_count": 0, "alert_log_count": 0},
            ),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)

        self.assertTrue(
            any(driver.category == "residual_wait_pressure" for driver in context.state_transition.residual_warning_drivers)
        )
        self.assertTrue(
            any("blocking" in driver.title.lower() for driver in context.state_transition.residual_warning_drivers)
        )

    def test_sql_regression_detection_from_awr(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="WARNING",
                summary="SQL got slower",
                metrics={"top_cpu_sql_cpu_s": 240, "top_elapsed_sql_elapsed_s": 500},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="Baseline",
                metrics={"top_cpu_sql_cpu_s": 100, "top_elapsed_sql_elapsed_s": 200},
            ),
        ]
        awr_diff = AwrStateDiff(
            available=True,
            snapshot_quality=AwrSnapshotQuality(confidence="HIGH", coverage_quality="HIGH", comparability_score=0.9),
            time_model=AwrTimeModelState(sql_elapsed_spike_flag=True),
            sql_change=AwrSqlChangeIntelligence(sql_regression_flag=True),
        )

        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, [], "none")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)

        self.assertTrue(any(driver.driver_type == "sql_regression" for driver in context.state_transition.primary_drivers))
        self.assertTrue(context.state_transition.learning_features.sql_regression_flag)
        self.assertIn(context.state_transition.learning_features.sql_regression_severity, {"MEDIUM", "HIGH"})

    def test_wait_class_shift_features(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="WARNING",
                summary="Shifted to I/O waits",
                metrics={},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="CPU dominant",
                metrics={},
            ),
        ]
        awr_diff = AwrStateDiff(
            available=True,
            snapshot_quality=AwrSnapshotQuality(confidence="MEDIUM", coverage_quality="MEDIUM", comparability_score=0.6),
            wait_class_shift=AwrWaitClassShift(wait_class_shift_flag=True, cpu_to_io_shift=True),
            memory_state=AwrMemoryState(memory_pressure_flag=True),
        )
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, [], "none")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)

        self.assertTrue(context.state_transition.learning_features.wait_class_shift_flag)
        self.assertTrue(context.state_transition.learning_features.cpu_to_io_shift_flag)
        self.assertTrue(context.state_transition.learning_features.memory_pressure_flag)

    def test_missing_awr_is_graceful(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="WARNING",
                summary="Current",
                metrics={"top_elapsed_sql_elapsed_s": 450, "top_cpu_sql_cpu_s": 220},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="Previous",
                metrics={"top_elapsed_sql_elapsed_s": 100, "top_cpu_sql_cpu_s": 90},
            ),
        ]
        awr_diff = AwrStateDiff(available=False)
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, ["AWR unavailable"], "awr_unavailable")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)

        self.assertIsNotNone(context.state_transition.awr_state_diff)
        self.assertFalse(context.state_transition.awr_state_diff.available)
        self.assertTrue(any("AWR" in note for note in context.state_transition.coverage_notes))
        self.assertTrue(any(driver.driver_type == "sql_regression" for driver in context.state_transition.primary_drivers))
        self.assertIn(context.state_transition.confidence, {"MEDIUM", "HIGH"})

    def test_low_confidence_when_no_primary_drivers(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-21T01:00:00Z", status="OK", summary="Stable", metrics={}),
            _trace(run_id="r1", completed_at="2026-04-21T00:00:00Z", status="OK", summary="Stable", metrics={}),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)

        self.assertEqual(context.state_transition.confidence, "LOW")

    def test_formatter_renders_transition_sections(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="CRITICAL",
                summary="Current",
                metrics={"blocking_count": 2, "top_cpu_sql_cpu_s": 200, "top_elapsed_sql_elapsed_s": 450},
                issues=[HealthIssue(category="locking", title="Blocking Sessions", severity="CRITICAL", description="x")],
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="Previous",
                metrics={"blocking_count": 0, "top_cpu_sql_cpu_s": 100, "top_elapsed_sql_elapsed_s": 200},
                issues=[HealthIssue(category="locking", title="Blocking Sessions", severity="WARNING", description="x")],
            ),
        ]
        awr_diff = AwrStateDiff(
            available=True,
            snapshot_quality=AwrSnapshotQuality(confidence="HIGH", coverage_quality="HIGH", comparability_score=0.92),
            load_profile=[],
            wait_class_shift=AwrWaitClassShift(wait_class_shift_flag=True),
            sql_change=AwrSqlChangeIntelligence(dominant_sql_changed_flag=True),
            time_model=AwrTimeModelState(sql_elapsed_spike_flag=True),
        )
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, [], "none")),
        ):
            context: HistoryContext = JsonlHistoryService().compare_recent_runs(limit=2)

        answer = {
            "context": context,
            "series": [],
            "summary_lines": ["Example summary"],
            "state_transition": context.state_transition,
            "awr_state_diff": context.state_transition.awr_state_diff,
            "learning_features": context.state_transition.learning_features,
            "domain": "transition",
            "time_scope": {"label": "last 2 runs"},
        }
        rendered = render_history_answer(answer)

        expected_sections = [
            "History Source",
            "State Transition Summary",
            "Incident Drivers",
            "Persistent Background Risks",
            "Change Since Last Report",
            "AWR Workload Changes",
            "Wait Class Shift",
            "SQL Change Summary",
            "Event Timeline",
            "Learning Features",
            "Confidence + Coverage Notes",
            "Recurring Patterns",
        ]
        for section in expected_sections:
            self.assertIn(section, rendered)
        section_positions = [rendered.find(section) for section in expected_sections]
        self.assertTrue(all(pos >= 0 for pos in section_positions))
        self.assertEqual(section_positions, sorted(section_positions))

    def test_critical_to_warning_recovery_and_residual_split(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-22T02:48:26Z",
                status="WARNING",
                summary="Current",
                metrics={
                    "blocking_count": 0,
                    "active_sessions": 1,
                    "host_cpu_pct": 0.4,
                    "top_elapsed_sql_elapsed_s": 261.27,
                    "top_cpu_sql_cpu_s": 45.0,
                    "alert_log_count": 3,
                },
                issues=[HealthIssue(category="sql", title="SQL regression detected", severity="WARNING", description="x")],
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-22T02:25:07Z",
                status="CRITICAL",
                summary="Previous",
                metrics={
                    "blocking_count": 1,
                    "active_sessions": 2,
                    "host_cpu_pct": 19.01,
                    "top_elapsed_sql_elapsed_s": 73.7,
                    "top_cpu_sql_cpu_s": 52.0,
                    "alert_log_count": 2,
                },
                issues=[HealthIssue(category="locking", title="Blocking Sessions", severity="CRITICAL", description="x")],
            ),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)

        transition = context.state_transition
        self.assertEqual(transition.transition_outcome, "recovered")
        self.assertTrue(transition.recovery_detected)
        self.assertTrue(any(driver.category == "blocker_resolution" for driver in transition.recovery_drivers))
        self.assertTrue(any(driver.category == "sql_regression" for driver in transition.residual_warning_drivers))
        self.assertTrue(any(driver.category == "error_growth" for driver in transition.residual_warning_drivers))

    def test_formatter_orders_recovery_before_residual(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-22T02:48:26Z",
                status="WARNING",
                summary="Current",
                metrics={"blocking_count": 0, "top_elapsed_sql_elapsed_s": 261.27, "alert_log_count": 3},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-22T02:25:07Z",
                status="CRITICAL",
                summary="Previous",
                metrics={"blocking_count": 1, "top_elapsed_sql_elapsed_s": 73.7, "alert_log_count": 2},
            ),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)

        answer = {
            "context": context,
            "series": [],
            "summary_lines": ["Example summary"],
            "state_transition": context.state_transition,
            "awr_state_diff": context.state_transition.awr_state_diff,
            "learning_features": context.state_transition.learning_features,
        }
        rendered = render_history_answer(answer)
        self.assertLess(rendered.find("Recovery Drivers"), rendered.find("Residual Warning Drivers"))
        self.assertIn("Status improved to WARNING", rendered)

    def test_formatter_hides_raw_awr_exception_and_shows_user_message(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="WARNING",
                summary="Current",
                metrics={"top_elapsed_sql_elapsed_s": 450, "top_cpu_sql_cpu_s": 220},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="Previous",
                metrics={"top_elapsed_sql_elapsed_s": 100, "top_cpu_sql_cpu_s": 90},
            ),
        ]
        raw_exception = "'>=' not supported between instances of 'NoneType' and 'float'"
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(
                JsonlHistoryService,
                "_build_optional_awr_diff",
                return_value=(
                    None,
                    ["AWR workload comparison unavailable due to incomplete AWR metric data; JSONL fallback used."],
                    "awr_runtime_failure",
                    raw_exception,
                ),
            ),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        rendered = render_history_answer({"context": context, "state_transition": context.state_transition, "summary_lines": []})
        self.assertIn("AWR workload comparison unavailable due to incomplete AWR metric data; JSONL fallback used.", rendered)
        self.assertNotIn(raw_exception, rendered)

    def test_event_timeline_reflects_recovery_wording(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-22T02:48:26Z",
                status="WARNING",
                summary="Current",
                metrics={"blocking_count": 0, "top_elapsed_sql_elapsed_s": 261.27, "alert_log_count": 3},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-22T02:25:07Z",
                status="CRITICAL",
                summary="Previous",
                metrics={"blocking_count": 1, "top_elapsed_sql_elapsed_s": 73.7, "alert_log_count": 2},
            ),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        current_timeline_summary = context.state_transition.event_timeline_entries[-1].summary
        self.assertIn("Status improved to WARNING", current_timeline_summary)

    def test_no_generic_other_driver_message(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="CRITICAL",
                summary="Current",
                metrics={"blocking_count": 2, "alert_log_count": 1, "top_elapsed_sql_elapsed_s": 450},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="Previous",
                metrics={"blocking_count": 0, "alert_log_count": 0, "top_elapsed_sql_elapsed_s": 100},
            ),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        self.assertTrue(all(driver.driver_type != "other" for driver in context.state_transition.primary_drivers))
        self.assertTrue(all("worsened (other)" not in driver.name.lower() for driver in context.state_transition.primary_drivers))

    def test_metric_trend_classification_semantic(self) -> None:
        traces = [
            _trace(
                run_id="r3",
                completed_at="2026-04-21T02:00:00Z",
                status="WARNING",
                summary="current",
                metrics={"blocking_count": 3},
            ),
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="WARNING",
                summary="middle",
                metrics={"blocking_count": 1},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="OK",
                summary="previous",
                metrics={"blocking_count": 1},
            ),
        ]
        with patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces):
            context = JsonlHistoryService().compare_recent_runs(limit=3)
        trend = next((item for item in context.trend_summaries if item.metric_name == "Blocking Sessions"), None)
        self.assertIsNotNone(trend)
        self.assertIn(
            trend.direction,
            {
                "newly_present",
                "no_longer_present",
                "increased",
                "decreased",
                "unchanged",
                "persistent_nonzero",
                "persistent_high",
                "persistent_low",
                "worsened",
                "improved",
                "missing_data",
            },
        )

    def test_one_to_one_metric_is_persistent_nonzero(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="WARNING",
                summary="current",
                metrics={"blocking_count": 1},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="previous",
                metrics={"blocking_count": 1},
            ),
        ]
        with patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        blocking_metric = next((row for row in context.state_transition.metric_deltas if row.metric_name == "Blocking Sessions"), None)
        self.assertIsNotNone(blocking_metric)
        self.assertEqual(blocking_metric.state_label, "persistent_nonzero")

    def test_critical_to_critical_internal_worsening_flag(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="CRITICAL",
                summary="current",
                metrics={"blocking_count": 1, "top_elapsed_sql_elapsed_s": 600},
                issues=[HealthIssue(category="locking", title="Blocking Sessions", severity="CRITICAL", description="x")],
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="CRITICAL",
                summary="previous",
                metrics={"blocking_count": 1, "top_elapsed_sql_elapsed_s": 120},
                issues=[HealthIssue(category="locking", title="Blocking Sessions", severity="CRITICAL", description="x")],
            ),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        self.assertTrue(context.state_transition.learning_features.state_persisted_but_worsened_flag)
        self.assertTrue(context.state_transition.learning_features.persistent_issue_with_higher_impact_flag)

    def test_window_based_comparison_metadata(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-21T00:10:00Z", status="WARNING", summary="current", metrics={}),
            _trace(run_id="r1", completed_at="2026-04-21T00:00:00Z", status="WARNING", summary="previous", metrics={}),
        ]
        with patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        self.assertIsNotNone(context.state_transition.comparison_window)
        self.assertIsNotNone(context.state_transition.comparison_window.window_start)
        self.assertIsNotNone(context.state_transition.comparison_window.window_end)
        self.assertGreater(context.state_transition.comparison_window.window_duration_minutes or 0, 0)

    def test_confidence_reason_populated(self) -> None:
        traces = [
            _trace(
                run_id="r2",
                completed_at="2026-04-21T01:00:00Z",
                status="WARNING",
                summary="current",
                metrics={"top_elapsed_sql_elapsed_s": 450, "top_cpu_sql_cpu_s": 120},
            ),
            _trace(
                run_id="r1",
                completed_at="2026-04-21T00:00:00Z",
                status="WARNING",
                summary="previous",
                metrics={"top_elapsed_sql_elapsed_s": 100, "top_cpu_sql_cpu_s": 90},
            ),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(None, ["AWR runtime failure"], "awr_runtime_failure")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        self.assertTrue(context.state_transition.historical_confidence.confidence_reason)
        self.assertEqual(context.state_transition.historical_confidence.fallback_mode, "awr_runtime_failure")

    def test_awr_workload_section_includes_previous_current_delta_significance(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T03:59:00Z", status="WARNING", summary="current"),
            _trace(run_id="r1", completed_at="2026-04-22T02:48:00Z", status="WARNING", summary="previous"),
        ]
        awr_diff = AwrStateDiff(
            available=True,
            snapshot_quality=AwrSnapshotQuality(confidence="MEDIUM", coverage_quality="MEDIUM", comparability_score=0.7),
            workload_metrics=[
                AwrMetricDelta(
                    metric_name="DB Time",
                    previous_value=120.4,
                    current_value=143.9,
                    delta_value=23.5,
                    percent_delta=19.5,
                    significance="MEDIUM",
                    interpretation="DB Time increased by 19.50% (MEDIUM).",
                ),
                AwrMetricDelta(
                    metric_name="Hard Parses",
                    previous_value=12.0,
                    current_value=None,
                    delta_value=None,
                    percent_delta=None,
                    significance="LOW",
                    interpretation="Hard Parses was partially available; comparison confidence is limited.",
                ),
            ],
        )
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, [], "none")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        rendered = render_history_answer({"context": context, "state_transition": context.state_transition, "summary_lines": []})
        self.assertIn("DB Time", rendered)
        self.assertIn("120.4", rendered)
        self.assertIn("143.9", rendered)
        self.assertIn("+23.50", rendered)
        self.assertIn("+19.50%", rendered)
        self.assertIn("MEDIUM", rendered)
        self.assertIn("Hard Parses", rendered)
        self.assertIn("Hard Parses was partial", rendered)

    def test_wait_class_shift_section_includes_dominant_and_top_events(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T03:59:00Z", status="WARNING", summary="current"),
            _trace(run_id="r1", completed_at="2026-04-22T02:48:00Z", status="WARNING", summary="previous"),
        ]
        awr_diff = AwrStateDiff(
            available=True,
            wait_shift_summary=AwrWaitShiftSummary(
                previous_dominant_wait_class="User I/O",
                current_dominant_wait_class="User I/O",
                previous_top_event="db file sequential read",
                current_top_event="db file sequential read",
                wait_class_shift_flag=False,
                cpu_to_io_shift=False,
                cpu_to_concurrency_shift=False,
                interpretation="No material wait-class shift detected.",
            ),
        )
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, [], "none")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        rendered = render_history_answer({"context": context, "state_transition": context.state_transition, "summary_lines": []})
        self.assertIn("previous_dominant_wait_class", rendered)
        self.assertIn("current_dominant_wait_class", rendered)
        self.assertIn("db file sequential read", rendered)
        self.assertIn("No material wait-class", rendered)

    def test_sql_change_summary_includes_richer_context(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T03:59:00Z", status="WARNING", summary="current"),
            _trace(run_id="r1", completed_at="2026-04-22T02:48:00Z", status="WARNING", summary="previous"),
        ]
        awr_diff = AwrStateDiff(
            available=True,
            sql_change_summary=AwrSqlChangeSummary(
                dominant_sql_id_previous="bd1s1g2dc3w14",
                dominant_sql_id_current="b39m8n96gxk7c",
                dominant_sql_schema_previous="DEVA1",
                dominant_sql_schema_current="DEVA1",
                dominant_sql_module_previous="APP_A",
                dominant_sql_module_current="APP_B",
                dominant_sql_class_previous="app_sql",
                dominant_sql_class_current="app_sql",
                sql_regression_flag=True,
                sql_regression_severity="LOW",
                plan_hash_changed_flag=False,
                elapsed_per_exec_spike=True,
                cpu_per_exec_spike=False,
                interpretation="Dominant SQL shifted and regression stayed LOW without plan-hash change.",
            ),
        )
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, [], "none")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        rendered = render_history_answer({"context": context, "state_transition": context.state_transition, "summary_lines": []})
        self.assertIn("dominant_sql_schema_previous", rendered)
        self.assertIn("dominant_sql_module_current", rendered)
        self.assertIn("sql_regression_severity", rendered)
        self.assertIn("LOW", rendered)
        self.assertIn("Dominant SQL shifted", rendered)

    def test_section_naming_changes_by_transition_outcome(self) -> None:
        worsened_traces = [
            _trace(run_id="r2", completed_at="2026-04-22T03:59:00Z", status="CRITICAL", summary="current", metrics={"blocking_count": 1}),
            _trace(run_id="r1", completed_at="2026-04-22T02:48:00Z", status="WARNING", summary="previous", metrics={"blocking_count": 0}),
        ]
        improved_traces = [
            _trace(run_id="r2", completed_at="2026-04-22T03:59:00Z", status="WARNING", summary="current", metrics={"blocking_count": 0}),
            _trace(run_id="r1", completed_at="2026-04-22T02:48:00Z", status="CRITICAL", summary="previous", metrics={"blocking_count": 1}),
        ]
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=worsened_traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            worsened_context = JsonlHistoryService().compare_recent_runs(limit=2)
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=improved_traces),
            patch.dict(os.environ, {"ODB_AUTODBA_ENABLE_AWR_HISTORY": "false"}, clear=False),
        ):
            improved_context = JsonlHistoryService().compare_recent_runs(limit=2)
        worsened_rendered = render_history_answer({"context": worsened_context, "state_transition": worsened_context.state_transition, "summary_lines": []})
        improved_rendered = render_history_answer({"context": improved_context, "state_transition": improved_context.state_transition, "summary_lines": []})
        self.assertIn("Incident Drivers", worsened_rendered)
        self.assertIn("Persistent Background Risks", worsened_rendered)
        self.assertIn("Recovery Drivers", improved_rendered)
        self.assertIn("Residual Warning Drivers", improved_rendered)

    def test_event_timeline_uses_worsened_wording_with_mild_awr(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T03:59:00Z", status="CRITICAL", summary="current", metrics={"blocking_count": 1}),
            _trace(run_id="r1", completed_at="2026-04-22T02:48:00Z", status="WARNING", summary="previous", metrics={"blocking_count": 0}),
        ]
        awr_diff = AwrStateDiff(
            available=True,
            workload_interpretation={
                "summary": "AWR workload deltas were mostly LOW significance.",
                "material_change_detected": False,
                "low_significance_majority": True,
            },
        )
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, [], "none")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        current_timeline_summary = context.state_transition.event_timeline_entries[-1].summary
        self.assertIn("Status worsened to CRITICAL", current_timeline_summary)
        self.assertIn("AWR workload deltas were mild", current_timeline_summary)

    def test_confidence_notes_render_snap_windows_concisely(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T03:59:00Z", status="WARNING", summary="current"),
            _trace(run_id="r1", completed_at="2026-04-22T02:48:00Z", status="WARNING", summary="previous"),
        ]
        awr_diff = AwrStateDiff(
            available=True,
            snapshot_quality=AwrSnapshotQuality(confidence="MEDIUM", coverage_quality="MEDIUM", comparability_score=0.7),
            window_mapping=AwrRunPairWindowMapping(
                previous=AwrSnapshotWindowMapping(begin_snap_id=210, end_snap_id=211),
                current=AwrSnapshotWindowMapping(begin_snap_id=211, end_snap_id=212),
            ),
        )
        with (
            patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
            patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(awr_diff, [], "none")),
        ):
            context = JsonlHistoryService().compare_recent_runs(limit=2)
        rendered = render_history_answer({"context": context, "state_transition": context.state_transition, "summary_lines": []})
        self.assertIn("Previous window: SNAP 210..211", rendered)
        self.assertIn("Current window: SNAP 211..212", rendered)
        self.assertEqual(rendered.count("Previous window: SNAP 210..211"), 1)
        self.assertEqual(rendered.count("Current window: SNAP 211..212"), 1)


class HistorySourceTransparencyTests(unittest.TestCase):
    def _index_paths(self, root: Path) -> dict[str, Path]:
        return {
            "health_runs": root / "health_runs.jsonl",
            "trace_chunks": root / "trace_chunks.jsonl",
            "recurring_issues": root / "recurring_issues.jsonl",
            "database_behavior_profiles": root / "database_behavior_profiles.jsonl",
            "history_indexing": root / "history_indexing.jsonl",
        }

    def test_history_answer_reports_raw_jsonl_when_indexes_missing(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T02:00:00Z", status="WARNING", summary="current"),
            _trace(run_id="r1", completed_at="2026-04-21T02:00:00Z", status="WARNING", summary="previous"),
        ]
        with tempfile.TemporaryDirectory() as td:
            paths = self._index_paths(Path(td))
            with (
                patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
                patch("odb_autodba.history.jsonl_service.history_data_source_paths", return_value=paths),
                patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(None, ["AWR disabled"], "awr_disabled")),
            ):
                answer = JsonlHistoryService().answer_history_question_from_jsonl(user_query="show trends", database_name="FREE")

        self.assertEqual(answer["history_source_used"], "raw JSONL only")
        self.assertEqual(answer["recurrence_computation_mode"], "raw_scan")
        self.assertEqual(answer["history_index_status"], "missing")
        self.assertIn("raw health_runs.jsonl", " ".join(answer["history_index_notes"]))

    def test_history_answer_uses_indexed_recurrence_when_available_and_fresh(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T02:25:00Z", status="CRITICAL", summary="current"),
            _trace(run_id="r1", completed_at="2026-04-21T02:25:00Z", status="WARNING", summary="previous"),
        ]
        recurring = [
            RecurringIssueIndexRecord(
                fingerprint="oracle:test123",
                database_name="FREE",
                category="blocking",
                title="Blocking locks detected",
                severity="CRITICAL",
                first_seen="2026-04-21T02:25:00Z",
                last_seen="2026-04-22T02:25:00Z",
                run_count=2,
                unhealthy_run_count=2,
            )
        ]
        with tempfile.TemporaryDirectory() as td:
            paths = self._index_paths(Path(td))
            paths["recurring_issues"].write_text("{}", encoding="utf-8")
            with (
                patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
                patch("odb_autodba.history.jsonl_service.history_data_source_paths", return_value=paths),
                patch("odb_autodba.history.jsonl_service.read_recurring_issue_index", return_value=recurring),
                patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(None, ["AWR disabled"], "awr_disabled")),
            ):
                answer = JsonlHistoryService().answer_history_question_from_jsonl(user_query="show trends", database_name="FREE")

        self.assertEqual(answer["recurrence_computation_mode"], "indexed")
        self.assertEqual(answer["history_source_used"], "indexed recurrence + raw run metrics")
        self.assertIn("recurring_issues", answer["index_usage_summary"])
        self.assertTrue(any("Blocking locks detected recurred in 2/2" in line for line in answer["context"].recurring_findings))

    def test_stale_index_detection_and_rebuild_flag(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T03:00:00Z", status="CRITICAL", summary="current"),
            _trace(run_id="r1", completed_at="2026-04-21T03:00:00Z", status="WARNING", summary="previous"),
        ]
        recurring = [
            RecurringIssueIndexRecord(
                fingerprint="oracle:test456",
                database_name="FREE",
                category="blocking",
                title="Blocking locks detected",
                severity="CRITICAL",
                first_seen="2026-04-20T03:00:00Z",
                last_seen="2026-04-21T03:00:00Z",
                run_count=5,
                unhealthy_run_count=5,
            )
        ]
        with tempfile.TemporaryDirectory() as td:
            paths = self._index_paths(Path(td))
            paths["recurring_issues"].write_text("{}", encoding="utf-8")
            with (
                patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
                patch("odb_autodba.history.jsonl_service.history_data_source_paths", return_value=paths),
                patch("odb_autodba.history.jsonl_service.read_recurring_issue_index", return_value=recurring),
                patch("odb_autodba.history.jsonl_service.rebuild_planner_memory_artifacts", return_value={}),
                patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(None, ["AWR disabled"], "awr_disabled")),
            ):
                answer = JsonlHistoryService().answer_history_question_from_jsonl(user_query="show trends", database_name="FREE")

        self.assertEqual(answer["history_index_freshness"], "stale")
        self.assertEqual(answer["history_index_status"], "stale")
        self.assertTrue(answer["history_index_rebuilt"])
        self.assertEqual(answer["recurrence_computation_mode"], "raw_scan")

    def test_formatter_displays_history_source_note_and_structured_mode(self) -> None:
        traces = [
            _trace(run_id="r2", completed_at="2026-04-22T02:00:00Z", status="WARNING", summary="current"),
            _trace(run_id="r1", completed_at="2026-04-21T02:00:00Z", status="WARNING", summary="previous"),
        ]
        with tempfile.TemporaryDirectory() as td:
            paths = self._index_paths(Path(td))
            with (
                patch("odb_autodba.history.jsonl_service.read_health_run_traces", return_value=traces),
                patch("odb_autodba.history.jsonl_service.history_data_source_paths", return_value=paths),
                patch.object(JsonlHistoryService, "_build_optional_awr_diff", return_value=(None, ["AWR disabled"], "awr_disabled")),
            ):
                answer = JsonlHistoryService().answer_history_question_from_jsonl(user_query="show trends", database_name="FREE")
        rendered = render_history_answer(answer)
        self.assertIn("History source:", rendered)
        self.assertIn("recurrence_mode=", " ".join(answer.get("summary_lines") or []))


if __name__ == "__main__":
    unittest.main()
