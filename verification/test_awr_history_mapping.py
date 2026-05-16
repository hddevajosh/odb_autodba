from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.db import awr_checks as awr_mod
from odb_autodba.db.awr_checks import (
    build_awr_state_diff,
    generate_awr_report_text,
    map_run_pair_to_awr_windows,
    map_run_to_snapshot_window,
    summarize_awr_report_text,
)
from odb_autodba.models.schemas import (
    AwrCapabilities,
    AwrHostCpuState,
    AwrIoProfileState,
    AwrMemoryState,
    AwrMetricDiff,
    AwrRunPairWindowMapping,
    AwrSnapshotWindowMapping,
    AwrSqlChangeIntelligence,
    AwrTimeModelState,
    AwrWaitClassShift,
)


def _snapshot_rows() -> list[dict]:
    return [
        {"dbid": 1234, "snap_id": 210, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T02:04:00", "end_time": "2026-04-22T02:14:00"},
        {"dbid": 1234, "snap_id": 210, "instance_number": 2, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T02:04:00", "end_time": "2026-04-22T02:14:00"},
        {"dbid": 1234, "snap_id": 211, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T02:14:00", "end_time": "2026-04-22T03:00:00"},
        {"dbid": 1234, "snap_id": 211, "instance_number": 2, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T02:14:00", "end_time": "2026-04-22T03:00:00"},
        {"dbid": 1234, "snap_id": 212, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T03:00:00", "end_time": "2026-04-22T04:00:00"},
        {"dbid": 1234, "snap_id": 212, "instance_number": 2, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T03:00:00", "end_time": "2026-04-22T04:00:00"},
    ]


class AwrHistoryMappingTests(unittest.TestCase):
    def test_awr_report_text_generation_and_summary(self) -> None:
        awr_text_rows = [
            {"output": "Load Profile"},
            {"output": "DB Time(s): 120.0"},
            {"output": "DB CPU(s): 75.0"},
            {"output": "Top 10 Foreground Events"},
            {"output": "enq: TX - row lock contention  11234"},
            {"output": "SQL ordered by CPU Time"},
            {"output": "3nkd7x4r8w1pb  95.3"},
        ]
        with patch("odb_autodba.db.awr_checks.fetch_all", return_value=awr_text_rows):
            lines = generate_awr_report_text(dbid=1234, begin_snap_id=211, end_snap_id=212, instance_number=1)
        self.assertTrue(any("DB Time" in line for line in lines))
        summary = summarize_awr_report_text(
            lines,
            dbid=1234,
            instance_number=1,
            begin_snap_id=211,
            end_snap_id=212,
        )
        self.assertTrue(summary.available)
        self.assertTrue(any("DB Time" in line for line in summary.load_profile_summary))
        self.assertTrue(any("enq: tx" in line.lower() for line in summary.main_bottlenecks))
        self.assertTrue(summary.sql_contributors)
        joined = "\n".join(summary.load_profile_summary + summary.main_bottlenecks + summary.sql_contributors)
        self.assertIn("workload", joined)
        self.assertIn("application/concurrency wait", joined)
        self.assertIn("SQL_ID: 3nkd7x4r8w1pb", joined)
        self.assertNotIn("SQL ordered by", joined)

    def test_duplicate_snapshot_rows_are_aggregated_per_snap_id(self) -> None:
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=_snapshot_rows()),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapped = map_run_to_snapshot_window("2026-04-22T02:25:00Z", dbid=1234)
        self.assertEqual(mapped.matched_snap_id, 211)
        self.assertEqual(mapped.instance_count, 1)
        self.assertEqual(mapped.instance_rows_found, 1)
        self.assertEqual(mapped.instance_number, 1)
        self.assertEqual(mapped.mapping_quality, "HIGH")

    def test_run_timestamp_maps_into_enclosing_snapshot_interval(self) -> None:
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=_snapshot_rows()),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapped = map_run_to_snapshot_window("2026-04-22T03:59:00Z", dbid=1234)
        self.assertEqual(mapped.matched_snap_id, 212)
        self.assertEqual(mapped.end_snap_id, 212)
        self.assertEqual(mapped.matched_begin_time, "2026-04-22T03:00:00")
        self.assertEqual(mapped.matched_end_time, "2026-04-22T04:00:00")

    def test_map_run_pair_debug_includes_selected_snapshots(self) -> None:
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=_snapshot_rows()),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapping = map_run_pair_to_awr_windows(
                "2026-04-22T02:48:00Z",
                "2026-04-22T03:59:00Z",
                dbid=1234,
                previous_window_start="2026-04-22T02:20:00Z",
                previous_window_end="2026-04-22T02:48:00Z",
                current_window_start="2026-04-22T03:30:00Z",
                current_window_end="2026-04-22T03:59:00Z",
            )
        self.assertEqual(mapping.debug.get("mapped_previous_snap"), 211)
        self.assertEqual(mapping.debug.get("mapped_current_snap"), 212)
        self.assertFalse(bool(mapping.debug.get("same_snap_selected")))
        self.assertIn("previous_run_timestamp", mapping.debug)
        self.assertIn("current_run_timestamp", mapping.debug)

    def test_duplicate_chain_selection_prefers_current_dbid_instance_startup(self) -> None:
        rows = [
            {"dbid": 1234, "snap_id": 3, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T02:00:00", "end_time": "2026-04-22T03:00:00"},
            {"dbid": 1234, "snap_id": 15, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T03:00:00", "end_time": "2026-04-22T04:00:00"},
            {"dbid": 9999, "snap_id": 278, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T02:00:00", "end_time": "2026-04-22T03:00:00"},
            {"dbid": 9999, "snap_id": 290, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T03:00:00", "end_time": "2026-04-22T04:00:00"},
        ]
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapped = map_run_to_snapshot_window("2026-04-22T03:30:00Z", dbid=1234)
        self.assertEqual(mapped.dbid, 1234)
        self.assertIn("Selected snapshot chain DBID=1234", " ".join(mapped.notes))

    def test_same_snap_uses_adjacent_intervals_for_structured_comparison(self) -> None:
        rows = [
            {"dbid": 1234, "snap_id": 296, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T06:00:00", "end_time": "2026-04-22T07:00:00"},
            {"dbid": 1234, "snap_id": 297, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T07:00:00", "end_time": "2026-04-22T08:00:00"},
            {"dbid": 1234, "snap_id": 298, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T08:00:00", "end_time": "2026-04-22T09:00:00"},
        ]
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapping = map_run_pair_to_awr_windows(
                "2026-04-22T08:42:00Z",
                "2026-04-22T08:55:00Z",
                dbid=1234,
                previous_window_start="2026-04-22T08:30:00Z",
                previous_window_end="2026-04-22T08:42:00Z",
                current_window_start="2026-04-22T08:50:00Z",
                current_window_end="2026-04-22T08:55:00Z",
            )
        self.assertTrue(bool(mapping.debug.get("same_snap_adjacent_interval_mode")))
        self.assertEqual((mapping.previous.begin_snap_id, mapping.previous.end_snap_id), (296, 297))
        self.assertEqual((mapping.current.begin_snap_id, mapping.current.end_snap_id), (297, 298))
        self.assertGreaterEqual(mapping.comparability_score, 0.6)
        self.assertTrue(any("adjacent completed awr intervals" in note.lower() for note in mapping.notes))

    def test_mixed_snap_mapping_uses_expected_adjacent_delta_windows(self) -> None:
        rows = [
            {"dbid": 1234, "snap_id": 296, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T06:00:00", "end_time": "2026-04-22T07:00:00"},
            {"dbid": 1234, "snap_id": 297, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T07:00:00", "end_time": "2026-04-22T08:00:00"},
            {"dbid": 1234, "snap_id": 298, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T08:00:00", "end_time": "2026-04-22T09:00:00"},
        ]
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapping = map_run_pair_to_awr_windows(
                "2026-04-22T08:02:00Z",
                "2026-04-22T09:05:00Z",
                dbid=1234,
                previous_window_start="2026-04-22T07:50:00Z",
                previous_window_end="2026-04-22T08:02:00Z",
                current_window_start="2026-04-22T08:55:00Z",
                current_window_end="2026-04-22T09:05:00Z",
            )
        self.assertEqual((mapping.previous.begin_snap_id, mapping.previous.end_snap_id), (296, 297))
        self.assertEqual((mapping.current.begin_snap_id, mapping.current.end_snap_id), (297, 298))

    def test_partial_metric_availability_still_produces_awr_diff(self) -> None:
        mapping = AwrRunPairWindowMapping(
            previous=AwrSnapshotWindowMapping(
                dbid=1234,
                begin_snap_id=210,
                end_snap_id=211,
                matched_snap_id=211,
                begin_time="2026-04-22T02:04:00",
                end_time="2026-04-22T03:00:00",
                matched_begin_time="2026-04-22T02:14:00",
                matched_end_time="2026-04-22T03:00:00",
                instance_count=2,
                instance_rows_found=2,
                mapping_quality="HIGH",
            ),
            current=AwrSnapshotWindowMapping(
                dbid=1234,
                begin_snap_id=211,
                end_snap_id=212,
                matched_snap_id=212,
                begin_time="2026-04-22T02:14:00",
                end_time="2026-04-22T04:00:00",
                matched_begin_time="2026-04-22T03:00:00",
                matched_end_time="2026-04-22T04:00:00",
                instance_count=2,
                instance_rows_found=2,
                mapping_quality="HIGH",
            ),
            comparability_score=0.82,
            confidence="HIGH",
            debug={"mapped_previous_snap": 211, "mapped_current_snap": 212, "same_snap_selected": False},
        )
        caps = AwrCapabilities(available=True, ash_available=True, dbid=1234, missing_components=[])
        with (
            patch("odb_autodba.db.awr_checks._collect_load_profile", side_effect=[{}, {}]),
            patch("odb_autodba.db.awr_checks._build_wait_class_shift", return_value=AwrWaitClassShift()),
            patch("odb_autodba.db.awr_checks._build_time_model_state", return_value=AwrTimeModelState()),
            patch("odb_autodba.db.awr_checks._build_host_cpu_state", return_value=AwrHostCpuState()),
            patch("odb_autodba.db.awr_checks._build_io_profile_state", return_value=AwrIoProfileState()),
            patch("odb_autodba.db.awr_checks._build_memory_state", return_value=AwrMemoryState()),
            patch("odb_autodba.db.awr_checks._build_sql_change_intel", return_value=AwrSqlChangeIntelligence()),
            patch(
                "odb_autodba.db.awr_checks.get_ash_window_state",
                return_value={"source": None, "notes": [], "top_sql": [], "wait_profile": [], "blocking": [], "aas_proxy": None},
            ),
        ):
            diff = build_awr_state_diff(window_mapping=mapping, capabilities=caps)
        self.assertTrue(diff.available)
        self.assertIn(diff.snapshot_quality.coverage_quality, {"LOW", "NONE"})
        self.assertTrue(any("metric rows were incomplete" in note.lower() for note in diff.notes))

    def test_identical_snapshot_windows_set_single_window_awr_mode(self) -> None:
        mapping = AwrRunPairWindowMapping(
            previous=AwrSnapshotWindowMapping(dbid=1234, begin_snap_id=216, end_snap_id=217, mapping_quality="MEDIUM"),
            current=AwrSnapshotWindowMapping(dbid=1234, begin_snap_id=216, end_snap_id=217, mapping_quality="MEDIUM"),
            comparability_score=0.4,
            confidence="LOW",
        )
        caps = AwrCapabilities(available=True, ash_available=True, dbid=1234, missing_components=[])
        with (
            patch("odb_autodba.db.awr_checks._collect_load_profile", side_effect=[{}, {}]),
            patch("odb_autodba.db.awr_checks._build_wait_class_shift", return_value=AwrWaitClassShift()),
            patch("odb_autodba.db.awr_checks._build_time_model_state", return_value=AwrTimeModelState()),
            patch("odb_autodba.db.awr_checks._build_host_cpu_state", return_value=AwrHostCpuState()),
            patch("odb_autodba.db.awr_checks._build_io_profile_state", return_value=AwrIoProfileState()),
            patch("odb_autodba.db.awr_checks._build_memory_state", return_value=AwrMemoryState()),
            patch("odb_autodba.db.awr_checks._build_sql_change_intel", return_value=AwrSqlChangeIntelligence()),
            patch(
                "odb_autodba.db.awr_checks.get_ash_window_state",
                return_value={"source": None, "notes": [], "top_sql": [], "wait_profile": [], "blocking": [], "aas_proxy": None},
            ),
        ):
            diff = build_awr_state_diff(window_mapping=mapping, capabilities=caps)
        self.assertEqual(diff.awr_mode, "single_window_interpretation")
        self.assertEqual(diff.snapshot_quality.window_quality, "LOW")
        self.assertEqual(diff.snapshot_quality.usage, "context_only")

    def test_window_quality_low_when_dbid_differs(self) -> None:
        mapping = AwrRunPairWindowMapping(
            previous=AwrSnapshotWindowMapping(dbid=1234, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=210, end_snap_id=211, mapping_quality="HIGH"),
            current=AwrSnapshotWindowMapping(dbid=9999, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=211, end_snap_id=212, mapping_quality="HIGH"),
            comparability_score=0.8,
            confidence="HIGH",
        )
        diff = build_awr_state_diff(window_mapping=mapping, capabilities=AwrCapabilities(available=True, ash_available=True, dbid=1234))
        self.assertEqual(diff.snapshot_quality.window_quality, "LOW")
        self.assertIn("different DBID", diff.snapshot_quality.reason)
        self.assertEqual(diff.snapshot_quality.usage, "context_only")

    def test_window_quality_low_when_instance_differs(self) -> None:
        mapping = AwrRunPairWindowMapping(
            previous=AwrSnapshotWindowMapping(dbid=1234, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=210, end_snap_id=211, mapping_quality="HIGH"),
            current=AwrSnapshotWindowMapping(dbid=1234, instance_number=2, startup_time="2026-04-22T00:00:00", begin_snap_id=211, end_snap_id=212, mapping_quality="HIGH"),
            comparability_score=0.8,
            confidence="HIGH",
        )
        diff = build_awr_state_diff(window_mapping=mapping, capabilities=AwrCapabilities(available=True, ash_available=True, dbid=1234))
        self.assertEqual(diff.snapshot_quality.window_quality, "LOW")
        self.assertEqual(diff.snapshot_quality.usage, "context_only")

    def test_only_one_snapshot_results_in_single_window_context(self) -> None:
        rows = [
            {"dbid": 1234, "snap_id": 298, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T08:00:00", "end_time": "2026-04-22T09:00:00"},
        ]
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapping = map_run_pair_to_awr_windows(
                "2026-04-22T08:40:00Z",
                "2026-04-22T09:05:00Z",
                dbid=1234,
                previous_window_start="2026-04-22T08:30:00Z",
                previous_window_end="2026-04-22T08:40:00Z",
                current_window_start="2026-04-22T08:55:00Z",
                current_window_end="2026-04-22T09:05:00Z",
            )
        self.assertEqual((mapping.current.begin_snap_id, mapping.current.end_snap_id), (298, 298))
        self.assertEqual(mapping.current.mapping_quality, "LOW")
        self.assertEqual(mapping.current.window_use, "context_only")
        self.assertIsNone(mapping.previous.begin_snap_id)
        self.assertIn("missing", (mapping.previous.window_reason or "").lower())

    def test_begin_equals_end_only_when_no_adjacent_snapshot_exists(self) -> None:
        rows_with_adjacent = [
            {"dbid": 1234, "snap_id": 297, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T07:00:00", "end_time": "2026-04-22T08:00:00"},
            {"dbid": 1234, "snap_id": 298, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T08:00:00", "end_time": "2026-04-22T09:00:00"},
        ]
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows_with_adjacent),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapped = map_run_to_snapshot_window("2026-04-22T09:05:00Z", dbid=1234)
        self.assertLess(mapped.begin_snap_id or 0, mapped.end_snap_id or 0)

        rows_without_adjacent = [
            {"dbid": 1234, "snap_id": 298, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T08:00:00", "end_time": "2026-04-22T09:00:00"},
        ]
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows_without_adjacent),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapped2 = map_run_to_snapshot_window("2026-04-22T09:05:00Z", dbid=1234)
        self.assertEqual((mapped2.begin_snap_id, mapped2.end_snap_id), (298, 298))

    def test_successful_211_to_212_style_comparison_populates_minimum_sections(self) -> None:
        mapping = AwrRunPairWindowMapping(
            previous=AwrSnapshotWindowMapping(
                dbid=1234,
                begin_snap_id=210,
                end_snap_id=211,
                matched_snap_id=211,
                begin_time="2026-04-22T02:04:00",
                end_time="2026-04-22T03:00:00",
                matched_begin_time="2026-04-22T02:14:00",
                matched_end_time="2026-04-22T03:00:00",
                instance_count=2,
                instance_rows_found=2,
                mapping_quality="HIGH",
            ),
            current=AwrSnapshotWindowMapping(
                dbid=1234,
                begin_snap_id=211,
                end_snap_id=212,
                matched_snap_id=212,
                begin_time="2026-04-22T02:14:00",
                end_time="2026-04-22T04:00:00",
                matched_begin_time="2026-04-22T03:00:00",
                matched_end_time="2026-04-22T04:00:00",
                instance_count=2,
                instance_rows_found=2,
                mapping_quality="HIGH",
            ),
            comparability_score=0.91,
            confidence="HIGH",
            debug={"mapped_previous_snap": 211, "mapped_current_snap": 212, "same_snap_selected": False},
        )
        caps = AwrCapabilities(available=True, ash_available=True, dbid=1234, missing_components=[])
        load_prev = {"DB Time": 110.0, "DB CPU": 55.0, "Parses": 100.0}
        load_curr = {"DB Time": 160.0, "DB CPU": 75.0, "Parses": 140.0}
        wait_shift = AwrWaitClassShift(
            top_foreground_events_previous=[{"event_name": "db file sequential read"}],
            top_foreground_events_current=[{"event_name": "log file sync"}],
            dominant_wait_class_previous="User I/O",
            dominant_wait_class_current="Commit",
            wait_class_shift_flag=True,
        )
        sql_change = AwrSqlChangeIntelligence(
            top_sql_by_elapsed_previous=[{"sql_id": "abc"}],
            top_sql_by_elapsed_current=[{"sql_id": "xyz"}],
            dominant_sql_id_previous="abc",
            dominant_sql_id_current="xyz",
            dominant_sql_changed_flag=True,
            sql_regression_flag=True,
            elapsed_per_exec_spike=True,
        )
        with (
            patch("odb_autodba.db.awr_checks._collect_load_profile", side_effect=[load_prev, load_curr]),
            patch("odb_autodba.db.awr_checks._build_wait_class_shift", return_value=wait_shift),
            patch(
                "odb_autodba.db.awr_checks._build_time_model_state",
                return_value=AwrTimeModelState(
                    metrics=[AwrMetricDiff(metric_name="DB time", previous=110.0, current=160.0, delta=50.0, pct_change=45.45, significance="HIGH")],
                    sql_elapsed_spike_flag=True,
                ),
            ),
            patch(
                "odb_autodba.db.awr_checks._build_host_cpu_state",
                return_value=AwrHostCpuState(
                    metrics=[AwrMetricDiff(metric_name="Host CPU usage", previous=35.0, current=55.0, delta=20.0, pct_change=57.14, significance="HIGH")]
                ),
            ),
            patch(
                "odb_autodba.db.awr_checks._build_io_profile_state",
                return_value=AwrIoProfileState(
                    metrics=[AwrMetricDiff(metric_name="total IO requests", previous=1200.0, current=1800.0, delta=600.0, pct_change=50.0, significance="HIGH")],
                    io_pressure_flag=True,
                ),
            ),
            patch(
                "odb_autodba.db.awr_checks._build_memory_state",
                return_value=AwrMemoryState(
                    metrics=[AwrMetricDiff(metric_name="PGA usage", previous=1024.0, current=1200.0, delta=176.0, pct_change=17.19, significance="MEDIUM")]
                ),
            ),
            patch("odb_autodba.db.awr_checks._build_sql_change_intel", return_value=sql_change),
            patch(
                "odb_autodba.db.awr_checks.get_ash_window_state",
                return_value={"source": "dba_hist_active_sess_history", "notes": [], "top_sql": [], "wait_profile": [], "blocking": [], "aas_proxy": 0.5},
            ),
        ):
            diff = build_awr_state_diff(window_mapping=mapping, capabilities=caps)

        self.assertTrue(diff.available)
        self.assertTrue(len(diff.load_profile) > 0)
        self.assertTrue(diff.wait_class_shift.wait_class_shift_flag)
        self.assertTrue(diff.sql_change.sql_regression_flag)
        self.assertTrue(bool(diff.sql_change.top_sql_by_elapsed_current))

    def test_same_snap_adjacent_windows_quality_is_medium_and_structured(self) -> None:
        mapping = AwrRunPairWindowMapping(
            previous=AwrSnapshotWindowMapping(
                dbid=1234,
                instance_number=1,
                startup_time="2026-04-22T00:00:00",
                begin_snap_id=296,
                end_snap_id=297,
                matched_snap_id=297,
                begin_time="2026-04-22T06:00:00",
                end_time="2026-04-22T08:00:00",
                duration_minutes=60.0,
                mapping_quality="MEDIUM",
                window_use="baseline",
            ),
            current=AwrSnapshotWindowMapping(
                dbid=1234,
                instance_number=1,
                startup_time="2026-04-22T00:00:00",
                begin_snap_id=297,
                end_snap_id=298,
                matched_snap_id=298,
                begin_time="2026-04-22T07:00:00",
                end_time="2026-04-22T09:00:00",
                duration_minutes=60.0,
                mapping_quality="MEDIUM",
                window_use="structured_delta",
            ),
            comparability_score=0.65,
            confidence="MEDIUM",
            debug={"same_snap_adjacent_interval_mode": True, "same_snap_selected": False},
        )
        caps = AwrCapabilities(available=True, ash_available=True, dbid=1234, missing_components=[])
        with (
            patch("odb_autodba.db.awr_checks._collect_load_profile", side_effect=[{"DB Time": 10.0}, {"DB Time": 12.0}]),
            patch("odb_autodba.db.awr_checks._build_wait_class_shift", return_value=AwrWaitClassShift()),
            patch("odb_autodba.db.awr_checks._build_time_model_state", return_value=AwrTimeModelState()),
            patch("odb_autodba.db.awr_checks._build_host_cpu_state", return_value=AwrHostCpuState()),
            patch("odb_autodba.db.awr_checks._build_io_profile_state", return_value=AwrIoProfileState()),
            patch("odb_autodba.db.awr_checks._build_memory_state", return_value=AwrMemoryState()),
            patch("odb_autodba.db.awr_checks._build_sql_change_intel", return_value=AwrSqlChangeIntelligence()),
            patch("odb_autodba.db.awr_checks.get_ash_window_state", return_value={"source": None, "notes": []}),
        ):
            diff = build_awr_state_diff(window_mapping=mapping, capabilities=caps)
        self.assertTrue(diff.available)
        self.assertEqual(diff.snapshot_quality.window_quality, "MEDIUM")
        self.assertEqual(diff.snapshot_quality.usage, "context_only")
        self.assertTrue(any("same completed awr snapshot" in note.lower() for note in diff.snapshot_quality.notes))

    def test_structured_queries_are_scoped_by_dbid_and_instance(self) -> None:
        captured: list[str] = []

        def _fake_fetch_all(sql: str, binds=None):  # noqa: ANN001
            captured.append(" ".join(sql.lower().split()))
            return []

        window = AwrSnapshotWindowMapping(
            dbid=1234,
            instance_number=1,
            startup_time="2026-04-22T00:00:00",
            begin_snap_id=210,
            end_snap_id=212,
            mapping_quality="HIGH",
        )
        with patch("odb_autodba.db.awr_checks.fetch_all", side_effect=_fake_fetch_all):
            awr_mod._collect_top_events(window, [], label="curr")
            awr_mod._collect_time_model(window, [], label="curr")
            awr_mod._collect_sysstat(window, [], label="curr")
            awr_mod._collect_top_sql(window, [], label="curr", order="elapsed")
        joined = "\n".join(captured)
        self.assertIn("s.dbid = :dbid", joined)
        self.assertIn("s.instance_number = :instance_number", joined)

    def test_workload_collectors_receive_delta_window_when_adjacent_exists(self) -> None:
        rows = [
            {"dbid": 1234, "snap_id": 296, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T06:00:00", "end_time": "2026-04-22T07:00:00"},
            {"dbid": 1234, "snap_id": 297, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T07:00:00", "end_time": "2026-04-22T08:00:00"},
            {"dbid": 1234, "snap_id": 298, "instance_number": 1, "startup_time": "2026-04-22T00:00:00", "begin_time": "2026-04-22T08:00:00", "end_time": "2026-04-22T09:00:00"},
        ]
        with (
            patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows),
            patch(
                "odb_autodba.db.awr_checks._current_awr_identity",
                return_value={"dbid": 1234, "instance_number": 1, "startup_dt": None, "startup_time": "2026-04-22T00:00:00"},
            ),
        ):
            mapping = map_run_pair_to_awr_windows(
                "2026-04-22T08:42:00Z",
                "2026-04-22T08:55:00Z",
                dbid=1234,
                previous_window_start="2026-04-22T08:30:00Z",
                previous_window_end="2026-04-22T08:42:00Z",
                current_window_start="2026-04-22T08:50:00Z",
                current_window_end="2026-04-22T08:55:00Z",
            )

        captured_binds: list[dict] = []

        def _fake_fetch_all(sql: str, binds=None):  # noqa: ANN001
            captured_binds.append(dict(binds or {}))
            return []

        with patch("odb_autodba.db.awr_checks.fetch_all", side_effect=_fake_fetch_all):
            awr_mod._collect_sysstat(mapping.current, [], label="current")
        self.assertTrue(captured_binds)
        self.assertLess(captured_binds[0].get("begin_snap_id", 0), captured_binds[0].get("end_snap_id", 0))

    def test_io_latency_under_1ms_is_negligible(self) -> None:
        self.assertEqual(awr_mod._wait_latency_impact(avg_wait_ms=0.2, wait_s=120.0), "negligible")
        self.assertEqual(awr_mod._event_interpretation(event="db file sequential read", impact="negligible"), "I/O latency negligible in this window.")

    def test_sql_elapsed_per_exec_is_na_when_exec_zero(self) -> None:
        rows = awr_mod._build_sql_delta_rows(
            previous_rows=[],
            current_rows=[{"sql_id": "abc123", "plan_hash_value": 999, "executions": 0, "elapsed_s": 15.0, "cpu_s": 5.0}],
            db_time_current=30.0,
        )
        self.assertEqual(rows[0]["Elapsed/Exec s"], "N/A")

    def test_sql_under_30s_with_low_db_time_is_candidate_only(self) -> None:
        rows = awr_mod._build_sql_delta_rows(
            previous_rows=[],
            current_rows=[{"sql_id": "abc123", "plan_hash_value": 101, "executions": 10, "elapsed_s": 20.0, "cpu_s": 5.0}],
            db_time_current=40.0,
        )
        self.assertEqual(rows[0]["Classification"], "candidate_only")

    def test_plan_hash_zero_classified_internal_wrapper(self) -> None:
        rows = awr_mod._build_sql_delta_rows(
            previous_rows=[],
            current_rows=[{"sql_id": "abc123", "plan_hash_value": 0, "executions": 2, "elapsed_s": 45.0, "cpu_s": 10.0}],
            db_time_current=100.0,
        )
        self.assertEqual(rows[0]["Classification"], "PL_SQL_WRAPPER_OR_INTERNAL")

    def test_sys_time_model_deltas_use_begin_end_snapshot_values(self) -> None:
        window = AwrSnapshotWindowMapping(dbid=1234, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=297, end_snap_id=298)
        rows = [
            {"stat_name": "DB time", "snap_id": 297, "value": 100_000_000},
            {"stat_name": "DB time", "snap_id": 298, "value": 160_000_000},
            {"stat_name": "DB CPU", "snap_id": 297, "value": 50_000_000},
            {"stat_name": "DB CPU", "snap_id": 298, "value": 90_000_000},
        ]
        with patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows):
            out = awr_mod._collect_time_model(window, [], label="curr")
        self.assertEqual(out.get("DB time"), 60.0)
        self.assertEqual(out.get("DB CPU"), 40.0)

    def test_sysstat_deltas_use_begin_end_snapshot_values(self) -> None:
        window = AwrSnapshotWindowMapping(dbid=1234, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=297, end_snap_id=298)
        rows = [
            {"stat_name": "redo size", "snap_id": 297, "value": 1000},
            {"stat_name": "redo size", "snap_id": 298, "value": 2500},
            {"stat_name": "session logical reads", "snap_id": 297, "value": 200},
            {"stat_name": "session logical reads", "snap_id": 298, "value": 500},
            {"stat_name": "physical reads", "snap_id": 297, "value": 50},
            {"stat_name": "physical reads", "snap_id": 298, "value": 70},
            {"stat_name": "execute count", "snap_id": 297, "value": 10},
            {"stat_name": "execute count", "snap_id": 298, "value": 15},
            {"stat_name": "parse count (total)", "snap_id": 297, "value": 4},
            {"stat_name": "parse count (total)", "snap_id": 298, "value": 7},
        ]
        with patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows):
            out = awr_mod._collect_sysstat(window, [], label="curr")
        self.assertEqual(out.get("redo size"), 1500.0)
        self.assertEqual(out.get("session logical reads"), 300.0)
        self.assertEqual(out.get("physical reads"), 20.0)
        self.assertEqual(out.get("execute count"), 5.0)
        self.assertEqual(out.get("parse count (total)"), 3.0)

    def test_system_event_deltas_produce_wait_rows(self) -> None:
        window = AwrSnapshotWindowMapping(dbid=1234, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=297, end_snap_id=298)
        rows = [
            {"event_name": "enq: tx - row lock contention", "wait_class": "Application", "snap_id": 297, "total_waits": 100, "time_waited_micro": 500_000},
            {"event_name": "enq: tx - row lock contention", "wait_class": "Application", "snap_id": 298, "total_waits": 140, "time_waited_micro": 1_700_000},
        ]
        with patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows):
            out = awr_mod._collect_top_events(window, [], label="curr")
        self.assertTrue(out)
        self.assertEqual(out[0].get("event_name"), "enq: tx - row lock contention")
        self.assertEqual(out[0].get("waits"), 40)
        self.assertEqual(out[0].get("time_waited_s"), 1.2)

    def test_unavailable_metric_reason_codes_are_emitted(self) -> None:
        window = AwrSnapshotWindowMapping(dbid=1234, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=297, end_snap_id=298)
        rows = [
            {"stat_name": "DB time", "snap_id": 298, "value": 160_000_000},  # begin missing
            {"stat_name": "DB CPU", "snap_id": 297, "value": 90_000_000},
            {"stat_name": "DB CPU", "snap_id": 298, "value": 50_000_000},  # negative delta
        ]
        with patch("odb_autodba.db.awr_checks.fetch_all", return_value=rows):
            values, reasons = awr_mod._collect_counter_deltas(
                window=window,
                notes=[],
                label="test",
                source_name="dba_hist_sys_time_model",
                stat_names=["DB time", "DB CPU", "parse time elapsed"],
                sql="select 1 from dual",
                scale=1e6,
                normalize=False,
            )
        self.assertIsNone(values.get("DB time"))
        self.assertEqual(reasons.get("DB time"), "begin_snap_missing")
        self.assertIsNone(values.get("DB CPU"))
        self.assertEqual(reasons.get("DB CPU"), "negative_delta")
        self.assertEqual(reasons.get("parse time elapsed"), "stat_name_not_found")

    def test_plan_stability_collapses_when_all_top_plans_are_zero(self) -> None:
        rows = awr_mod._build_plan_stability_rows(
            previous_rows=[],
            current_rows=[
                {"sql_id": "a", "plan_hash_value": 0, "elapsed_per_exec_s": 20.0},
                {"sql_id": "b", "plan_hash_value": 0, "elapsed_per_exec_s": 30.0},
            ],
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("Plan stability not evaluated", str(rows[0].get("Regression Evidence")))

    def test_sql_delta_wrapper_interpretation_mentions_blocking_correlation(self) -> None:
        rows = awr_mod._build_sql_delta_rows(
            previous_rows=[],
            current_rows=[
                {
                    "sql_id": "0m92022d1yzhs",
                    "plan_hash_value": 0,
                    "executions": 1,
                    "elapsed_s": 1066.95,
                    "cpu_s": 0.01,
                    "io_wait_s": 0.0,
                    "app_wait_s": 1066.94,
                    "conc_wait_s": 0.0,
                    "parsing_schema_name": "APP",
                    "module": "SQL*Plus",
                    "sql_text_sample": "begin do_work; end;",
                }
            ],
            db_time_current=1200.0,
        )
        self.assertIn("Application wait", str(rows[0].get("Interpretation")))

    def test_redo_commit_profile_includes_numeric_or_reason(self) -> None:
        window_prev = AwrSnapshotWindowMapping(dbid=1234, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=296, end_snap_id=297)
        window_curr = AwrSnapshotWindowMapping(dbid=1234, instance_number=1, startup_time="2026-04-22T00:00:00", begin_snap_id=297, end_snap_id=298)
        with (
            patch(
                "odb_autodba.db.awr_checks._collect_sysstat",
                side_effect=[
                    {"redo size": 1000.0, "user commits": 10.0, "user rollbacks": 1.0},
                    {"redo size": 1600.0, "user commits": 12.0, "user rollbacks": 2.0},
                ],
            ),
            patch(
                "odb_autodba.db.awr_checks._collect_wait_event_deltas",
                side_effect=[
                    (
                        {"log file sync": {"avg_wait_ms": 2.0}, "log file parallel write": {"avg_wait_ms": 1.5}},
                        {"log file sync": "ok", "log file parallel write": "ok"},
                    ),
                    (
                        {"log file sync": {"avg_wait_ms": 3.5}, "log file parallel write": {"avg_wait_ms": 2.0}},
                        {"log file sync": "ok", "log file parallel write": "ok"},
                    ),
                ],
            ),
        ):
            rows = awr_mod._build_redo_commit_rows(previous_window=window_prev, current_window=window_curr, notes=[])
        by_metric = {str(row.get("Metric")): row for row in rows}
        self.assertEqual(by_metric["redo size"]["Delta"], 600.0)
        self.assertEqual(by_metric["log file sync avg ms"]["Delta"], 1.5)


if __name__ == "__main__":
    unittest.main()
