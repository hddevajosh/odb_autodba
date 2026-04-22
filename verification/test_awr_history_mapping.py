from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.db.awr_checks import build_awr_state_diff, map_run_pair_to_awr_windows, map_run_to_snapshot_window
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
        {"snap_id": 210, "instance_number": 1, "begin_time": "2026-04-22T02:04:00", "end_time": "2026-04-22T02:14:00"},
        {"snap_id": 210, "instance_number": 2, "begin_time": "2026-04-22T02:04:00", "end_time": "2026-04-22T02:14:00"},
        {"snap_id": 211, "instance_number": 1, "begin_time": "2026-04-22T02:14:00", "end_time": "2026-04-22T03:00:00"},
        {"snap_id": 211, "instance_number": 2, "begin_time": "2026-04-22T02:14:00", "end_time": "2026-04-22T03:00:00"},
        {"snap_id": 212, "instance_number": 1, "begin_time": "2026-04-22T03:00:00", "end_time": "2026-04-22T04:00:00"},
        {"snap_id": 212, "instance_number": 2, "begin_time": "2026-04-22T03:00:00", "end_time": "2026-04-22T04:00:00"},
    ]


class AwrHistoryMappingTests(unittest.TestCase):
    def test_duplicate_snapshot_rows_are_aggregated_per_snap_id(self) -> None:
        with patch("odb_autodba.db.awr_checks.fetch_all", return_value=_snapshot_rows()):
            mapped = map_run_to_snapshot_window("2026-04-22T02:25:00Z", dbid=1234)
        self.assertEqual(mapped.matched_snap_id, 211)
        self.assertEqual(mapped.instance_count, 2)
        self.assertEqual(mapped.instance_rows_found, 2)
        self.assertEqual(mapped.mapping_quality, "HIGH")

    def test_run_timestamp_maps_into_enclosing_snapshot_interval(self) -> None:
        with patch("odb_autodba.db.awr_checks.fetch_all", return_value=_snapshot_rows()):
            mapped = map_run_to_snapshot_window("2026-04-22T03:59:00Z", dbid=1234)
        self.assertEqual(mapped.matched_snap_id, 212)
        self.assertEqual(mapped.end_snap_id, 212)
        self.assertEqual(mapped.matched_begin_time, "2026-04-22T03:00:00")
        self.assertEqual(mapped.matched_end_time, "2026-04-22T04:00:00")

    def test_map_run_pair_debug_includes_selected_snapshots(self) -> None:
        with patch("odb_autodba.db.awr_checks.fetch_all", return_value=_snapshot_rows()):
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


if __name__ == "__main__":
    unittest.main()
