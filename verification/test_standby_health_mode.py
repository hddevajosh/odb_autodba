from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.agents.root_cause_engine import infer_root_cause
from odb_autodba.db.extended_health_checks import (
    _database_role_mode,
    _evaluate_services,
    _listener_connectivity_log_signals_section,
    _standby_archive_gap_section,
    _standby_dataguard_status_section,
    _standby_lag_section,
    _standby_managed_recovery_section,
)


class StandbyHealthModeTests(unittest.TestCase):
    def test_mounted_physical_standby_ok_path_and_primary_checks_skipped(self) -> None:
        role_mode = _database_role_mode({"database_role": "PHYSICAL STANDBY", "open_mode": "MOUNTED"})
        self.assertTrue(role_mode["standby_health_mode"])
        self.assertTrue(role_mode["primary_style_checks_skipped"])

        with patch(
            "odb_autodba.db.extended_health_checks._fetch_all",
            return_value=(
                [
                    {
                        "inst_id": 1,
                        "process": "MRP0",
                        "status": "APPLYING_LOG",
                        "client_process": "N/A",
                        "thread#": 1,
                        "sequence#": 100,
                        "block#": 1,
                        "blocks": 10,
                    },
                    {
                        "inst_id": 1,
                        "process": "RFS",
                        "status": "IDLE",
                        "client_process": "LGWR",
                        "thread#": 1,
                        "sequence#": 100,
                        "block#": 1,
                        "blocks": 10,
                    },
                ],
                None,
            ),
        ):
            managed_section, _ = _standby_managed_recovery_section(role_mode=role_mode)
        self.assertEqual(managed_section.status, "OK")

        with patch(
            "odb_autodba.db.extended_health_checks._fetch_all",
            return_value=(
                [
                    {"name": "apply lag", "value": "+00 00:00:00", "unit": "day(2) to second(0)", "time_computed": "x", "datum_time": "x"},
                    {"name": "transport lag", "value": "+00 00:00:00", "unit": "day(2) to second(0)", "time_computed": "x", "datum_time": "x"},
                ],
                None,
            ),
        ):
            lag_section, _ = _standby_lag_section()
        self.assertEqual(lag_section.status, "OK")

        with patch("odb_autodba.db.extended_health_checks._fetch_all", return_value=([], None)):
            gap_section, _ = _standby_archive_gap_section()
        self.assertEqual(gap_section.status, "OK")

    def test_mounted_physical_standby_mrp_missing_is_critical(self) -> None:
        role_mode = _database_role_mode({"database_role": "PHYSICAL STANDBY", "open_mode": "MOUNTED"})
        with patch(
            "odb_autodba.db.extended_health_checks._fetch_all",
            return_value=([{"inst_id": 1, "process": "RFS", "status": "IDLE", "client_process": "LGWR"}], None),
        ):
            section, _ = _standby_managed_recovery_section(role_mode=role_mode)
        self.assertEqual(section.status, "CRITICAL")

    def test_archive_gap_row_is_critical(self) -> None:
        with patch(
            "odb_autodba.db.extended_health_checks._fetch_all",
            return_value=([{"thread#": 1, "low_sequence#": 100, "high_sequence#": 110}], None),
        ):
            section, _ = _standby_archive_gap_section()
        self.assertEqual(section.status, "CRITICAL")

    def test_standby_read_only_with_apply_missing_required_service_is_critical(self) -> None:
        evaluation = _evaluate_services(
            active_rows=[],
            expected=[{"name": "RO_SVC", "required": True, "expected_instances": [1]}],
            role_mode=_database_role_mode({"database_role": "PHYSICAL STANDBY", "open_mode": "READ ONLY WITH APPLY"}),
        )
        self.assertEqual(evaluation["severity"], "CRITICAL")

    def test_mounted_standby_no_services_without_expectation_is_info(self) -> None:
        evaluation = _evaluate_services(
            active_rows=[],
            expected=[],
            role_mode=_database_role_mode({"database_role": "PHYSICAL STANDBY", "open_mode": "MOUNTED"}),
        )
        self.assertEqual(evaluation["severity"], "INFO")

    def test_apply_lag_warning_threshold(self) -> None:
        rows = [
            {"name": "apply lag", "value": "+00 00:10:00", "unit": "day(2) to second(0)", "time_computed": "x", "datum_time": "x"},
            {"name": "transport lag", "value": "+00 00:00:00", "unit": "day(2) to second(0)", "time_computed": "x", "datum_time": "x"},
        ]
        with patch("odb_autodba.db.extended_health_checks._fetch_all", return_value=(rows, None)):
            section, _ = _standby_lag_section()
        self.assertEqual(section.status, "WARNING")

    def test_apply_lag_critical_threshold(self) -> None:
        rows = [
            {"name": "apply lag", "value": "+00 00:40:00", "unit": "day(2) to second(0)", "time_computed": "x", "datum_time": "x"},
            {"name": "transport lag", "value": "+00 00:00:00", "unit": "day(2) to second(0)", "time_computed": "x", "datum_time": "x"},
        ]
        with patch("odb_autodba.db.extended_health_checks._fetch_all", return_value=(rows, None)):
            section, _ = _standby_lag_section()
        self.assertEqual(section.status, "CRITICAL")

    def test_dataguard_status_error_rows_critical(self) -> None:
        rows = [{"timestamp": "2026-05-06 00:00:00", "severity": "Error", "facility": "Log Apply Services", "error_code": "ORA-16766", "message": "Apply service failed"}]
        with patch("odb_autodba.db.extended_health_checks._fetch_all", return_value=(rows, None)):
            section, _ = _standby_dataguard_status_section(hours=24)
        self.assertEqual(section.status, "CRITICAL")

    def test_listener_check_skipped_without_os_access(self) -> None:
        with patch.dict("os.environ", {"ODB_AUTODBA_LISTENER_LOG_PATH": ""}, clear=False):
            section, meta = _listener_connectivity_log_signals_section(hours=24)
        self.assertEqual(section.status, "INFO")
        self.assertTrue(meta.get("skipped_no_os_access"))
        self.assertIn("skipped", section.summary.lower())

    def test_mounted_standby_low_cache_ratio_does_not_trigger_primary_rca(self) -> None:
        supporting = {
            "history_context": {
                "latest_run": {
                    "metrics": {
                        "database_role": "PHYSICAL STANDBY",
                        "open_mode": "MOUNTED",
                        "mounted_physical_standby": True,
                        "buffer_hit_pct": 72.0,
                        "active_sessions": 0,
                        "blocking_count": 0,
                    }
                }
            }
        }
        rc = infer_root_cause(
            mode="health",
            summary="x",
            supporting_data=supporting,
            rendered_report="Low buffer cache ratio observed",
        )
        self.assertEqual(rc.get("category"), "inconclusive")
        self.assertIn("standby", " ".join(rc.get("primary_evidence") or []).lower())


if __name__ == "__main__":
    unittest.main()
