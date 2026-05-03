from __future__ import annotations

import unittest

from odb_autodba.agents.root_cause_engine import infer_root_cause, render_root_cause_section


def _base_supporting() -> dict:
    return {
        "history_context": {
            "latest_run": {
                "metrics": {
                    "blocking_count": 0,
                    "host_cpu_pct": 20.0,
                    "memory_pct": 40.0,
                    "hottest_tablespace_pct": 40.0,
                    "alert_log_count": 0,
                    "listener_error_count": 0,
                }
            },
            "recurring_findings": [],
        },
        "state_transition": {
            "learning_features": {
                "sql_regression_flag": False,
                "sql_regression_severity": "NONE",
                "sql_elapsed_delta": 0.0,
                "sql_cpu_delta": 0.0,
                "memory_pressure_flag": False,
            },
            "recurring_patterns_ranked": [],
            "awr_state_diff": {
                "sql_change": {"sql_regression_flag": False, "sql_regression_severity": "NONE", "plan_hash_changed_flag": False},
                "host_cpu_state": {"cpu_pressure_flag": False},
                "memory_state": {"memory_pressure_flag": False},
            },
        },
    }


class RootCauseEngineTests(unittest.TestCase):
    def test_sql_regression_beats_historical_recurrence(self) -> None:
        supporting = _base_supporting()
        supporting["state_transition"]["learning_features"]["sql_regression_flag"] = True
        supporting["state_transition"]["learning_features"]["sql_elapsed_delta"] = 65.0
        supporting["state_transition"]["recurring_patterns_ranked"] = ["Top SQL regression reoccurs"]
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="# report")
        self.assertEqual(rc.get("category"), "sql_regression")
        self.assertTrue(any("Recurring historical pattern count" in item for item in rc.get("supporting_evidence") or []))

    def test_blocking_lock_beats_sql_regression(self) -> None:
        supporting = _base_supporting()
        supporting["history_context"]["latest_run"]["metrics"]["blocking_count"] = 2
        supporting["state_transition"]["learning_features"]["sql_regression_flag"] = True
        supporting["state_transition"]["learning_features"]["sql_elapsed_delta"] = 55.0
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="enq: TX - row lock contention")
        self.assertEqual(rc.get("category"), "blocking_lock")

    def test_cpu_pressure_beats_historical_recurrence_when_saturation_is_correlated(self) -> None:
        supporting = _base_supporting()
        supporting["host_check"] = {
            "host_check_mode": "ssh_remote",
            "host_check_scope": "remote_db_host_ssh",
            "host_check_label": "Remote Oracle DB host via SSH",
        }
        supporting["history_context"]["latest_run"]["metrics"]["host_cpu_pct"] = 88.0
        supporting["state_transition"]["awr_state_diff"]["host_cpu_state"]["cpu_pressure_flag"] = True
        supporting["state_transition"]["recurring_patterns_ranked"] = ["CPU rise repeated"]
        rc = infer_root_cause(mode="history", summary="x", supporting_data=supporting, rendered_report="DB CPU pressure observed")
        self.assertEqual(rc.get("category"), "cpu_pressure")

    def test_memory_pressure_beats_historical_recurrence(self) -> None:
        supporting = _base_supporting()
        supporting["history_context"]["latest_run"]["metrics"]["memory_pct"] = 91.0
        supporting["history_context"]["latest_run"]["metrics"]["temp_usage_pct"] = 88.0
        supporting["state_transition"]["recurring_patterns_ranked"] = ["memory hot"]
        rc = infer_root_cause(mode="history", summary="x", supporting_data=supporting, rendered_report="# report")
        self.assertEqual(rc.get("category"), "memory_pressure")

    def test_local_app_host_cpu_alone_does_not_produce_high_confidence_db_root_cause(self) -> None:
        supporting = _base_supporting()
        supporting["host_check"] = {
            "host_check_mode": "local_app_host",
            "host_check_scope": "local_app_host",
            "host_check_label": "Local AutoDBA app host",
        }
        supporting["history_context"]["latest_run"]["metrics"]["host_cpu_pct"] = 97.0
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="# report")
        self.assertNotEqual(rc.get("confidence"), "HIGH")
        self.assertNotEqual(rc.get("category"), "cpu_pressure")

    def test_top_sql_without_cpu_saturation_is_sql_performance_pattern(self) -> None:
        supporting = _base_supporting()
        supporting["history_context"]["latest_run"]["metrics"]["host_cpu_pct"] = 22.0
        supporting["history_context"]["latest_run"]["metrics"]["container_cpu_pct"] = 18.0
        supporting["history_context"]["latest_run"]["metrics"]["top_cpu_sql_cpu_s"] = 72.0
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="# report")
        self.assertEqual(rc.get("category"), "sql_performance_pattern")

    def test_remote_ssh_scope_can_produce_stronger_cpu_confidence(self) -> None:
        supporting = _base_supporting()
        supporting["host_check"] = {
            "host_check_mode": "ssh_remote",
            "host_check_scope": "remote_db_host_ssh",
            "host_check_label": "Remote Oracle DB host via SSH",
        }
        supporting["history_context"]["latest_run"]["metrics"]["host_cpu_pct"] = 91.0
        supporting["history_context"]["latest_run"]["metrics"]["top_cpu_sql_cpu_s"] = 5.0
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="# report")
        self.assertEqual(rc.get("category"), "cpu_pressure")
        self.assertIn(rc.get("confidence"), {"MEDIUM", "HIGH"})

    def test_unavailable_ssh_scope_does_not_drive_cpu_or_memory_root_cause(self) -> None:
        supporting = _base_supporting()
        supporting["host_check"] = {
            "host_check_mode": "ssh_remote",
            "host_check_scope": "unavailable",
            "host_check_label": "Remote Oracle DB host via SSH",
            "host_check_warning": "Remote SSH host check failed: timeout",
        }
        supporting["history_context"]["latest_run"]["metrics"]["host_cpu_pct"] = 95.0
        supporting["history_context"]["latest_run"]["metrics"]["memory_pct"] = 96.0
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="# report")
        self.assertNotIn(rc.get("category"), {"cpu_pressure", "memory_pressure"})

    def test_storage_ora_error_beats_historical_recurrence(self) -> None:
        supporting = _base_supporting()
        supporting["history_context"]["latest_run"]["metrics"]["hottest_tablespace_pct"] = 96.0
        supporting["state_transition"]["recurring_patterns_ranked"] = ["sql issue historic"]
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="ORA-01653 unable to extend table")
        self.assertEqual(rc.get("category"), "storage_or_alert_error")

    def test_historical_recurrence_only_when_no_stronger_signal(self) -> None:
        supporting = _base_supporting()
        supporting["state_transition"]["recurring_patterns_ranked"] = ["same warning repeatedly"]
        rc = infer_root_cause(mode="history", summary="x", supporting_data=supporting, rendered_report="# report")
        self.assertEqual(rc.get("category"), "historical_recurrence")

    def test_inconclusive_when_evidence_weak(self) -> None:
        rc = infer_root_cause(mode="health", summary="", supporting_data={}, rendered_report="")
        self.assertEqual(rc.get("category"), "inconclusive")
        self.assertEqual(rc.get("confidence"), "LOW")

    def test_render_root_cause_section_includes_guardrail_fields_and_friendly_label(self) -> None:
        rc = {
            "category": "blocking_lock",
            "confidence": "HIGH",
            "primary_evidence": ["blocking_count=2"],
            "supporting_evidence": ["lock wait observed"],
            "reasoning": "Blocking signal is dominant.",
            "impacted_components": ["sessions"],
            "next_validation_step": "Validate blockers.",
        }
        rendered = render_root_cause_section(rc)
        self.assertIn("Blocking / lock contention", rendered)
        self.assertIn("Confidence:", rendered)
        self.assertIn("Primary Evidence", rendered)
        self.assertIn("Supporting Evidence", rendered)
        self.assertIn("Next Validation Step", rendered)

    def test_evidence_lists_are_deduped_and_capped(self) -> None:
        rc = infer_root_cause(
            mode="history",
            summary="x",
            supporting_data={
                "state_transition": {"recurring_patterns_ranked": ["dup", "dup", "dup", "dup", "dup", "dup"]},
                "history_context": {"latest_run": {"metrics": {}}, "recurring_findings": ["dup", "dup"]},
            },
            rendered_report="# report",
        )
        self.assertLessEqual(len(rc.get("primary_evidence") or []), 3)
        self.assertLessEqual(len(rc.get("supporting_evidence") or []), 5)
        self.assertEqual(len(set(rc.get("supporting_evidence") or [])), len(rc.get("supporting_evidence") or []))


if __name__ == "__main__":
    unittest.main()
