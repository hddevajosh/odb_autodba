from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import json
import os

from odb_autodba.agents.correlation_engine import correlate_root_cause_from_traces
from odb_autodba.agents.root_cause_engine import infer_root_cause
from odb_autodba.db.awr_checks import build_awr_state_diff
from odb_autodba.db.awr_checks import _sql_ids_from_line
from odb_autodba.db.extended_health_checks import (
    _cache_summary,
    _cache_status,
    _evaluate_services,
    _performance_actions,
    _redo_section,
    _services_and_routing,
    _tablespace_pct_from_metrics,
    _tablespace_section,
)
from odb_autodba.db.health_checks import _derive_issues
from odb_autodba.db.query_deep_dive import _plan_analysis, classify_sql
from odb_autodba.db.running_sessions import ACTIVE_SESSION_SUMMARY_SQL, ACTIVE_SESSIONS_SQL, BLOCKING_SQL
from odb_autodba.models.schemas import (
    AwrCapabilities,
    AwrRunPairWindowMapping,
    AwrSnapshotWindowMapping,
    BlockingChain,
    HealthSnapshot,
    SessionSummary,
    TablespaceUsageRow,
)


class OracleDbaGradeFixTests(unittest.TestCase):
    def test_tablespace_headline_percentage_formula(self) -> None:
        pct_used, pct_free = _tablespace_pct_from_metrics(used_space=3095, tablespace_size=10000)
        self.assertEqual(pct_used, 30.95)
        self.assertEqual(pct_free, 69.05)

    def test_tablespace_severity_thresholds(self) -> None:
        ok = _tablespace_section([{"tablespace_name": "USERS", "pct_used": 84.99, "pct_free": 15.01}])
        warn = _tablespace_section([{"tablespace_name": "USERS", "pct_used": 85.00, "pct_free": 15.00}])
        crit = _tablespace_section([{"tablespace_name": "USERS", "pct_used": 97.00, "pct_free": 3.00}])
        self.assertEqual(ok.status, "OK")
        self.assertEqual(warn.status, "WARNING")
        self.assertEqual(crit.status, "CRITICAL")

    def test_temp_capacity_query_uses_dba_temp_free_space_shape(self) -> None:
        from odb_autodba.db.extended_health_checks import _temp_summary

        captured_sql: list[str] = []

        def fake_fetch_all(sql: str, binds=None, *, max_rows=None):  # noqa: ANN001
            captured_sql.append(" ".join(sql.lower().split()))
            if "from dba_temp_free_space" in sql.lower():
                return (
                    [
                        {
                            "tablespace_name": "TEMP",
                            "temp_allocated_gb": 10.0,
                            "temp_current_allocated_gb": 10.0,
                            "temp_free_gb": 7.0,
                            "temp_used_gb": 3.0,
                            "temp_used_pct": 30.0,
                        }
                    ],
                    None,
                )
            return ([], None)

        with patch("odb_autodba.db.extended_health_checks._fetch_all", side_effect=fake_fetch_all):
            temp = _temp_summary()
        self.assertEqual((temp.get("capacity") or {}).get("temp_used_pct"), 30.0)
        self.assertTrue(any("from dba_temp_free_space" in text for text in captured_sql))

    def test_active_idle_waits_do_not_imply_pressure(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-05-06T00:00:00Z",
            session_summary=SessionSummary(active_total=10, active_sessions=10, true_active_non_idle=0, active_idle_waiting=10),
            tablespaces=[TablespaceUsageRow(tablespace_name="USERS", pct_used=10.0, pct_free=90.0, used_pct=10.0)],
        )
        issues = _derive_issues(snapshot)
        self.assertFalse(any(issue.category == "blocking" for issue in issues))

    def test_blocking_transient_info_not_critical_issue(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-05-06T00:00:00Z",
            blocking_chains=[
                BlockingChain(
                    blocked_inst_id=1,
                    blocked_sid=20,
                    blocker_inst_id=1,
                    blocker_sid=10,
                    seconds_in_wait=0,
                    blocking_severity="INFO",
                    blocker_classification="background_process",
                    blocking_reason="transient_or_moving_block",
                )
            ],
        )
        issues = _derive_issues(snapshot)
        self.assertFalse(any(issue.category == "blocking" for issue in issues))

    def test_blocking_real_critical_issue(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-05-06T00:00:00Z",
            blocking_chains=[
                BlockingChain(
                    blocked_inst_id=1,
                    blocked_sid=20,
                    blocker_inst_id=1,
                    blocker_sid=10,
                    seconds_in_wait=120,
                    wait_class="Application",
                    blocker_user="SOE",
                    object_name="ORDERS",
                    blocking_severity="CRITICAL",
                    blocker_classification="foreground_session",
                    blocking_reason="foreground_blocking_chain",
                )
            ],
        )
        issues = _derive_issues(snapshot)
        blocking = [issue for issue in issues if issue.category == "blocking"]
        self.assertTrue(blocking)
        self.assertEqual(blocking[0].severity, "CRITICAL")

    def test_services_missing_required_service_is_critical(self) -> None:
        evaluation = _evaluate_services(
            active_rows=[],
            expected=[{"name": "FREEPDB1", "required": True, "expected_instances": [1]}],
        )
        self.assertEqual(evaluation["severity"], "CRITICAL")
        self.assertTrue(any("missing" in item.lower() for item in evaluation["findings"]))

    def test_services_discovered_without_expected_config_is_info(self) -> None:
        evaluation = _evaluate_services(
            active_rows=[{"inst_id": 1, "name": "FREEPDB1", "network_name": "FREEPDB1", "con_id": 3, "container_name": "FREEPDB1"}],
            expected=[],
        )
        self.assertEqual(evaluation["severity"], "INFO")
        self.assertTrue(any("no expected_services config" in item.lower() for item in evaluation["findings"]))

    def test_runtime_sql_is_rac_safe_gv_views(self) -> None:
        self.assertIn("from gv$session", ACTIVE_SESSIONS_SQL.lower())
        self.assertIn("from gv$session", ACTIVE_SESSION_SUMMARY_SQL.lower())
        self.assertIn("from gv$session", BLOCKING_SQL.lower())
        self.assertNotIn("from v$session", ACTIVE_SESSIONS_SQL.lower())
        self.assertIn("nvl(wait_class,'?') <> 'idle'", ACTIVE_SESSION_SUMMARY_SQL.lower())
        self.assertIn("nvl(wait_class,'?') = 'idle'", ACTIVE_SESSION_SUMMARY_SQL.lower())

    def test_cache_ratio_only_not_critical(self) -> None:
        self.assertEqual(_cache_status({"buffer_hit_pct": 72.0}), "INFO")
        self.assertIn("insufficient correlated i/o evidence", _cache_summary({"buffer_hit_pct": 72.0}).lower())

    def test_cache_ratio_healthy_wording_when_buffer_hit_above_90(self) -> None:
        summary = _cache_summary({"buffer_hit_pct": 96.3, "library_hit_pct": 99.1, "dictionary_hit_pct": 99.0})
        self.assertIn("healthy/context only", summary.lower())
        self.assertNotIn("low buffer cache ratio observed", summary.lower())

    def test_redo_switch_rate_alone_is_info(self) -> None:
        section = _redo_section(
            {
                "switches_24h_total": 72,
                "max_switches_per_hour": 3.0,
                "switches_by_thread": [{"thread#": 1, "switches_24h": 72, "switches_per_hour": 3.0}],
                "redo_waits": [],
                "log_mode": "ARCHIVELOG",
                "archive_dest": "/fra/arch",
                "log_groups": [{"size_mb": 4096}],
            },
            hours=24,
        )
        self.assertEqual(section.status, "INFO")

    def test_checkpoint_incomplete_wait_drives_severity(self) -> None:
        section = _redo_section(
            {
                "switches_24h_total": 10,
                "max_switches_per_hour": 0.42,
                "switches_by_thread": [{"thread#": 1, "switches_24h": 10, "switches_per_hour": 0.42}],
                "redo_waits": [{"event": "log file switch (checkpoint incomplete)", "avg_wait_ms": 1500}],
                "log_mode": "ARCHIVELOG",
                "archive_dest": "/fra/arch",
                "log_groups": [{"size_mb": 4096}],
            },
            hours=24,
        )
        self.assertIn(section.status, {"WARNING", "CRITICAL"})

    def test_awr_same_snapshot_window_disables_trend_comparison(self) -> None:
        mapping = AwrRunPairWindowMapping(
            previous=AwrSnapshotWindowMapping(dbid=1234, begin_snap_id=265, end_snap_id=266, mapping_quality="MEDIUM"),
            current=AwrSnapshotWindowMapping(dbid=1234, begin_snap_id=265, end_snap_id=266, mapping_quality="MEDIUM"),
            comparability_score=0.4,
            confidence="LOW",
        )
        diff = build_awr_state_diff(window_mapping=mapping, capabilities=AwrCapabilities(available=True, ash_available=True, dbid=1234))
        self.assertFalse(diff.available)
        self.assertEqual(diff.snapshot_quality.confidence, "LOW")
        self.assertTrue(any("same snapshot window" in note.lower() for note in diff.notes))

    def test_sql_id_wrapper_detected_and_plan_unavailable(self) -> None:
        classification = classify_sql(
            sql_id="9b2f6f8h1j3k5",
            sql_text="BEGIN :1 := orderentry.neworder(:2,:3,:4); END;",
            current_stats={"parsing_schema_name": "APP", "module": "ORDER"},
            active_queries=[],
        )
        self.assertEqual(classification.classification, "plsql_wrapper")
        analysis = _plan_analysis(
            current={"sql_kind": "PL_SQL_WRAPPER", "plan_hash_value": 0},
            children=[],
            awr={"plan_changes": []},
            lookback_days=1,
            execution_plan={"source_used": None},
        )
        self.assertEqual(analysis["status"], "PLAN_UNAVAILABLE")
        self.assertNotIn("stable", str(analysis.get("stability") or "").lower())

    def test_sql_id_parser_rejects_invalid_and_accepts_valid(self) -> None:
        self.assertEqual(_sql_ids_from_line("5188075855872 95.3"), [])
        self.assertEqual(_sql_ids_from_line("configuration section"), [])
        self.assertEqual(_sql_ids_from_line("Top SQL 3nkd7x4r8w1pb 95.3"), ["3nkd7x4r8w1pb"])

    def test_blocking_count_zero_prevents_current_blocking_rca(self) -> None:
        supporting = {
            "history_context": {"latest_run": {"metrics": {"blocking_count": 0, "blocking_critical_count": 0, "blocking_warning_count": 0}}},
            "active_sessions": {"blocking_count": 0, "blocking_critical_count": 0, "blocking_warning_count": 0},
        }
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="enq: TX - row lock contention")
        self.assertNotEqual(rc.get("category"), "blocking_lock")

    def test_active_idle_only_prevents_rca(self) -> None:
        supporting = {
            "history_context": {
                "latest_run": {
                    "metrics": {
                        "active_sessions": 25,
                        "true_active_non_idle": 0,
                        "active_idle_waiting": 25,
                        "on_cpu_sessions": 0,
                        "blocking_count": 0,
                    }
                }
            }
        }
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="ACTIVE sessions mostly PL/SQL lock timer Idle")
        self.assertIn(rc.get("category"), {"inconclusive", "unknown_pattern"})

    def test_io_root_cause_confidence_capped_when_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runtime_root = Path(td) / "runtime" / "databases"
            trace_path = runtime_root / "db1" / "traces" / "health_runs.jsonl"
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            trace_path.write_text(
                (
                    '{"run_id":"r1","recorded_at":"2026-05-01T00:00:00Z","completed_at":"2026-05-01T00:00:00Z",'
                    '"database_name":"DB1","overall_status":"WARNING","summary":"io wait",'
                    '"metrics":{"io_wait_ms":50.0},"issues":[{"category":"io","title":"I/O pressure","severity":"CRITICAL","description":"io"}]}\n'
                ),
                encoding="utf-8",
            )
            with (
                patch.dict("os.environ", {"ODB_AUTODBA_RUNTIME_ROOT": str(runtime_root)}, clear=False),
                patch("odb_autodba.agents.correlation_engine._build_missing_evidence", return_value=["missing_io_wait_or_disk_latency_evidence"]),
                patch(
                    "odb_autodba.agents.correlation_engine._score_candidates",
                    return_value={
                        "primary_category": "io_bottleneck",
                        "scores": {"io_bottleneck": 0.9},
                        "score_components": {"io_bottleneck": {}},
                        "primary_evidence": ["io trend"],
                        "contributing_factors": [],
                    },
                ),
            ):
                result = correlate_root_cause_from_traces("db1")
        primary = result.get("primary_cause") or {}
        self.assertEqual(primary.get("category"), "io_bottleneck")
        self.assertNotEqual(primary.get("confidence"), "HIGH")

    def test_memory_normal_indicators_do_not_emit_memory_pressure_rca(self) -> None:
        supporting = {
            "memory_config": {"pga_mb": 1.89, "pga_to_sga_pct": 0.12, "temp_consumer_count": 0, "top_pga_sessions": []},
            "history_context": {
                "latest_run": {
                    "metrics": {
                        "pga_mb": 1.89,
                        "pga_to_sga_pct": 0.12,
                        "host_memory_pct": 32.94,
                        "container_memory_pct": 15.19,
                        "temp_consumer_count": 0,
                        "temp_usage_pct": 0.0,
                        "memory_hotspot_triggered": False,
                    }
                }
            },
            "state_transition": {"learning_features": {"memory_pressure_flag": True}},
        }
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="PGA in use 1.89 MB")
        self.assertNotEqual(rc.get("category"), "memory_pressure")

    def test_tiny_sql_elapsed_movement_under_low_db_time_not_regression(self) -> None:
        supporting = {
            "history_context": {"latest_run": {"metrics": {"top_elapsed_sql_elapsed_s": 1.02, "db_time_s": 8.0}}},
            "state_transition": {"learning_features": {"sql_regression_flag": True, "sql_elapsed_delta": 0.70, "sql_cpu_delta": 0.10}},
        }
        rc = infer_root_cause(mode="health", summary="x", supporting_data=supporting, rendered_report="SQL elapsed 0.32s -> 1.02s")
        self.assertNotEqual(rc.get("category"), "sql_regression")

    def test_services_query_fallback_without_aq_ha_notifications(self) -> None:
        calls: list[str] = []

        def fake_fetch_all(sql: str, binds=None, *, max_rows=None):  # noqa: ANN001
            calls.append(" ".join(sql.lower().split()))
            if "from gv$active_services" in sql.lower():
                return ([], "insufficient privileges")
            if "from v$active_services" in sql.lower():
                return ([{"inst_id": None, "name": "FREEPDB1", "network_name": "FREEPDB1", "con_id": 3, "container_name": "FREEPDB1"}], None)
            if "aq_ha_notifications" in sql.lower():
                return ([], "ORA-00904: \"AQ_HA_NOTIFICATIONS\": invalid identifier")
            if "from gv$services" in sql.lower():
                return ([{"inst_id": 1, "name": "FREEPDB1", "network_name": "FREEPDB1", "con_id": 3, "goal": None, "clb_goal": None}], None)
            return ([], None)

        with patch("odb_autodba.db.extended_health_checks._fetch_all", side_effect=fake_fetch_all):
            services = _services_and_routing(role_mode={})
        self.assertTrue((services.get("configured_services") or []))
        self.assertIn("fallback query used without aq_ha_notifications", str(services.get("configured_error") or "").lower())
        self.assertTrue(any("aq_ha_notifications" in sql for sql in calls))

    def test_correlation_blocking_score_zero_when_latest_blocking_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runtime_root = Path(td) / "runtime" / "databases"
            trace_path = runtime_root / "db1" / "traces" / "health_runs.jsonl"
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            rows = [
                {
                    "run_id": "r1",
                    "recorded_at": "2026-05-01T00:00:00Z",
                    "completed_at": "2026-05-01T00:00:00Z",
                    "database_name": "DB1",
                    "overall_status": "CRITICAL",
                    "summary": "blocking",
                    "metrics": {"blocking_count": 3},
                    "issues": [{"category": "blocking", "title": "Lock contention", "severity": "CRITICAL", "description": "blocking"}],
                },
                {
                    "run_id": "r2",
                    "recorded_at": "2026-05-02T00:00:00Z",
                    "completed_at": "2026-05-02T00:00:00Z",
                    "database_name": "DB1",
                    "overall_status": "OK",
                    "summary": "cleared",
                    "metrics": {"blocking_count": 0},
                    "issues": [],
                },
            ]
            trace_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with patch.dict("os.environ", {"ODB_AUTODBA_RUNTIME_ROOT": str(runtime_root)}, clear=False):
                corr = correlate_root_cause_from_traces("db1")
        self.assertEqual(float((((corr.get("score_components") or {}).get("blocking_lock") or {}).get("weighted_score") or 0.0)), 0.0)

    def test_correlation_storage_alert_score_zero_when_no_current_alert_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runtime_root = Path(td) / "runtime" / "databases"
            trace_path = runtime_root / "db1" / "traces" / "health_runs.jsonl"
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            rows = [
                {
                    "run_id": "r1",
                    "recorded_at": "2026-05-01T00:00:00Z",
                    "completed_at": "2026-05-01T00:00:00Z",
                    "database_name": "DB1",
                    "overall_status": "WARNING",
                    "summary": "old ora",
                    "metrics": {"alert_log_count": 2},
                    "issues": [{"category": "alert", "title": "ORA/TNS errors", "severity": "WARNING", "description": "old"}],
                },
                {
                    "run_id": "r2",
                    "recorded_at": "2026-05-02T00:00:00Z",
                    "completed_at": "2026-05-02T00:00:00Z",
                    "database_name": "DB1",
                    "overall_status": "OK",
                    "summary": "cleared",
                    "metrics": {"alert_log_count": 0, "listener_error_count": 0},
                    "issues": [],
                },
            ]
            trace_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with patch.dict("os.environ", {"ODB_AUTODBA_RUNTIME_ROOT": str(runtime_root)}, clear=False):
                corr = correlate_root_cause_from_traces("db1")
        self.assertEqual(float((((corr.get("score_components") or {}).get("storage_or_alert_error") or {}).get("weighted_score") or 0.0)), 0.0)

    def test_correlation_io_microsecond_latency_not_high(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runtime_root = Path(td) / "runtime" / "databases"
            trace_path = runtime_root / "db1" / "traces" / "health_runs.jsonl"
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            rows = [
                {
                    "run_id": "r1",
                    "recorded_at": "2026-05-01T00:00:00Z",
                    "completed_at": "2026-05-01T00:00:00Z",
                    "database_name": "DB1",
                    "overall_status": "WARNING",
                    "summary": "io",
                    "metrics": {"io_wait_ms": 0.06, "top_elapsed_sql_elapsed_s": 1.02, "db_time_s": 8.0},
                    "issues": [{"category": "io", "title": "I/O pressure", "severity": "WARNING", "description": "tiny latency"}],
                }
            ]
            trace_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with patch.dict("os.environ", {"ODB_AUTODBA_RUNTIME_ROOT": str(runtime_root)}, clear=False):
                corr = correlate_root_cause_from_traces("db1")
        primary = corr.get("primary_cause") or {}
        if primary.get("category") == "io_bottleneck":
            self.assertIn(primary.get("confidence"), {"LOW"})

    def test_ash_top_cpu_action_requires_minimum_samples(self) -> None:
        actions_low = _performance_actions({"top_cpu_sql": {"sql_id": "abc123", "cpu_pct": 82.0, "total_oncpu_samples": 8}}, hours=24)
        actions_high = _performance_actions({"top_cpu_sql": {"sql_id": "abc123", "cpu_pct": 82.0, "total_oncpu_samples": 80}}, hours=24)
        self.assertFalse(any(action.title == "ASH top CPU SQL concentration" for action in actions_low))
        self.assertTrue(any(action.title == "ASH top CPU SQL concentration" for action in actions_high))


if __name__ == "__main__":
    unittest.main()
