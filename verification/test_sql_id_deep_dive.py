from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.db.plan_checks import collect_formatted_execution_plan
from odb_autodba.db.query_deep_dive import (
    _dba_recommendation,
    classify_sql,
    collect_sql_wait_profile,
)
from odb_autodba.models.schemas import (
    SqlClassification,
    SqlIdDeepDive,
    SqlImpactSummary,
    SqlWaitProfile,
)
from odb_autodba.utils.formatter import render_sql_id_deep_dive_report


class SqlIdDeepDiveTests(unittest.TestCase):
    def test_wait_profile_available_from_ash(self) -> None:
        ash_profile = SqlWaitProfile(
            available=True,
            source_used="v$active_session_history",
            sample_count=12,
            top_event="db file sequential read",
            top_wait_class="User I/O",
            user_io_pct=50.0,
        )
        awr_profile = SqlWaitProfile(available=False, source_used="dba_hist_active_sess_history")
        with (
            patch("odb_autodba.db.query_deep_dive._ash_wait_profile", return_value=ash_profile),
            patch("odb_autodba.db.query_deep_dive._awr_wait_profile", return_value=awr_profile),
        ):
            profile = collect_sql_wait_profile(
                sql_id="abc123xyz9",
                active_queries=[],
                lookback_days=7,
                notes=[],
            )
        self.assertTrue(profile.available)
        self.assertEqual(profile.source_used, "v$active_session_history")
        self.assertEqual(profile.sample_count, 12)

    def test_wait_profile_unavailable(self) -> None:
        with (
            patch(
                "odb_autodba.db.query_deep_dive._ash_wait_profile",
                return_value=SqlWaitProfile(available=False, source_used="v$active_session_history"),
            ),
            patch(
                "odb_autodba.db.query_deep_dive._awr_wait_profile",
                return_value=SqlWaitProfile(available=False, source_used="dba_hist_active_sess_history"),
            ),
        ):
            profile = collect_sql_wait_profile(
                sql_id="abc123xyz9",
                active_queries=[],
                lookback_days=7,
                notes=[],
            )
        self.assertFalse(profile.available)
        self.assertIn("No wait evidence", profile.interpretation)

    def test_dbms_xplan_display_cursor_success(self) -> None:
        def fake_fetch_all(sql: str, binds=None, max_rows=None):  # noqa: ANN001
            lowered = " ".join(sql.lower().split())
            if "display_cursor" in lowered:
                return [
                    {"plan_table_output": "Plan hash value: 123"},
                    {"plan_table_output": "| Id | Operation | Name |"},
                    {"plan_table_output": "| 0  | SELECT STATEMENT | |"},
                ]
            return []

        with patch("odb_autodba.db.plan_checks.fetch_all", side_effect=fake_fetch_all):
            section = collect_formatted_execution_plan(
                sql_id="abc123xyz9",
                current_stats={"plan_hash_value": 123},
                child_cursors=[{"child_number": 0}],
                awr={},
                raw_plan_lines=[],
            )
        self.assertTrue(section.available)
        self.assertEqual(section.source_used, "DBMS_XPLAN.DISPLAY_CURSOR")
        self.assertTrue(any("Plan hash value" in line for line in section.lines))

    def test_dbms_xplan_fallback_on_privilege_failure(self) -> None:
        def fake_fetch_all(sql: str, binds=None, max_rows=None):  # noqa: ANN001
            lowered = " ".join(sql.lower().split())
            if "display_cursor" in lowered or "display_awr" in lowered:
                raise RuntimeError("ORA-00942: table or view does not exist")
            return []

        with (
            patch("odb_autodba.db.plan_checks.fetch_all", side_effect=fake_fetch_all),
            patch("odb_autodba.db.plan_checks.fetch_one", return_value={"dbid": 999}),
        ):
            section = collect_formatted_execution_plan(
                sql_id="abc123xyz9",
                current_stats={"plan_hash_value": 321},
                child_cursors=[],
                awr={"plan_changes": [{"plan_hash_value": 321}]},
                raw_plan_lines=[
                    {
                        "id": 1,
                        "parent_id": 0,
                        "operation": "TABLE ACCESS",
                        "options": "FULL",
                        "object_name": "BIG_TABLE",
                        "cost": 100,
                        "cardinality": 1000,
                    }
                ],
            )
        self.assertEqual(section.source_used, "v$sql_plan (fallback)")
        self.assertTrue(any("BIG_TABLE" in line for line in section.lines))
        self.assertIn("Full scans", section.interpretation)

    def test_classification_sys_dictionary_sql(self) -> None:
        result = classify_sql(
            sql_id="abc123xyz9",
            sql_text="select sid, serial# from v$session",
            current_stats={"parsing_schema_name": "SYS", "module": "JDBC Thin Client"},
            active_queries=[],
        )
        self.assertEqual(result.classification, "dictionary_sql")
        self.assertIn("dictionary", result.explanation.lower())

    def test_recommendation_generation_io_waits(self) -> None:
        recommendation = _dba_recommendation(
            classification=SqlClassification(classification="application_sql", confidence="HIGH", explanation="app"),
            wait_profile=SqlWaitProfile(
                available=True,
                sample_count=20,
                source_used="v$active_session_history",
                user_io_pct=55.0,
                system_io_pct=10.0,
                top_wait_class="User I/O",
            ),
            impact_summary=SqlImpactSummary(
                executions=200,
                elapsed_s_total=500.0,
                impact_summary="Top workload contributor pattern. SQL is likely material to system performance.",
            ),
            lock_analysis={"as_blocker_count": 0, "as_waiter_count": 0},
            plan_analysis={"churn_detected": False},
            risk_summary={"status": "WARNING"},
            awr={"totals": {"executions": 200}},
        )
        self.assertTrue(any("I/O" in line for line in recommendation.rationale))
        self.assertGreaterEqual(len(recommendation.next_actions), 1)

    def test_formatter_rendering_order(self) -> None:
        deep_dive = SqlIdDeepDive(
            sql_id="abc123xyz9",
            sql_text="select * from dual",
            current_stats={"executions": 10, "elapsed_s": 1.2},
            active_queries=[],
            wait_profile=SqlWaitProfile(available=False, source_used=None, interpretation="No wait evidence."),
            classification=SqlClassification(classification="application_sql", confidence="HIGH", explanation="app sql"),
            impact_summary=SqlImpactSummary(executions=10, impact_summary="Visible SQL with currently low-to-moderate impact."),
            child_cursors=[],
            execution_plan={"available": False, "lines": [], "interpretation": "No plan evidence."},
            plan_analysis={"stability": "stable", "summary": "1 plan"},
            history_analysis={"runs_scanned": 0, "matched_runs": []},
            risk_summary={"status": "OK", "reason_lines": ["No strong risk signal."]},
            dba_recommendation={"severity": "INFO", "recommendation": "No tuning required", "rationale": ["Low impact."]},
            notes=["collector note"],
        )
        rendered = render_sql_id_deep_dive_report(deep_dive)
        expected_order = [
            "## SQL Text",
            "## SQL Classification",
            "## Current Cursor Evidence",
            "## Live Session Correlation",
            "## SQL Wait Profile",
            "## Impact Summary",
            "## Child Cursor Summary",
            "## Execution Plan",
            "## Plan Interpretation",
            "## Plan Stability Analysis",
            "## Historical Recurrence",
            "## Risk Verdict",
            "## DBA Recommendation",
            "## Collector Notes",
        ]
        positions = [rendered.find(section) for section in expected_order]
        self.assertTrue(all(index >= 0 for index in positions))
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
