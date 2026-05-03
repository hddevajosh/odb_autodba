from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.agents.planner_agent import PlannerAgent
from odb_autodba.models.schemas import BlockingChain, SessionRow


class PlannerActiveSessionsTests(unittest.TestCase):
    def test_show_active_sessions_returns_focused_report_without_health_snapshot(self) -> None:
        active = [
            SessionRow(
                inst_id=1,
                sid=42,
                serial_num=11,
                username="APP",
                status="ACTIVE",
                sql_id="abc12345",
                event="db file sequential read",
                wait_class="User I/O",
                module="app",
            )
        ]
        blocking = [
            BlockingChain(
                blocker_inst_id=1,
                blocker_sid=10,
                blocker_serial=20,
                blocker_user="APP",
                blocked_inst_id=1,
                blocked_sid=42,
                blocked_serial=11,
                blocked_user="APP",
            )
        ]
        resource_rows = [{"inst_id": 1, "sid": 42, "sql_id": "abc12345", "cpu_seconds": 12.3}]

        with patch("odb_autodba.agents.planner_agent.get_running_sessions_inventory", return_value=active), patch(
            "odb_autodba.agents.planner_agent.get_blocking_chains",
            return_value=blocking,
        ), patch(
            "odb_autodba.agents.planner_agent.get_top_session_resource_candidates",
            return_value=resource_rows,
        ), patch(
            "odb_autodba.agents.planner_agent.collect_health_snapshot",
            side_effect=AssertionError("health snapshot should not be used"),
        ):
            response = PlannerAgent().handle_message("show active sessions")

        self.assertEqual(response.mode, "focused_domain_report")
        self.assertIn("Active session snapshot collected", response.summary)
        self.assertIn("# Active Sessions", response.body_markdown)
        self.assertIn("Active Session Inventory", response.body_markdown)
        self.assertEqual((response.supporting_data.get("active_sessions") or {}).get("active_count"), 1)


if __name__ == "__main__":
    unittest.main()
