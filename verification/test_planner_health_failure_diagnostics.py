from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from odb_autodba.agents.planner_agent import PlannerAgent
from odb_autodba.config import OracleTarget


class PlannerHealthFailureDiagnosticsTests(unittest.TestCase):
    def test_failed_health_check_includes_sanitized_supporting_data(self) -> None:
        target = OracleTarget(
            db_key="prod__ora-host01__1521__pdb1",
            environment="prod",
            host="ora-host01",
            port=1521,
            username="system",
            service_name="FREEPDB1",
            connect_descriptor="scott/tiger@ora-host01/FREEPDB1",
            display_name="prod:ora-host01:1521:FREEPDB1",
            sysdba=False,
        )
        error = RuntimeError("password=SuperSecret! token=tok_abc dsn=scott/tiger@ora-host01/FREEPDB1")
        with patch("odb_autodba.agents.planner_agent.collect_health_snapshot", side_effect=error), patch(
            "odb_autodba.agents.planner_agent.get_oracle_target",
            return_value=target,
        ):
            response = PlannerAgent().handle_message("Check health of my Oracle database")

        self.assertEqual(response.summary, "Oracle health check could not be completed.")
        supporting = response.supporting_data
        self.assertEqual(supporting.get("failure_stage"), "collect_health_snapshot")
        self.assertEqual(supporting.get("error_type"), "RuntimeError")
        self.assertEqual(supporting.get("db_key"), target.db_key)
        self.assertIsInstance(supporting.get("target"), dict)
        self.assertIn("error_message", supporting)
        self.assertNotIn("password", supporting.get("target", {}))

        error_message = supporting.get("error_message") or ""
        self.assertIn("***REDACTED***", error_message)
        self.assertNotIn("SuperSecret!", error_message)
        self.assertNotIn("tok_abc", error_message)
        self.assertNotIn("scott/tiger", error_message)

    def test_failed_health_check_supporting_data_does_not_leak_passwords(self) -> None:
        target = OracleTarget(
            db_key="prod__ora-host01__1521__pdb1",
            environment="prod",
            host="ora-host01",
            port=1521,
            username="system",
            service_name="FREEPDB1",
            connect_descriptor="//scott:WalletPwd@ora-host01/FREEPDB1",
            display_name="prod:ora-host01:1521:FREEPDB1",
            sysdba=False,
        )
        error = RuntimeError("secret=mysecret wallet_password=abc123")
        with patch("odb_autodba.agents.planner_agent.collect_health_snapshot", side_effect=error), patch(
            "odb_autodba.agents.planner_agent.get_oracle_target",
            return_value=target,
        ):
            response = PlannerAgent().handle_message("Check health of my Oracle database")

        payload = json.dumps(response.supporting_data, sort_keys=True)
        self.assertNotIn("WalletPwd", payload)
        self.assertNotIn("abc123", payload)
        self.assertNotIn("mysecret", payload)
        self.assertIn("***REDACTED***", payload)


if __name__ == "__main__":
    unittest.main()
