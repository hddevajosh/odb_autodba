from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.db.connection import load_connection_settings
from odb_autodba.target_registry import build_transient_target, clear_transient_targets, register_transient_target


class ConnectionTargetRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_transient_targets()

    def tearDown(self) -> None:
        clear_transient_targets()

    def _base_env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "ODB_AUTODBA_ENVIRONMENT": "default",
                "ORACLE_HOST": "localhost",
                "ORACLE_PORT": "1521",
                "ORACLE_SERVICE_NAME": "FREEPDB1",
                "ORACLE_USER": "system",
                "ORACLE_PASSWORD": "default-secret",
            }
        )
        return env

    def test_load_connection_settings_uses_selected_target_and_password_env(self) -> None:
        env = self._base_env()
        env["PROD_DB01_PASSWORD"] = "prod-secret"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "oracle_targets.yaml"
            path.write_text(
                """
                targets:
                  - environment: dev
                    host: localhost
                    port: 1521
                    service_name: FREEPDB1
                    username: system
                    password_env: ORACLE_PASSWORD

                  - environment: prod
                    host: prod-db01.example.com
                    port: 1522
                    service_name: PDB1
                    username: app_monitor
                    password_env: PROD_DB01_PASSWORD
                """,
                encoding="utf-8",
            )
            env["ODB_AUTODBA_TARGETS_FILE"] = str(path)
            with patch.dict(os.environ, env, clear=True):
                from odb_autodba.target_registry import load_oracle_targets

                target = load_oracle_targets()[1]
                settings = load_connection_settings(db_key=target.db_key)

        self.assertEqual(settings.host, "prod-db01.example.com")
        self.assertEqual(settings.port, 1522)
        self.assertEqual(settings.service_name, "PDB1")
        self.assertEqual(settings.user, "app_monitor")
        self.assertEqual(settings.password, "prod-secret")

    def test_load_connection_settings_fallback_default_password_envs(self) -> None:
        env = self._base_env()
        env.pop("ORACLE_PASSWORD", None)
        env["DB_PASSWORD"] = "db-fallback-secret"
        with patch.dict(os.environ, env, clear=True):
            settings = load_connection_settings()
        self.assertEqual(settings.password, "db-fallback-secret")

    def test_load_connection_settings_uses_transient_runtime_password(self) -> None:
        env = self._base_env()
        env["ORACLE_PASSWORD"] = "default-secret"
        with patch.dict(os.environ, env, clear=True):
            target = build_transient_target(
                environment="adhoc",
                host="prod-db99.example.com",
                port=1521,
                username="monitor",
                service_name="PDB99",
                display_name="Adhoc PDB99",
            )
            register_transient_target(target, password="runtime-secret", replace=True)
            settings = load_connection_settings(db_key=target.db_key)
        self.assertEqual(settings.host, "prod-db99.example.com")
        self.assertEqual(settings.user, "monitor")
        self.assertEqual(settings.service_name, "PDB99")
        self.assertEqual(settings.password, "runtime-secret")


if __name__ == "__main__":
    unittest.main()
