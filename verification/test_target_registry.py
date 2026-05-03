from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.target_registry import (
    get_oracle_target,
    get_target_password,
    list_oracle_targets_safe,
    load_oracle_targets,
)


class TargetRegistryTests(unittest.TestCase):
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
        env.pop("ODB_AUTODBA_TARGETS_FILE", None)
        return env

    def test_missing_registry_falls_back_to_default_target(self) -> None:
        env = self._base_env()
        env["ODB_AUTODBA_TARGETS_FILE"] = "/tmp/does-not-exist-oracle-targets.yaml"
        with patch.dict(os.environ, env, clear=True):
            targets = load_oracle_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].host, "localhost")
        self.assertEqual(targets[0].service_name, "FREEPDB1")

    def test_yaml_registry_loads_multiple_targets(self) -> None:
        env = self._base_env()
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
                    display_name: Local Oracle Free
                    tags: [local, dev]

                  - environment: prod
                    host: prod-db01.example.com
                    port: 1521
                    service_name: PDB1
                    username: app_monitor
                    password_env: PROD_DB01_PASSWORD
                    display_name: PROD DB01 PDB1
                    tags: [prod, critical]
                """,
                encoding="utf-8",
            )
            env["ODB_AUTODBA_TARGETS_FILE"] = str(path)
            with patch.dict(os.environ, env, clear=True):
                targets = load_oracle_targets()
                safe = list_oracle_targets_safe()

        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].display_name, "Local Oracle Free")
        self.assertEqual(targets[1].host, "prod-db01.example.com")
        self.assertEqual(safe[0].get("password_env_present"), True)

    def test_duplicate_db_key_fails_clearly(self) -> None:
        env = self._base_env()
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

                  - environment: dev
                    host: localhost
                    port: 1521
                    service_name: FREEPDB1
                    username: app_monitor
                    password_env: PROD_DB01_PASSWORD
                """,
                encoding="utf-8",
            )
            env["ODB_AUTODBA_TARGETS_FILE"] = str(path)
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(ValueError) as ctx:
                    load_oracle_targets()
        self.assertIn("Duplicate db_key", str(ctx.exception))

    def test_safe_target_list_does_not_expose_password(self) -> None:
        env = self._base_env()
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
                """,
                encoding="utf-8",
            )
            env["ODB_AUTODBA_TARGETS_FILE"] = str(path)
            env["ORACLE_PASSWORD"] = "very-secret"
            with patch.dict(os.environ, env, clear=True):
                safe = list_oracle_targets_safe()
        payload = str(safe)
        self.assertNotIn("very-secret", payload)
        self.assertNotIn("'password':", payload.lower())
        self.assertTrue(any(bool(row.get("password_env_present")) for row in safe))

    def test_get_oracle_target_by_db_key_returns_correct_target(self) -> None:
        env = self._base_env()
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
                    port: 1521
                    service_name: PDB1
                    username: app_monitor
                    password_env: PROD_DB01_PASSWORD
                """,
                encoding="utf-8",
            )
            env["ODB_AUTODBA_TARGETS_FILE"] = str(path)
            with patch.dict(os.environ, env, clear=True):
                targets = load_oracle_targets()
                selected = get_oracle_target(targets[1].db_key)
        self.assertEqual(selected.host, "prod-db01.example.com")

    def test_get_target_password_prefers_password_env(self) -> None:
        env = self._base_env()
        env["ORACLE_PASSWORD"] = "default-secret"
        env["PROD_DB01_PASSWORD"] = "prod-secret"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "oracle_targets.yaml"
            path.write_text(
                """
                targets:
                  - environment: prod
                    host: prod-db01.example.com
                    port: 1521
                    service_name: PDB1
                    username: app_monitor
                    password_env: PROD_DB01_PASSWORD
                """,
                encoding="utf-8",
            )
            env["ODB_AUTODBA_TARGETS_FILE"] = str(path)
            with patch.dict(os.environ, env, clear=True):
                target = load_oracle_targets()[0]
                password = get_target_password(target)
        self.assertEqual(password, "prod-secret")


if __name__ == "__main__":
    unittest.main()
