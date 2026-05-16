from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from odb_autodba.config import OracleTarget
from odb_autodba.frontend import gradio_app
from odb_autodba.mcp import client as mcp_client
from odb_autodba.mcp.jobs import create_job, get_job, update_job


class SecretRedactionTests(unittest.TestCase):
    class _Target:
        def __init__(self, db_key: str) -> None:
            self.db_key = db_key

    def test_job_payload_and_result_redact_secret_like_keys(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job(
                    "investigation",
                    db_key="db1",
                    payload={
                        "question": "x",
                        "password": "secret-pass",
                        "api_key": "secret-api",
                        "nested": {"private_key": "secret-private", "token_value": "secret-token"},
                    },
                )
                update_job(job["job_id"], result={"credential": "secret-credential", "ok": True})
                text = (Path(td) / f"{job['job_id']}.json").read_text(encoding="utf-8")
                self.assertNotIn("secret-pass", text)
                self.assertNotIn("secret-api", text)
                self.assertNotIn("secret-private", text)
                self.assertNotIn("secret-token", text)
                self.assertNotIn("secret-credential", text)
                payload = get_job(job["job_id"]) or {}
                self.assertIn("***REDACTED***", json.dumps(payload, ensure_ascii=True))

    def test_password_env_survives_safe_mcp_target_payload_without_value(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"ODB_AUTODBA_JOBS_DIR": td}, clear=False), patch(
                "odb_autodba.mcp.jobs.get_oracle_target",
                return_value=self._Target("db1"),
            ):
                job = create_job(
                    "health_check",
                    db_key="db1",
                    payload={"target": {"environment": "dev", "host": "db", "port": 1521, "username": "system", "service_name": "PDB1", "password_env": "ORACLE_PASSWORD"}},
                )
                text = (Path(td) / f"{job['job_id']}.json").read_text(encoding="utf-8")
        self.assertIn("ORACLE_PASSWORD", text)
        self.assertNotIn("unit-secret", text)

    def test_safe_dict_hides_password_env_name(self) -> None:
        target = OracleTarget(
            db_key="dev__db__1521__pdb1",
            environment="dev",
            host="db",
            port=1521,
            username="system",
            service_name="PDB1",
            password_env="TOP_SECRET_PASSWORD_ENV",
        )
        safe = target.safe_dict()
        self.assertNotIn("password_env", safe)
        self.assertTrue(safe.get("password_env_present"))
        self.assertNotIn("TOP_SECRET_PASSWORD_ENV", str(safe))

    def test_error_sanitizers_cover_common_secret_shapes(self) -> None:
        text = "password=abc123 token=tok123value secret=s456 api_key=k789 private_key=p000 system/manager@db //user:pass@host"
        self.assertNotIn("abc", gradio_app._safe_error_message(text))
        self.assertNotIn("tok123value", mcp_client._sanitize_error_message(text))
        self.assertNotIn("manager", gradio_app._safe_error_message(text))
        self.assertNotIn(":pass@", mcp_client._sanitize_error_message(text))


if __name__ == "__main__":
    unittest.main()
