from __future__ import annotations

import os
from unittest.mock import patch

from odb_autodba.db.connection import load_connection_settings


CONNECTION_ENV_NAMES = (
    "ORACLE_HOST",
    "ORACLE_PORT",
    "ORACLE_SERVICE_NAME",
    "ORACLE_SERVICE",
    "ORACLE_USER",
    "ORACLE_PASSWORD",
    "ORACLE_PASS",
    "ORACLE_DSN",
    "DB_HOST",
    "DB_PORT",
    "DB_SERVICE",
    "DB_USER",
    "DB_PASSWORD",
    "DB_DSN",
)


def test_connection_settings_accept_db_env_aliases():
    env = _clean_env()
    env.update(
        {
            "DB_HOST": "db-host",
            "DB_PORT": "1522",
            "DB_SERVICE": "db-service",
            "DB_USER": "db-user",
            "DB_PASSWORD": "db-password",
        }
    )

    with patch.dict(os.environ, env, clear=True):
        settings = load_connection_settings()

    assert settings.host == "db-host"
    assert settings.port == 1522
    assert settings.service_name == "db-service"
    assert settings.user == "db-user"
    assert settings.password == "db-password"


def test_connection_settings_prefers_oracle_env():
    env = _clean_env()
    env.update(
        {
            "DB_HOST": "db-host",
            "DB_PORT": "1522",
            "DB_SERVICE": "db-service",
            "DB_USER": "db-user",
            "DB_PASSWORD": "db-password",
            "ORACLE_HOST": "oracle-host",
            "ORACLE_PORT": "1523",
            "ORACLE_SERVICE_NAME": "oracle-service",
            "ORACLE_USER": "oracle-user",
            "ORACLE_PASSWORD": "oracle-password",
        }
    )

    with patch.dict(os.environ, env, clear=True):
        settings = load_connection_settings()

    assert settings.host == "oracle-host"
    assert settings.port == 1523
    assert settings.service_name == "oracle-service"
    assert settings.user == "oracle-user"
    assert settings.password == "oracle-password"


def _clean_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key not in CONNECTION_ENV_NAMES}
