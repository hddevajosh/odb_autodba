from __future__ import annotations

import os
from unittest.mock import patch

from odb_autodba.config import get_default_oracle_target, make_db_key


TARGET_ENV_NAMES = (
    "ODB_AUTODBA_ENVIRONMENT",
    "ORACLE_HOST",
    "ORACLE_PORT",
    "ORACLE_SERVICE_NAME",
    "ORACLE_SERVICE",
    "ORACLE_SID",
    "ORACLE_PDB_NAME",
    "ORACLE_CDB_NAME",
    "ORACLE_USER",
    "ORACLE_PASSWORD",
    "ORACLE_PASS",
    "ORACLE_DSN",
    "ORACLE_SYSDBA",
    "DB_HOST",
    "DB_PORT",
    "DB_SERVICE",
    "DB_SID",
    "DB_PDB_NAME",
    "DB_CDB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_DSN",
)


def test_make_db_key_normalization() -> None:
    key = make_db_key(" Prod ", " Ora Host_01 ", "1521", " PDB$1 ")
    assert key == "prod__ora-host-01__1521__pdb-1"


def test_get_default_oracle_target_from_env() -> None:
    env = _clean_env()
    env.update(
        {
            "ODB_AUTODBA_ENVIRONMENT": "prod",
            "ORACLE_HOST": "ora-host01",
            "ORACLE_PORT": "1521",
            "ORACLE_SERVICE_NAME": "freepdb1",
            "ORACLE_USER": "system",
            "ORACLE_PASSWORD": "super-secret",
            "ORACLE_SYSDBA": "true",
        }
    )
    with patch.dict(os.environ, env, clear=True):
        target = get_default_oracle_target()

    assert target.environment == "prod"
    assert target.host == "ora-host01"
    assert target.port == 1521
    assert target.username == "system"
    assert target.service_name == "freepdb1"
    assert target.sysdba is True
    assert target.db_key == "prod__ora-host01__1521__freepdb1"
    assert target.display_name == "prod:ora-host01:1521:freepdb1"


def test_pdb_priority_over_service_name() -> None:
    env = _clean_env()
    env.update(
        {
            "ODB_AUTODBA_ENVIRONMENT": "dev",
            "ORACLE_HOST": "localhost",
            "ORACLE_PORT": "1521",
            "ORACLE_SERVICE_NAME": "freepdb1",
            "ORACLE_PDB_NAME": "salespdb",
            "ORACLE_USER": "system",
            "ORACLE_PASSWORD": "super-secret",
        }
    )
    with patch.dict(os.environ, env, clear=True):
        target = get_default_oracle_target()

    assert target.service_or_sid_or_pdb == "salespdb"
    assert target.db_key.endswith("__salespdb")


def test_safe_dict_does_not_include_password() -> None:
    env = _clean_env()
    env.update(
        {
            "ODB_AUTODBA_ENVIRONMENT": "test",
            "ORACLE_HOST": "db01",
            "ORACLE_PORT": "1521",
            "ORACLE_SERVICE_NAME": "freepdb1",
            "ORACLE_USER": "system",
            "ORACLE_PASSWORD": "ultra-secret",
        }
    )
    with patch.dict(os.environ, env, clear=True):
        target = get_default_oracle_target()

    payload = target.safe_dict()
    assert "password" not in payload
    assert "ultra-secret" not in str(payload)


def _clean_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key not in TARGET_ENV_NAMES}
