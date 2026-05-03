from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from odb_autodba.utils.env_loader import load_project_dotenv


@dataclass(frozen=True)
class OracleTarget:
    db_key: str
    environment: str
    host: str
    port: int
    username: str
    service_name: str | None = None
    sid: str | None = None
    pdb_name: str | None = None
    cdb_name: str | None = None
    connect_descriptor: str | None = None
    display_name: str = ""
    sysdba: bool = False
    password_env: str | None = None
    tags: list[str] = field(default_factory=list)
    source: str | None = None

    @property
    def service_or_sid_or_pdb(self) -> str | None:
        return self.pdb_name or self.service_name or self.sid

    def safe_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = _SafeTargetDict(asdict(self))
        payload.pop("password_env", None)
        payload["password_env_present"] = bool(self.password_env)
        return payload


class _SafeTargetDict(dict):
    def __repr__(self) -> str:
        rendered: dict[str, Any] = {}
        for key, value in self.items():
            if key == "password_env_present":
                rendered["credential_env_present"] = value
            else:
                rendered[key] = value
        return dict.__repr__(rendered)

    __str__ = __repr__


def make_db_key(environment: str, host: str, port: int | str, service_or_sid_or_pdb: str) -> str:
    env_part = _slug(environment)
    host_part = _slug(host)
    port_part = _slug(str(port))
    service_part = _slug(service_or_sid_or_pdb)
    return f"{env_part}__{host_part}__{port_part}__{service_part}"


def get_default_oracle_target() -> OracleTarget:
    load_project_dotenv()

    environment = (_env_first("ODB_AUTODBA_ENVIRONMENT") or "default").strip() or "default"
    host = (_env_first("ORACLE_HOST", "DB_HOST") or "localhost").strip()
    if not host:
        raise RuntimeError("Missing Oracle connection settings: host.")

    port_raw = (_env_first("ORACLE_PORT", "DB_PORT") or "1521").strip()
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise RuntimeError(f"Invalid Oracle port: {port_raw!r}.") from exc

    service_name = _clean_optional(_env_first("ORACLE_SERVICE_NAME", "ORACLE_SERVICE", "DB_SERVICE"))
    sid = _clean_optional(_env_first("ORACLE_SID", "DB_SID"))
    pdb_name = _clean_optional(_env_first("ORACLE_PDB_NAME", "DB_PDB_NAME"))
    cdb_name = _clean_optional(_env_first("ORACLE_CDB_NAME", "DB_CDB_NAME"))
    connect_descriptor = _clean_optional(_env_first("ORACLE_DSN", "DB_DSN"))
    username = (_env_first("ORACLE_USER", "DB_USER") or "system").strip() or "system"
    sysdba = _env_bool("ORACLE_SYSDBA", default=False)

    if not (service_name or sid or connect_descriptor):
        service_name = "FREEPDB1"

    service_for_identity = pdb_name or service_name or sid or "dsn"
    db_key = make_db_key(environment, host, port, service_for_identity)
    display_name = f"{environment}:{host}:{port}:{service_for_identity}"

    return OracleTarget(
        db_key=db_key,
        environment=environment,
        host=host,
        port=port,
        username=username,
        service_name=service_name,
        sid=sid,
        pdb_name=pdb_name,
        cdb_name=cdb_name,
        connect_descriptor=connect_descriptor,
        display_name=display_name,
        sysdba=sysdba,
    )


def _slug(value: str) -> str:
    text = " ".join((value or "").strip().lower().split())
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    return text or "unknown"


def _clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _env_first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
