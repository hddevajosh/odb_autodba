from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

from pydantic import BaseModel, ConfigDict

from odb_autodba.utils.env_loader import load_project_dotenv


class ConnectionSettings(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    host: str
    port: int = 1521
    service_name: str
    user: str
    password: str
    dsn: str | None = None
    sysdba: bool = False


def load_connection_settings() -> ConnectionSettings:
    load_project_dotenv()
    dsn = _env_first("ORACLE_DSN", "DB_DSN")
    missing = [
        canonical
        for canonical, aliases in {
            "host": ("ORACLE_HOST", "DB_HOST"),
            "service_name": ("ORACLE_SERVICE_NAME", "ORACLE_SERVICE", "DB_SERVICE"),
            "user": ("ORACLE_USER", "DB_USER"),
            "password": ("ORACLE_PASSWORD", "ORACLE_PASS", "DB_PASSWORD"),
        }.items()
        if not _env_first(*aliases)
    ]
    if missing and not dsn:
        raise RuntimeError(
            "Missing Oracle connection settings: "
            + ", ".join(missing)
            + ". Set ORACLE_HOST/ORACLE_SERVICE_NAME/ORACLE_USER/ORACLE_PASSWORD "
            + "or DB_HOST/DB_SERVICE/DB_USER/DB_PASSWORD."
        )
    return ConnectionSettings(
        host=_env_first("ORACLE_HOST", "DB_HOST") or "localhost",
        port=int(_env_first("ORACLE_PORT", "DB_PORT") or "1521"),
        service_name=_env_first("ORACLE_SERVICE_NAME", "ORACLE_SERVICE", "DB_SERVICE") or "FREEPDB1",
        user=_env_first("ORACLE_USER", "DB_USER") or "system",
        password=_env_first("ORACLE_PASSWORD", "ORACLE_PASS", "DB_PASSWORD") or "oracle",
        dsn=dsn,
        sysdba=os.getenv("ORACLE_SYSDBA", "false").lower() in {"1", "true", "yes", "on"},
    )


def create_connection(settings: ConnectionSettings | None = None):
    import oracledb  # type: ignore

    active = settings or load_connection_settings()
    dsn = active.dsn or oracledb.makedsn(active.host, active.port, service_name=active.service_name)
    kwargs: dict[str, Any] = {
        "user": active.user,
        "password": active.password,
        "dsn": dsn,
    }
    if active.sysdba:
        kwargs["mode"] = oracledb.AUTH_MODE_SYSDBA
    conn = oracledb.connect(**kwargs)
    return conn


@contextmanager
def db_connection(settings: ConnectionSettings | None = None) -> Iterator[Any]:
    conn = create_connection(settings)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def fetch_all(sql: str, binds: dict[str, Any] | None = None, *, settings: ConnectionSettings | None = None, max_rows: int | None = None) -> list[dict[str, Any]]:
    with db_connection(settings) as conn:
        cur = conn.cursor()
        cur.execute(sql, binds or {})
        cols = [d[0].lower() for d in (cur.description or [])]
        rows: list[dict[str, Any]] = []
        for idx, row in enumerate(cur):
            if max_rows is not None and idx >= max_rows:
                break
            rows.append({cols[i]: _normalize_value(row[i]) for i in range(len(cols))})
        return rows


def fetch_one(sql: str, binds: dict[str, Any] | None = None, *, settings: ConnectionSettings | None = None) -> dict[str, Any] | None:
    rows = fetch_all(sql, binds, settings=settings, max_rows=1)
    return rows[0] if rows else None


def _normalize_value(value: Any) -> Any:
    try:
        if hasattr(value, "read"):
            return value.read()
    except Exception:
        return str(value)
    return value


def _env_first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None
