from __future__ import annotations

from contextvars import ContextVar
from contextlib import contextmanager
from typing import Any, Iterator

from pydantic import BaseModel, ConfigDict

from odb_autodba.target_registry import get_oracle_target, get_target_password
from odb_autodba.utils.env_loader import load_project_dotenv

_ACTIVE_DB_KEY: ContextVar[str | None] = ContextVar("odb_autodba_active_db_key", default=None)


class ConnectionSettings(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    host: str
    port: int = 1521
    service_name: str
    user: str
    password: str
    dsn: str | None = None
    sysdba: bool = False


def load_connection_settings(db_key: str | None = None) -> ConnectionSettings:
    load_project_dotenv()
    active_db_key = db_key if (db_key or "").strip() else _ACTIVE_DB_KEY.get()
    target = get_oracle_target(active_db_key)
    dsn = target.connect_descriptor
    service_name = target.service_name or target.sid

    if not service_name and not dsn:
        raise RuntimeError(
            "Missing Oracle connection settings: service_name. "
            "Set ORACLE_SERVICE_NAME/ORACLE_SERVICE or DB_SERVICE, "
            "or provide ORACLE_DSN/DB_DSN."
        )

    return ConnectionSettings(
        host=target.host,
        port=int(target.port),
        service_name=service_name or "FREEPDB1",
        user=target.username,
        password=get_target_password(target),
        dsn=dsn,
        sysdba=target.sysdba,
    )


def create_connection(settings: ConnectionSettings | None = None, *, db_key: str | None = None):
    import oracledb  # type: ignore

    active = settings or load_connection_settings(db_key=db_key)
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
def db_connection(settings: ConnectionSettings | None = None, *, db_key: str | None = None) -> Iterator[Any]:
    conn = create_connection(settings, db_key=db_key)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def fetch_all(
    sql: str,
    binds: dict[str, Any] | None = None,
    *,
    settings: ConnectionSettings | None = None,
    max_rows: int | None = None,
    db_key: str | None = None,
) -> list[dict[str, Any]]:
    with db_connection(settings, db_key=db_key) as conn:
        cur = conn.cursor()
        cur.execute(sql, binds or {})
        cols = [d[0].lower() for d in (cur.description or [])]
        rows: list[dict[str, Any]] = []
        for idx, row in enumerate(cur):
            if max_rows is not None and idx >= max_rows:
                break
            rows.append({cols[i]: _normalize_value(row[i]) for i in range(len(cols))})
        return rows


def fetch_one(
    sql: str,
    binds: dict[str, Any] | None = None,
    *,
    settings: ConnectionSettings | None = None,
    db_key: str | None = None,
) -> dict[str, Any] | None:
    rows = fetch_all(sql, binds, settings=settings, max_rows=1, db_key=db_key)
    return rows[0] if rows else None


def _normalize_value(value: Any) -> Any:
    try:
        if hasattr(value, "read"):
            return value.read()
    except Exception:
        return str(value)
    return value


@contextmanager
def db_key_context(db_key: str | None) -> Iterator[None]:
    cleaned = (db_key or "").strip() or None
    token = _ACTIVE_DB_KEY.set(cleaned)
    try:
        yield
    finally:
        _ACTIVE_DB_KEY.reset(token)


def active_db_key() -> str | None:
    value = _ACTIVE_DB_KEY.get()
    return value if (value or "").strip() else None
