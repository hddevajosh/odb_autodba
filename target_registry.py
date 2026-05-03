from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from odb_autodba.config import OracleTarget, get_default_oracle_target, make_db_key
from odb_autodba.utils.env_loader import load_project_dotenv

PACKAGE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parent
DEFAULT_TARGETS_YAML = REPO_ROOT / "config" / "oracle_targets.yaml"
DEFAULT_TARGETS_JSON = REPO_ROOT / "config" / "oracle_targets.json"
TRANSIENT_SOURCE = "transient_ui"

_TRANSIENT_LOCK = threading.Lock()
_TRANSIENT_TARGETS: dict[str, OracleTarget] = {}
_TRANSIENT_PASSWORDS: dict[str, str] = {}
_TRANSIENT_RUNTIME_PASSWORD_KEYS: set[str] = set()


def load_oracle_targets() -> list[OracleTarget]:
    registry_targets = _load_registry_targets_if_present()
    base_targets = registry_targets if registry_targets is not None else [get_default_oracle_target()]
    return _merge_with_transient_targets(base_targets)


def get_oracle_target(db_key: str | None = None) -> OracleTarget:
    requested = (db_key or "").strip()
    default_target = get_default_oracle_target()
    transient = _get_transient_target(requested) if requested else None
    if transient is not None:
        return transient
    registry_targets = _load_registry_targets_if_present()

    if not requested:
        if registry_targets:
            for target in registry_targets:
                if target.db_key == default_target.db_key:
                    return target
        return default_target

    if registry_targets:
        for target in registry_targets:
            if target.db_key == requested:
                return target

    if default_target.db_key == requested:
        return default_target

    available = list_oracle_targets_safe()
    known = ", ".join(sorted(str(item.get("db_key") or "") for item in available if item.get("db_key"))) or "none"
    raise ValueError(f"Unknown db_key '{requested}'. Available db_keys: {known}")


def list_oracle_targets_safe() -> list[dict[str, Any]]:
    targets = load_oracle_targets()
    return [target.safe_dict() for target in targets]


def get_target_password(target: OracleTarget) -> str:
    load_project_dotenv()
    transient_password = _get_transient_password(target.db_key)
    if transient_password is not None:
        return transient_password

    env_name = (target.password_env or "").strip()
    if env_name:
        value = os.getenv(env_name)
        if value:
            return value
        raise RuntimeError(
            f"Missing password environment variable '{env_name}' for db_key '{target.db_key}'."
        )

    for fallback_env in ("ORACLE_PASSWORD", "ORACLE_PASS", "DB_PASSWORD"):
        value = os.getenv(fallback_env)
        if value:
            return value

    raise RuntimeError(
        f"Missing Oracle password for db_key '{target.db_key}'. "
        "Set target.password_env or ORACLE_PASSWORD/ORACLE_PASS/DB_PASSWORD."
    )


def _load_registry_targets_if_present() -> list[OracleTarget] | None:
    registry_path = _resolve_registry_path()
    if registry_path is None:
        return None

    payload = _read_registry_payload(registry_path)
    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, list):
        raise ValueError(f"Registry file '{registry_path}' must contain a top-level 'targets' list.")

    parsed: list[OracleTarget] = []
    for idx, item in enumerate(raw_targets, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Registry target entry #{idx} in '{registry_path}' must be an object.")
        parsed.append(_parse_target(item, source=str(registry_path), index=idx))

    _validate_no_duplicate_db_keys(parsed, source=str(registry_path))
    return parsed


def _resolve_registry_path() -> Path | None:
    load_project_dotenv()

    configured = (os.getenv("ODB_AUTODBA_TARGETS_FILE") or "").strip()
    if configured:
        candidate = Path(configured)
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if candidate.exists():
            return candidate
        return None

    if DEFAULT_TARGETS_YAML.exists():
        return DEFAULT_TARGETS_YAML
    if DEFAULT_TARGETS_JSON.exists():
        return DEFAULT_TARGETS_JSON
    return None


def _read_registry_payload(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    if suffix == ".json":
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError(f"Registry file '{path}' must be a JSON object with a 'targets' array.")
        return payload

    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "YAML target registry requested but PyYAML is unavailable. "
                "Install 'PyYAML' or use JSON registry file config/oracle_targets.json."
            ) from exc
        payload = yaml.safe_load(text) or {}
        if not isinstance(payload, dict):
            raise ValueError(f"Registry file '{path}' must contain a mapping with 'targets'.")
        return payload

    # Unknown extension: allow JSON as a practical fallback.
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError(f"Unsupported registry format for '{path}'. Expected YAML or JSON object.")
    return payload


def _parse_target(item: dict[str, Any], *, source: str, index: int) -> OracleTarget:
    environment = _clean_text(item.get("environment")) or "default"
    host = _clean_text(item.get("host"))
    if not host:
        raise ValueError(f"Registry target entry #{index} in '{source}' is missing required field 'host'.")

    port_raw = item.get("port", 1521)
    try:
        port = int(port_raw)
    except Exception as exc:
        raise ValueError(
            f"Registry target entry #{index} in '{source}' has invalid 'port': {port_raw!r}."
        ) from exc

    service_name = _clean_text(item.get("service_name"))
    sid = _clean_text(item.get("sid"))
    pdb_name = _clean_text(item.get("pdb_name"))
    cdb_name = _clean_text(item.get("cdb_name"))
    connect_descriptor = _clean_text(item.get("connect_descriptor"))

    if not (service_name or sid or connect_descriptor):
        service_name = "FREEPDB1"

    username = _clean_text(item.get("username")) or "system"
    password_env = _clean_text(item.get("password_env"))
    display_name = _clean_text(item.get("display_name"))
    tags = _normalize_tags(item.get("tags"))
    sysdba = _to_bool(item.get("sysdba"), default=False)

    service_for_identity = pdb_name or service_name or sid or "dsn"
    db_key = make_db_key(environment, host, port, service_for_identity)

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
        display_name=display_name or f"{environment}:{host}:{port}:{service_for_identity}",
        sysdba=sysdba,
        password_env=password_env,
        tags=tags,
        source=source,
    )


def _normalize_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        tag = value.strip()
        return [tag] if tag else []
    if not isinstance(value, list):
        raise ValueError("Target 'tags' must be a list of strings when provided.")

    tags: list[str] = []
    for item in value:
        tag = _clean_text(item)
        if tag:
            tags.append(tag)
    return tags


def _validate_no_duplicate_db_keys(targets: list[OracleTarget], *, source: str) -> None:
    seen: dict[str, int] = {}
    for idx, target in enumerate(targets, start=1):
        if target.db_key in seen:
            first = seen[target.db_key]
            raise ValueError(
                f"Duplicate db_key '{target.db_key}' in '{source}' "
                f"(entries #{first} and #{idx})."
            )
        seen[target.db_key] = idx


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _to_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def register_transient_target(
    target: OracleTarget,
    *,
    password: str | None = None,
    replace: bool = True,
) -> OracleTarget:
    normalized = OracleTarget(
        db_key=target.db_key,
        environment=target.environment,
        host=target.host,
        port=int(target.port),
        username=target.username,
        service_name=target.service_name,
        sid=target.sid,
        pdb_name=target.pdb_name,
        cdb_name=target.cdb_name,
        connect_descriptor=target.connect_descriptor,
        display_name=target.display_name,
        sysdba=target.sysdba,
        password_env=target.password_env,
        tags=list(target.tags or []),
        source=target.source or TRANSIENT_SOURCE,
    )
    with _TRANSIENT_LOCK:
        if not replace and normalized.db_key in _TRANSIENT_TARGETS:
            raise ValueError(f"Transient target already exists for db_key '{normalized.db_key}'.")
        _TRANSIENT_TARGETS[normalized.db_key] = normalized
        if password is not None and str(password).strip():
            _TRANSIENT_PASSWORDS[normalized.db_key] = str(password)
            _TRANSIENT_RUNTIME_PASSWORD_KEYS.add(normalized.db_key)
        elif normalized.db_key in _TRANSIENT_PASSWORDS:
            _TRANSIENT_PASSWORDS.pop(normalized.db_key, None)
            _TRANSIENT_RUNTIME_PASSWORD_KEYS.discard(normalized.db_key)
    return normalized


def build_transient_target(
    *,
    environment: str,
    host: str,
    port: int | str,
    username: str,
    service_name: str | None = None,
    sid: str | None = None,
    pdb_name: str | None = None,
    cdb_name: str | None = None,
    connect_descriptor: str | None = None,
    display_name: str | None = None,
    password_env: str | None = None,
    sysdba: bool = False,
) -> OracleTarget:
    env = (environment or "").strip() or "default"
    host_value = (host or "").strip()
    if not host_value:
        raise ValueError("Host is required.")
    try:
        port_value = int(port)
    except Exception as exc:
        raise ValueError(f"Invalid port value: {port!r}") from exc
    user = (username or "").strip() or "system"
    service = (service_name or "").strip() or None
    sid_value = (sid or "").strip() or None
    pdb = (pdb_name or "").strip() or None
    cdb = (cdb_name or "").strip() or None
    descriptor = (connect_descriptor or "").strip() or None
    password_env_name = (password_env or "").strip() or None
    if not (service or sid_value or descriptor):
        service = "FREEPDB1"
    identity = pdb or service or sid_value or "dsn"
    db_key = make_db_key(env, host_value, port_value, identity)
    friendly = (display_name or "").strip() or f"{env}:{host_value}:{port_value}:{identity}"
    return OracleTarget(
        db_key=db_key,
        environment=env,
        host=host_value,
        port=port_value,
        username=user,
        service_name=service,
        sid=sid_value,
        pdb_name=pdb,
        cdb_name=cdb,
        connect_descriptor=descriptor,
        display_name=friendly,
        sysdba=bool(sysdba),
        password_env=password_env_name,
        tags=["transient"],
        source=TRANSIENT_SOURCE,
    )


def is_transient_target(db_key: str | None) -> bool:
    key = (db_key or "").strip()
    if not key:
        return False
    with _TRANSIENT_LOCK:
        return key in _TRANSIENT_TARGETS


def transient_target_requires_local_mode(db_key: str | None) -> bool:
    key = (db_key or "").strip()
    if not key:
        return False
    with _TRANSIENT_LOCK:
        if key not in _TRANSIENT_TARGETS:
            return False
        return key in _TRANSIENT_RUNTIME_PASSWORD_KEYS


def transient_target_mcp_payload(db_key: str | None) -> dict[str, Any] | None:
    key = (db_key or "").strip()
    if not key:
        return None
    with _TRANSIENT_LOCK:
        target = _TRANSIENT_TARGETS.get(key)
        if target is None:
            return None
        if key in _TRANSIENT_RUNTIME_PASSWORD_KEYS:
            return None
    return {
        "db_key": target.db_key,
        "environment": target.environment,
        "host": target.host,
        "port": target.port,
        "username": target.username,
        "service_name": target.service_name,
        "sid": target.sid,
        "pdb_name": target.pdb_name,
        "cdb_name": target.cdb_name,
        "connect_descriptor": target.connect_descriptor,
        "display_name": target.display_name,
        "sysdba": target.sysdba,
        "password_env": target.password_env,
        "source": target.source or TRANSIENT_SOURCE,
        "tags": list(target.tags or []),
    }


def clear_transient_targets() -> None:
    with _TRANSIENT_LOCK:
        _TRANSIENT_TARGETS.clear()
        _TRANSIENT_PASSWORDS.clear()
        _TRANSIENT_RUNTIME_PASSWORD_KEYS.clear()


def _merge_with_transient_targets(base: list[OracleTarget]) -> list[OracleTarget]:
    with _TRANSIENT_LOCK:
        transient = list(_TRANSIENT_TARGETS.values())
    if not transient:
        return base
    merged: dict[str, OracleTarget] = {item.db_key: item for item in base}
    for item in transient:
        merged[item.db_key] = item
    return list(merged.values())


def _get_transient_target(db_key: str) -> OracleTarget | None:
    key = (db_key or "").strip()
    if not key:
        return None
    with _TRANSIENT_LOCK:
        return _TRANSIENT_TARGETS.get(key)


def _get_transient_password(db_key: str) -> str | None:
    key = (db_key or "").strip()
    if not key:
        return None
    with _TRANSIENT_LOCK:
        return _TRANSIENT_PASSWORDS.get(key)
