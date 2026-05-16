---
component_id: 4.1.1
component_name: Target Inventory & Discovery
---

# Target Inventory & Discovery

## Component Description

Manages the catalog of available Oracle instances. It handles the discovery of database targets from registry files, merges them with transient environment configurations, and resolves secure credentials. It acts as the source of truth for what databases the system can manage.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/target_registry.py (lines 24-27)
```
def load_oracle_targets() -> list[OracleTarget]:
    registry_targets = _load_registry_targets_if_present()
    base_targets = registry_targets if registry_targets is not None else [get_default_oracle_target()]
    return _merge_with_transient_targets(base_targets)
```

### /home/neha/projects/agents/odb_autodba/target_registry.py (lines 30-55)
```
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
```

### /home/neha/projects/agents/odb_autodba/target_registry.py (lines 63-86)
```
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
```


## Source Files:

- `target_registry.py`

