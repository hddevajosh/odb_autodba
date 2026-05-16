---
component_id: 4.1
component_name: Database Connectivity & Target Registry
---

# Database Connectivity & Target Registry

## Component Description

Acts as the gateway to the database estate. It manages the inventory of Oracle targets, handles secure credential retrieval, and provides a robust connection pooling mechanism using oracledb. It ensures that all other diagnostic components have authenticated and stable access to the required instances.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/db/connection.py (lines 69-77)
```
def db_connection(settings: ConnectionSettings | None = None, *, db_key: str | None = None) -> Iterator[Any]:
    conn = create_connection(settings, db_key=db_key)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass
```

### /home/neha/projects/agents/odb_autodba/target_registry.py (lines 24-27)
```
def load_oracle_targets() -> list[OracleTarget]:
    registry_targets = _load_registry_targets_if_present()
    base_targets = registry_targets if registry_targets is not None else [get_default_oracle_target()]
    return _merge_with_transient_targets(base_targets)
```

### /home/neha/projects/agents/odb_autodba/config.py (lines 12-37)
```
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
```


## Source Files:

- `config.py`
- `db/connection.py`
- `target_registry.py`
- `utils/oracle_env.py`

