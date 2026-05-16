---
component_id: 4.1.2
component_name: Database Schema & Configuration
---

# Database Schema & Configuration

## Component Description

Defines the formal data models and serialization logic for database targets. It ensures that connection parameters are validated, normalized into unique keys (slugs), and can be safely serialized for transit between the local environment and the MCP server.

---

## Key References:

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

### /home/neha/projects/agents/odb_autodba/config.py (lines 53-58)
```
def make_db_key(environment: str, host: str, port: int | str, service_or_sid_or_pdb: str) -> str:
    env_part = _slug(environment)
    host_part = _slug(host)
    port_part = _slug(str(port))
    service_part = _slug(service_or_sid_or_pdb)
    return f"{env_part}__{host_part}__{port_part}__{service_part}"
```

### /home/neha/projects/agents/odb_autodba/config.py (lines 33-37)
```
    def safe_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = _SafeTargetDict(asdict(self))
        payload.pop("password_env", None)
        payload["password_env_present"] = bool(self.password_env)
        return payload
```


## Source Files:

- `config.py`

