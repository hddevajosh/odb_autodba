---
component_id: 4.1.3
component_name: Connection Engine & Executor
---

# Connection Engine & Executor

## Component Description

The operational core that interfaces with `python-oracledb`. It manages the initialization of the Oracle client environment, establishes authenticated sessions using the provided target metadata, and provides context-managed execution blocks for running queries and fetching results.

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

### /home/neha/projects/agents/odb_autodba/db/connection.py (lines 52-65)
```
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
```

### /home/neha/projects/agents/odb_autodba/db/connection.py (lines 80-97)
```
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
```


## Source Files:

- `db/connection.py`
- `utils/oracle_env.py`

