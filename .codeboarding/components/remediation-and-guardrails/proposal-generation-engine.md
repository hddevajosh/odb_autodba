---
component_id: 6.1
component_name: Proposal Generation Engine
---

# Proposal Generation Engine

## Component Description

Responsible for translating high-level remediation strategies (like resolving blocking locks or tablespace exhaustion) into concrete, executable SQL payloads using predefined templates.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/tools/action_proposals.py (lines 24-38)
```
def build_remediation_proposal(snapshot: HealthSnapshot) -> RemediationProposal | None:
    candidates: list[RemediationProposal] = []
    blocking = _blocking_lock_proposal(snapshot)
    if blocking is not None:
        candidates.append(blocking)

    tablespace = _tablespace_extend_proposal(snapshot)
    if tablespace is not None:
        candidates.append(tablespace)

    if not candidates:
        return None

    candidates.sort(key=_proposal_priority)
    return candidates[0]
```

### /home/neha/projects/agents/odb_autodba/db/remediation_sql.py (lines 31-65)
```
def build_extend_tablespace_sql(
    *,
    tablespace_name: str,
    initial_gb: int = 1,
    next_mb: int = 256,
    max_gb: int = 32,
    bigfile_hint: bool | None = None,
) -> tuple[str, list[str]]:
    notes: list[str] = []
    ts = str(tablespace_name or "").strip().upper()
    if not ts:
        raise ValueError("tablespace_name is required for extend_tablespace action.")

    is_bigfile: bool | None = bigfile_hint
    file_id: int | None = None
    try:
        row = fetch_one(TABLESPACE_INFO_SQL, {"ts": ts}) or {}
        if row:
            is_bigfile = str(row.get("bigfile") or "").upper() == "YES"
    except Exception as exc:
        notes.append(f"Unable to query dba_tablespaces for {ts}: {exc}")

    if is_bigfile:
        try:
            row = fetch_one(TABLESPACE_BIGFILE_DATAFILE_SQL, {"ts": ts}) or {}
            file_id = _as_int(row.get("file_id"))
        except Exception as exc:
            notes.append(f"Unable to query dba_data_files for BIGFILE tablespace {ts}: {exc}")
        if file_id is not None:
            sql = f"ALTER DATABASE DATAFILE {file_id} AUTOEXTEND ON NEXT {int(next_mb)}M MAXSIZE {int(max_gb)}G"
            return sql, notes
        notes.append("Falling back to ALTER TABLESPACE ADD DATAFILE because BIGFILE file_id is unavailable.")

    sql = f"ALTER TABLESPACE {ts} ADD DATAFILE SIZE {int(initial_gb)}G AUTOEXTEND ON NEXT {int(next_mb)}M MAXSIZE {int(max_gb)}G"
    return sql, notes
```


## Source Files:

- `db/remediation_sql.py`
- `tools/action_proposals.py`

