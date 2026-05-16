---
component_id: 2.3.3
component_name: Severity & Synthesis Engine
---

# Severity & Synthesis Engine

## Component Description

The intelligence layer of the formatter. It applies logic to rank database issues (Critical, Warning, Info), determines the overall status of a snapshot, and partitions AI notes into factual observations versus interpretive insights.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/utils/severity.py (lines 14-15)
```
def worst_status(statuses: list[MetricStatus]) -> MetricStatus:
    return max(statuses or ["OK"], key=severity_rank)
```

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 215-219)
```
def _overall_snapshot_status(snapshot: HealthSnapshot) -> str:
    statuses = [issue.severity for issue in snapshot.issues]
    statuses.extend(item.severity for item in snapshot.actionable_items)
    statuses.extend(str(section.status) for section in snapshot.health_sections if str(section.status) != "INFO")
    return _worst_status(statuses)
```

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 1448-1462)
```
def _partition_section_notes(section_name: str, notes: list[str]) -> tuple[list[str], list[str]]:
    inline_notes: list[str] = []
    moved_interpretive: list[str] = []
    for raw_note in notes or []:
        note = str(raw_note or "").strip()
        if not note:
            continue
        if _is_interpretive_note(note):
            moved_interpretive.append(note)
            continue
        if _is_factual_collection_note(note) or len(note) <= 140:
            inline_notes.append(note)
            continue
        moved_interpretive.append(note)
    return _dedupe_text_lines(inline_notes), _dedupe_text_lines(moved_interpretive)
```


## Source Files:

- `utils/formatter.py`
- `utils/severity.py`

