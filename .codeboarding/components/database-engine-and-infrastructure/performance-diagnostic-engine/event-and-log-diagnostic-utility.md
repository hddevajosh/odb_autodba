---
component_id: 4.2.3
component_name: Event & Log Diagnostic Utility
---

# Event & Log Diagnostic Utility

## Component Description

A specialized diagnostic layer that scans system alert logs and trace files for ORA- errors and critical system events.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/db/log_checks.py (lines 9-14)
```
def collect_alert_error_summary(limit: int = 20) -> list[OraErrorRow]:
    rows = get_recent_alert_log_errors(limit)
    if not rows:
        return []
    counts = Counter(str(row.get("message_text", "")).strip() for row in rows if row.get("message_text"))
    return [OraErrorRow(message=msg, count=count, matched_pattern=_best_pattern(msg)) for msg, count in counts.most_common(10)]
```


## Source Files:

- `db/log_checks.py`

