---
component_id: 2.3.4
component_name: Atomic Formatting Primitives
---

# Atomic Formatting Primitives

## Component Description

Provides the foundational rendering logic for the entire subsystem. It handles low-level data transformation (e.g., converting bytes to GB), table construction, and column inference to ensure Markdown consistency.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 1859-1866)
```
def _render_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return ""
    useful_columns = [column for column in columns if any(_has_value(row.get(column)) for row in rows)]
    if not useful_columns:
        useful_columns = columns[:3]
    table_columns = [_text_column_spec(column, rows) for column in useful_columns]
    return _render_dba_code_table(rows, table_columns)
```

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 1997-2013)
```
def _format_value(value: Any, max_length: int = 400) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return f"{value:.2f}".rstrip("0").rstrip(".")
    if isinstance(value, dict):
        text = ", ".join(f"{friendly_label(str(key))}={_format_value(val, max_length=120)}" for key, val in value.items() if _has_value(val))
    elif isinstance(value, list):
        text = ", ".join(_format_value(item, max_length=80) for item in value[:5])
    else:
        text = str(value)
    text = " ".join(text.split())
    if len(text) > max_length:
        return text[: max_length - 1] + "…"
    return text
```

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 1869-1877)
```
def _infer_columns(rows: list[dict[str, Any]], limit: int = 8) -> list[str]:
    columns: list[str] = []
    for row in rows:
        for key, value in row.items():
            if key not in columns and _has_value(value):
                columns.append(key)
            if len(columns) >= limit:
                return columns
    return columns or list(rows[0].keys())[:limit]
```


## Source Files:

- `utils/formatter.py`

