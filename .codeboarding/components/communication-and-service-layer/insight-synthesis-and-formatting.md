---
component_id: 2.3
component_name: Insight Synthesis & Formatting
---

# Insight Synthesis & Formatting

## Component Description

Transforms structured data and AI reasoning traces into polished Markdown reports. It applies severity logic to rank database issues and uses specialized templates to render health snapshots, AWR (Automatic Workload Repository) analyses, and investigation summaries for the end-user.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 449-506)
```
def render_health_snapshot_report(snapshot: HealthSnapshot) -> str:
    database_name = snapshot.instance_info.db_name or snapshot.instance_info.instance_name or "unknown"
    overall_status = _overall_snapshot_status(snapshot)
    lines = [
        "# Oracle AutoDBA Report",
        "",
        f"**Database:** `{database_name}`",
        f"**Open mode / role:** `{snapshot.instance_info.open_mode}` / `{snapshot.instance_info.database_role}`",
        f"**Generated at:** `{snapshot.generated_at}`",
        f"**Overall status:** {_status_badge(overall_status)}",
        "",
        _section_heading("Executive Summary", status=overall_status),
        "",
        _render_executive_summary(snapshot),
        "",
        _section_heading("Key Health Signals", informational=True),
        "",
        _render_key_signals(snapshot),
        "",
        _section_heading("Host Check Scope", informational=True),
        "",
        _render_host_check_scope_section(snapshot),
        "",
        _section_heading("Findings Needing Attention", status=_findings_status(snapshot)),
        "",
        _render_actionable_items(snapshot),
        "",
        _section_heading("Supporting Evidence", informational=True),
        "",
        _render_supporting_evidence(snapshot),
        "",
        _section_heading("Top SQL by CPU", status="WARNING" if snapshot.top_sql_by_cpu else "OK"),
        "",
        _render_top_cpu_sql(snapshot),
        "",
        _section_heading("Top SQL by Elapsed", status="WARNING" if snapshot.top_sql_by_elapsed else "OK"),
        "",
        _render_top_elapsed_sql(snapshot),
        "",
        _top_sql_overlap_note(snapshot),
        "",
        _section_heading("Detailed Evidence", informational=True),
        "",
    ]
    moved_interpretive_notes: list[str] = []
    for section in snapshot.health_sections:
        inline_notes, interpretive_notes = _partition_section_notes(section.name, section.notes)
        moved_interpretive_notes.extend(interpretive_notes)
        lines.extend(_render_health_section(section, notes_override=inline_notes))
    lines.extend(
        [
            _section_heading("AI Investigation Summary", informational=True),
            "",
            _render_ai_investigation_summary(snapshot, moved_interpretive_notes),
            "",
        ]
    )
    return "\n".join(line for line in lines if line is not None).strip()
```

### /home/neha/projects/agents/odb_autodba/utils/formatter.py (lines 2028-2062)
```
def render_investigation_final_report(report: InvestigationReport) -> str:
    sections = [
        "# AI Investigation Report",
        "",
        "## Problem Understood",
        report.problem_statement,
        "",
        "## Investigation Summary",
        report.summary,
        "",
        "## Likely Cause",
        report.likely_cause,
        "",
        "## Supporting Evidence",
    ]
    if report.evidence:
        sections.extend(f"- {line}" for line in report.evidence)
    else:
        sections.append("- No strong evidence captured.")
    sections.extend(["", "## Recommended Next Actions"])
    sections.extend(f"- {line}" for line in (report.recommended_next_actions or ["Review the SQL steps and confirm the suspected cause."]))
    sections.extend(["", "## SQL Steps Run"])
    for step in report.steps:
        sections.extend([
            f"### Step {step.step_number}: {step.goal}",
            "",
            "```sql",
            step.sql,
            "```",
            "",
            step.result_preview,
            "",
        ])
        sections.extend(_render_investigation_step_output(step))
    return "\n".join(sections)
```

### /home/neha/projects/agents/odb_autodba/utils/severity.py (lines 14-15)
```
def worst_status(statuses: list[MetricStatus]) -> MetricStatus:
    return max(statuses or ["OK"], key=severity_rank)
```


## Source Files:

- `utils/formatter.py`
- `utils/severity.py`

