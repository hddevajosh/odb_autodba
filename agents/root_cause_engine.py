from __future__ import annotations

import re

from odb_autodba.models.schemas import HealthSnapshot, HistoricalStateTransition


def rank_root_causes(snapshot: HealthSnapshot) -> list[str]:
    causes: list[str] = []
    critical = [item for item in snapshot.actionable_items if item.severity == "CRITICAL"]
    if critical:
        causes.append(f"{critical[0].title} is the highest priority actionable finding.")

    host = snapshot.host_snapshot
    if host and host.cpu_hotspot.triggered:
        if (host.cpu_hotspot.container_cpu_pct or 0) >= 85 and (host.cpu_hotspot.host_cpu_pct or 0) < 70:
            causes.append(
                "Oracle container CPU is critically high while host CPU is moderate, indicating localized DB/container pressure."
            )
        elif (host.cpu_hotspot.host_cpu_pct or 0) >= 85:
            causes.append("Host CPU pressure is high enough to affect database response time.")
        if host.cpu_hotspot.oracle_candidate_sql:
            contributor_parts: list[str] = []
            for row in host.cpu_hotspot.oracle_candidate_sql[:3]:
                sql_id = row.sql_id or "unknown"
                owner = row.username or row.parsing_schema_name or "-"
                classification = row.sql_classification or "unknown"
                contributor_parts.append(f"{sql_id} ({owner}, {classification})")
            causes.append("DB-side CPU contributors: " + "; ".join(contributor_parts) + ".")
            if host.cpu_hotspot.correlation_confidence in {"low", "none"}:
                causes.append(
                    "OS process sampling was non-Oracle or incomplete, but Oracle SQL/session evidence still indicates DB CPU pressure."
                )
        elif host.cpu_hotspot.correlation_confidence in {"low", "none"}:
            causes.append("OS hotspot correlation to Oracle sessions was incomplete; interpret OS and DB SQL signals together.")

    if host and host.memory_hotspot.triggered and host.memory_hotspot.oracle_correlated_rows:
        top_mem = host.memory_hotspot.oracle_correlated_rows[0]
        causes.append(
            f"Memory pressure aligns with session SID {top_mem.sid} SQL_ID {top_mem.sql_id or '-'} "
            f"(PGA {top_mem.pga_used_mb or '-'} MB, module={top_mem.module or '-'}, program={top_mem.program or '-'})."
        )
    elif host and (host.memory_pct or 0) >= 90:
        causes.append("Host memory pressure is high enough to affect Oracle or OS stability.")
    else:
        memory_cfg = snapshot.raw_evidence.get("memory_config") or {}
        top_pga = (memory_cfg.get("top_pga_sessions") or [None])[0]
        if isinstance(top_pga, dict):
            try:
                pga_used_mb = float(top_pga.get("pga_used_mb") or 0.0)
            except Exception:
                pga_used_mb = 0.0
            if pga_used_mb >= 512.0:
                causes.append(
                    f"Largest current PGA session is SID {top_pga.get('sid')} SQL_ID {top_pga.get('sql_id') or '-'} "
                    f"({pga_used_mb:.2f} MB), even without a memory hotspot trigger."
                )

    if snapshot.blocking_chains:
        causes.append("Blocking sessions are the strongest current cause candidate.")
    else:
        blocking_note = snapshot.raw_evidence.get("blocking_interpretation") or {}
        if isinstance(blocking_note, dict) and blocking_note.get("lock_wait_observed") and not blocking_note.get("active_blocker_present"):
            causes.append(
                "Row-lock wait pressure was observed, but active blockers were absent during collection, indicating transient lock contention."
            )

    if snapshot.top_sql_by_cpu and not (host and host.cpu_hotspot.oracle_candidate_sql):
        causes.append(f"SQL_ID {snapshot.top_sql_by_cpu[0].sql_id} is a likely CPU contributor.")

    anomaly = snapshot.raw_evidence.get("tablespace_allocation_anomaly") or {}
    if isinstance(anomaly, dict) and anomaly.get("tablespace_allocation_failure_with_low_pct"):
        ts_name = _resolve_tablespace_name(snapshot, anomaly)
        causes.append(
            f"ORA-01653 allocation failures were seen on {ts_name} despite low overall tablespace usage, "
            "suggesting file autoextend/maxsize or extent/quota constraints."
        )
    elif snapshot.tablespaces and snapshot.tablespaces[0].used_pct >= 90:
        causes.append(f"Tablespace pressure on {snapshot.tablespaces[0].tablespace_name} could worsen performance or failures.")

    if snapshot.raw_evidence.get("alert_log"):
        causes.append("Recent ORA/TNS errors indicate instability or workload-related failures.")
    return causes[:6]


def _resolve_tablespace_name(snapshot: HealthSnapshot, anomaly: dict[str, object]) -> str:
    explicit = str(anomaly.get("tablespace_name") or "").strip()
    if explicit:
        return explicit

    message_fields = [
        str(anomaly.get("message") or "").strip(),
        str(anomaly.get("error_message") or "").strip(),
    ]
    alert_rows = snapshot.raw_evidence.get("alert_log") or []
    if isinstance(alert_rows, list):
        for row in alert_rows[:20]:
            if not isinstance(row, dict):
                continue
            message_fields.append(str(row.get("message") or "").strip())

    pattern = re.compile(r"in\s+tablespace\s+([A-Za-z0-9_$#]+)", re.IGNORECASE)
    for message in message_fields:
        if not message:
            continue
        match = pattern.search(message)
        if match:
            return match.group(1)

    if snapshot.tablespaces:
        first_name = str(snapshot.tablespaces[0].tablespace_name or "").strip()
        if first_name:
            return first_name
    return "the affected tablespace"


def rank_transition_causes(transition: HistoricalStateTransition | None) -> list[str]:
    if transition is None or not transition.available:
        return ["State transition evidence is unavailable."]
    lines: list[str] = []
    if transition.recovery_drivers:
        for driver in transition.recovery_drivers[:2]:
            evidence = "; ".join(driver.evidence[:2]) if driver.evidence else "No supporting evidence captured."
            lines.append(f"Recovery driver: {driver.title} ({driver.category}, strength={driver.score:.2f}) — {evidence}")
    if transition.residual_warning_drivers:
        for driver in transition.residual_warning_drivers[:2]:
            evidence = "; ".join(driver.evidence[:2]) if driver.evidence else "No supporting evidence captured."
            lines.append(f"Residual warning driver: {driver.title} ({driver.category}, strength={driver.score:.2f}) — {evidence}")
    driver_rows = transition.primary_transition_drivers or transition.primary_drivers
    for driver in driver_rows[:4]:
        evidence = "; ".join(driver.evidence[:2]) if driver.evidence else "No supporting evidence captured."
        driver_type = getattr(driver, "category", None) or getattr(driver, "driver_type", "unknown")
        strength = getattr(driver, "score", None)
        if strength is None:
            strength = getattr(driver, "strength", 0.0)
        lines.append(f"{driver.name} ({driver_type}, strength={float(strength):.2f}) — {evidence}")
    if not lines:
        lines.append("No primary transition drivers were detected.")
    return lines
