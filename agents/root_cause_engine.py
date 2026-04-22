from __future__ import annotations

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
            top = host.cpu_hotspot.oracle_candidate_sql[0]
            causes.append(
                f"DB-side SQL contributor: SQL_ID {top.sql_id or 'unknown'} user={top.username or '-'} module={top.module or '-'} source={top.source}."
            )
        elif host.cpu_hotspot.correlation_confidence in {"low", "none"}:
            causes.append("OS hotspot correlation to Oracle sessions was incomplete; interpret OS and DB SQL signals together.")

    if host and host.memory_hotspot.triggered and host.memory_hotspot.oracle_correlated_rows:
        top_mem = host.memory_hotspot.oracle_correlated_rows[0]
        causes.append(
            f"Memory pressure aligns with session SID {top_mem.sid} SQL_ID {top_mem.sql_id or '-'} (PGA {top_mem.pga_used_mb or '-'} MB)."
        )
    elif host and (host.memory_pct or 0) >= 90:
        causes.append("Host memory pressure is high enough to affect Oracle or OS stability.")

    if snapshot.blocking_chains:
        causes.append("Blocking sessions are the strongest current cause candidate.")
    else:
        blocking_note = snapshot.raw_evidence.get("blocking_interpretation") or {}
        if isinstance(blocking_note, dict) and blocking_note.get("lock_wait_observed") and not blocking_note.get("active_blocker_present"):
            causes.append(
                "Row-lock wait pressure was observed, but active blockers were absent during collection, indicating transient lock contention."
            )

    if snapshot.top_sql_by_cpu:
        causes.append(f"SQL_ID {snapshot.top_sql_by_cpu[0].sql_id} is a likely CPU contributor.")

    anomaly = snapshot.raw_evidence.get("tablespace_allocation_anomaly") or {}
    if isinstance(anomaly, dict) and anomaly.get("tablespace_allocation_failure_with_low_pct"):
        causes.append(
            "ORA-01653 allocation failures were seen despite low overall tablespace usage, suggesting file autoextend/maxsize or extent/quota constraints."
        )
    elif snapshot.tablespaces and snapshot.tablespaces[0].used_pct >= 90:
        causes.append(f"Tablespace pressure on {snapshot.tablespaces[0].tablespace_name} could worsen performance or failures.")

    if snapshot.raw_evidence.get("alert_log"):
        causes.append("Recent ORA/TNS errors indicate instability or workload-related failures.")
    return causes[:4]


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
