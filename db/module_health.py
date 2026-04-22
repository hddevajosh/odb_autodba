from __future__ import annotations

from odb_autodba.models.schemas import HealthSnapshot, ModuleHealthSummary


def summarize_modules(snapshot: HealthSnapshot) -> list[ModuleHealthSummary]:
    out: list[ModuleHealthSummary] = []
    out.append(ModuleHealthSummary(module_name="Sessions", status=("CRITICAL" if snapshot.blocking_chains else "OK"), headline=f"{len(snapshot.active_sessions)} active session(s) and {len(snapshot.blocking_chains)} blocking chain(s)."))
    hottest = max((t.used_pct for t in snapshot.tablespaces), default=0)
    out.append(ModuleHealthSummary(module_name="Storage", status=("CRITICAL" if hottest >= 95 else "WARNING" if hottest >= 85 else "OK"), headline=f"Highest tablespace usage is {hottest:.1f}%.", findings=[ts.tablespace_name for ts in snapshot.tablespaces[:3]]))
    out.append(ModuleHealthSummary(module_name="Errors", status=("WARNING" if snapshot.ora_errors or snapshot.listener_errors else "OK"), headline=f"{len(snapshot.ora_errors)} alert-log pattern(s), {len(snapshot.listener_errors)} listener pattern(s)."))
    critical = sum(1 for item in snapshot.actionable_items if item.severity == "CRITICAL")
    warning = sum(1 for item in snapshot.actionable_items if item.severity == "WARNING")
    out.append(ModuleHealthSummary(module_name="Extended Health", status=("CRITICAL" if critical else "WARNING" if warning else "OK"), headline=f"{critical} critical and {warning} warning actionable finding(s).", findings=[item.title for item in snapshot.actionable_items[:5]]))
    if snapshot.host_snapshot:
        host_status = "CRITICAL" if (snapshot.host_snapshot.cpu_pct or 0) >= 85 or (snapshot.host_snapshot.memory_pct or 0) >= 90 else "WARNING" if (snapshot.host_snapshot.cpu_pct or 0) >= 60 or (snapshot.host_snapshot.memory_pct or 0) >= 70 else "OK"
        out.append(ModuleHealthSummary(module_name="Host", status=host_status, headline=f"Host CPU={snapshot.host_snapshot.cpu_pct}, memory={snapshot.host_snapshot.memory_pct}, load={snapshot.host_snapshot.load_average}."))
    return out
