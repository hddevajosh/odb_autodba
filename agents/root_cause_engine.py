from __future__ import annotations

import re
from typing import Any

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
        critical_blocking = any(str(chain.blocking_severity or "").upper() == "CRITICAL" for chain in snapshot.blocking_chains)
        if critical_blocking:
            causes.append("Blocking sessions are the strongest current cause candidate.")
        else:
            causes.append("Blocking was observed but current evidence indicates mostly transient/non-critical blocking.")
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
    elif snapshot.tablespaces:
        top = snapshot.tablespaces[0]
        top_pct = _tablespace_pct(top)
        if top_pct >= 85:
            causes.append(f"Tablespace pressure on {top.tablespace_name} could worsen performance or failures.")

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


def _tablespace_pct(row: Any) -> float:
    try:
        if getattr(row, "pct_used", None) is not None:
            return float(getattr(row, "pct_used"))
        return float(getattr(row, "used_pct", 0.0) or 0.0)
    except Exception:
        return 0.0


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


def infer_root_cause(
    *,
    mode: str,
    summary: str,
    supporting_data: dict[str, Any] | None,
    rendered_report: str | None,
) -> dict[str, Any]:
    supporting = supporting_data or {}
    report_text = (rendered_report or "").lower()
    latest_metrics = _extract_latest_metrics(supporting)
    database_role = str(latest_metrics.get("database_role") or "").strip().upper()
    open_mode = str(latest_metrics.get("open_mode") or "").strip().upper()
    mounted_physical_standby = bool(
        _to_bool(latest_metrics.get("mounted_physical_standby"))
        or (database_role == "PHYSICAL STANDBY" and open_mode == "MOUNTED")
    )
    host_check = _extract_host_check_context(supporting=supporting, latest_metrics=latest_metrics)
    state_transition = supporting.get("state_transition") if isinstance(supporting.get("state_transition"), dict) else {}
    learning = _extract_learning_features(supporting, state_transition)
    awr = state_transition.get("awr_state_diff") if isinstance(state_transition.get("awr_state_diff"), dict) else {}
    active_payload = supporting.get("active_sessions") if isinstance(supporting.get("active_sessions"), dict) else {}
    recurring_patterns = _extract_recurring_patterns(supporting, state_transition)
    recurrence_support = _build_recurrence_support(recurring_patterns)

    blocking_signal = _detect_blocking_signal(report_text, latest_metrics, active_payload)
    sql_signal = _detect_sql_regression_signal(learning, awr, latest_metrics)
    sql_pattern_signal = _detect_sql_performance_pattern_signal(report_text, learning, awr, latest_metrics)
    cpu_signal = _detect_cpu_signal(report_text, learning, awr, latest_metrics, host_check)
    memory_signal = _detect_memory_signal(report_text, learning, awr, latest_metrics, host_check, supporting)
    storage_signal = _detect_storage_or_alert_signal(report_text, latest_metrics)
    if mounted_physical_standby:
        blocking_signal = {"present": False}
        sql_signal = {"present": False}
        sql_pattern_signal = {"present": False}
        cpu_signal = {"present": False}
        memory_signal = {"present": False}

    # Priority order: blocking_lock > sql_regression > sql_performance_pattern > cpu_pressure > memory_pressure > storage_or_alert_error > historical_recurrence > inconclusive
    if blocking_signal["present"]:
        category = "blocking_lock"
        signal = blocking_signal
    elif sql_signal["present"]:
        category = "sql_regression"
        signal = sql_signal
    elif sql_pattern_signal["present"]:
        category = "sql_performance_pattern"
        signal = sql_pattern_signal
    elif cpu_signal["present"]:
        category = "cpu_pressure"
        signal = cpu_signal
    elif memory_signal["present"]:
        category = "memory_pressure"
        signal = memory_signal
    elif storage_signal["present"]:
        category = "storage_or_alert_error"
        signal = storage_signal
    elif recurrence_support:
        category = "inconclusive"
        signal = _build_inconclusive_signal(latest_metrics, learning, recurring_patterns)
        historical_note = (
            "Recurring historical patterns were observed, but no matching current evidence was found "
            "(historical_not_current)."
        )
        signal["supporting_evidence"] = _dedupe_cap_lines((signal.get("supporting_evidence") or []) + [historical_note], cap=5)
    elif mode == "investigation":
        likely_signal = _detect_investigation_likely_cause_signal(supporting)
        if likely_signal["present"]:
            category = likely_signal["category"]
            signal = likely_signal
        else:
            category = "inconclusive"
            signal = _build_inconclusive_signal(latest_metrics, learning, recurring_patterns)
    else:
        category = "inconclusive"
        signal = _build_inconclusive_signal(latest_metrics, learning, recurring_patterns)
    if mounted_physical_standby and category == "inconclusive":
        signal = {
            "present": True,
            "strength": 34.0,
            "primary_evidence": ["Primary-style RCA skipped in mounted standby mode."],
            "supporting_evidence": ["Standby health should be driven by Data Guard apply/transport/gap evidence."],
            "reasoning": "Mounted physical standby mode suppresses primary workload RCA categories by design.",
            "impacted_components": ["standby apply/transport pipeline"],
            "next_validation_step": "Review managed recovery, apply/transport lag, archive gaps, and Data Guard status messages.",
            "current_evidence_count": 1,
        }

    primary_evidence = _dedupe_cap_lines(signal.get("primary_evidence") or [], cap=3)
    supporting_evidence = _dedupe_cap_lines((signal.get("supporting_evidence") or []) + recurrence_support, cap=5)
    if category == "historical_recurrence":
        supporting_evidence = _dedupe_cap_lines(signal.get("supporting_evidence") or [], cap=5)
    if not primary_evidence:
        if supporting_evidence:
            primary_evidence = [supporting_evidence[0]]
            supporting_evidence = supporting_evidence[1:]
        else:
            primary_evidence = [f"Deterministic rule matched category `{category}` with limited explicit metric detail."]

    all_evidence = _dedupe_cap_lines(primary_evidence + supporting_evidence, cap=8)
    current_evidence_count = _to_int(signal.get("current_evidence_count"))
    contradictions = _category_contradictions(category=category, latest_metrics=latest_metrics, report_text=report_text, signal=signal)
    confidence = _resolve_confidence(
        score=_to_float(signal.get("strength")),
        category=category,
        host_check_scope=str(host_check.get("host_check_scope") or ""),
        current_evidence_count=current_evidence_count,
        recurrence_count=len(recurring_patterns),
        data_completeness=_estimate_data_completeness(latest_metrics, learning, state_transition),
        contradictions=contradictions,
    )
    reasoning = str(signal.get("reasoning") or "").strip() or "Deterministic signal rules identified the most likely contributing category."
    impacted_components = _dedupe_cap_lines(signal.get("impacted_components") or [], cap=6)
    next_validation_step = str(signal.get("next_validation_step") or _default_next_validation_step(category)).strip()

    return {
        "category": category,
        "confidence": confidence,
        "evidence": all_evidence,
        "primary_evidence": primary_evidence,
        "supporting_evidence": supporting_evidence,
        "reasoning": reasoning,
        "impacted_components": impacted_components,
        "next_validation_step": next_validation_step,
        "contradictions": contradictions[:4],
    }


def render_root_cause_section(root_cause: dict[str, Any], *, heading: str = "## 🔴 Root Cause Analysis") -> str:
    category = str(root_cause.get("category") or "inconclusive")
    category_label = _friendly_category_label(category)
    confidence = str(root_cause.get("confidence") or "LOW")
    primary_evidence = _dedupe_cap_lines(root_cause.get("primary_evidence") or [], cap=3)
    supporting_evidence = _dedupe_cap_lines(root_cause.get("supporting_evidence") or [], cap=5)
    if not primary_evidence:
        evidence_fallback = root_cause.get("evidence") if isinstance(root_cause.get("evidence"), list) else []
        primary_evidence = _dedupe_cap_lines(evidence_fallback, cap=3)
    reasoning = str(root_cause.get("reasoning") or "No deterministic explanation available.")
    impacted = root_cause.get("impacted_components") if isinstance(root_cause.get("impacted_components"), list) else []
    next_validation_step = str(root_cause.get("next_validation_step") or _default_next_validation_step(category))

    lines = [
        heading,
        "",
        f"- Category: {category_label} (`{category}`)",
        f"- Confidence: {confidence}",
        "- Primary Evidence:",
    ]
    if primary_evidence:
        lines.extend([f"  - {item}" for item in primary_evidence])
    else:
        lines.append("  - No evidence lines were captured.")
    lines.append("- Supporting Evidence:")
    if supporting_evidence:
        lines.extend([f"  - {item}" for item in supporting_evidence])
    else:
        lines.append("  - None")
    lines.append(f"- Explanation: {reasoning}")
    if impacted:
        lines.append("- Impacted Components: " + ", ".join(str(item) for item in impacted[:6]))
    lines.append(f"- Next Validation Step: {next_validation_step}")
    return "\n".join(lines)


def _extract_latest_metrics(supporting: dict[str, Any]) -> dict[str, Any]:
    history_context = supporting.get("history_context") if isinstance(supporting.get("history_context"), dict) else {}
    latest_run = history_context.get("latest_run") if isinstance(history_context.get("latest_run"), dict) else {}
    metrics = latest_run.get("metrics") if isinstance(latest_run.get("metrics"), dict) else {}
    return metrics


def _extract_host_check_context(*, supporting: dict[str, Any], latest_metrics: dict[str, Any]) -> dict[str, Any]:
    raw = supporting.get("host_check") if isinstance(supporting.get("host_check"), dict) else {}
    scope = str(raw.get("host_check_scope") or latest_metrics.get("host_check_scope") or "local_app_host").strip().lower()
    mode = str(raw.get("host_check_mode") or latest_metrics.get("host_check_mode") or "local_app_host").strip().lower()
    warning = str(raw.get("host_check_warning") or latest_metrics.get("host_check_warning") or "").strip()
    return {
        "host_check_scope": scope or "local_app_host",
        "host_check_mode": mode or "local_app_host",
        "host_check_warning": warning,
    }


def _extract_learning_features(supporting: dict[str, Any], state_transition: dict[str, Any]) -> dict[str, Any]:
    learning = state_transition.get("learning_features") if isinstance(state_transition.get("learning_features"), dict) else {}
    if learning:
        return learning
    alt = supporting.get("learning_features")
    return alt if isinstance(alt, dict) else {}


def _deep_get(payload: dict[str, Any], path: list[str]) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y", "on"}


def _to_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except Exception:
        return 0.0


def _to_int(value: Any) -> int:
    try:
        return int(float(value or 0))
    except Exception:
        return 0


def _score_to_confidence(score: float) -> str:
    if score >= 80.0:
        return "HIGH"
    if score >= 60.0:
        return "MEDIUM"
    return "LOW"


def _detect_blocking_signal(report_text: str, latest_metrics: dict[str, Any], active_payload: dict[str, Any]) -> dict[str, Any]:
    blocking_count = _to_int(active_payload.get("blocking_count"))
    if blocking_count == 0:
        blocking_count = _to_int(latest_metrics.get("blocking_count"))
    critical_count = _to_int(active_payload.get("blocking_critical_count"))
    warning_count = _to_int(active_payload.get("blocking_warning_count"))
    if critical_count == 0 and warning_count == 0:
        critical_count = _to_int(latest_metrics.get("blocking_critical_count"))
        warning_count = _to_int(latest_metrics.get("blocking_warning_count"))
    info_count = _to_int(active_payload.get("blocking_info_count"))
    if info_count == 0:
        info_count = _to_int(latest_metrics.get("blocking_info_count"))
    lock_wait = "row lock contention" in report_text or "enq: tx" in report_text
    only_transient_info = blocking_count > 0 and critical_count <= 0 and warning_count <= 0 and info_count >= blocking_count
    if only_transient_info and not lock_wait:
        return {"present": False}
    if blocking_count <= 0 and critical_count <= 0 and warning_count <= 0:
        return {"present": False}
    primary = []
    if critical_count > 0:
        primary.append(f"Critical blocking chains observed (`blocking_critical_count={critical_count}`).")
    elif warning_count > 0:
        primary.append(f"Sustained blocking chains observed (`blocking_warning_count={warning_count}`).")
    elif blocking_count > 0:
        primary.append(f"Active blocking sessions observed (`blocking_count={blocking_count}`).")
    if lock_wait:
        primary.append("Lock wait event detected (`enq: TX - row lock contention`).")
    supporting = []
    if "blocking chain" in report_text:
        supporting.append("Blocking-chain evidence is present in the current report.")
    if info_count > 0 and critical_count <= 0 and warning_count <= 0:
        supporting.append("Observed blockers are mostly transient/info severity.")
    return {
        "present": True,
        "strength": min(
            70.0
            + (15.0 if critical_count > 0 else 0.0)
            + (8.0 if warning_count > 0 else 0.0)
            + (5.0 if blocking_count >= 2 else 0.0)
            + (5.0 if lock_wait else 0.0),
            96.0,
        ),
        "primary_evidence": primary,
        "supporting_evidence": supporting,
        "reasoning": "Current locking evidence indicates foreground session contention driven by blockers.",
        "impacted_components": ["session concurrency", "transaction locks", "application throughput"],
        "next_validation_step": "Inspect blocker SID/SERIAL#, SQL_ID, and transaction age, then validate blocked session release after action.",
        "current_evidence_count": len(primary) + len(supporting),
    }


def _detect_sql_regression_signal(learning: dict[str, Any], awr: dict[str, Any], latest_metrics: dict[str, Any]) -> dict[str, Any]:
    sql_regression_flag = _to_bool(learning.get("sql_regression_flag")) or _to_bool(_deep_get(awr, ["sql_change", "sql_regression_flag"])) or _to_bool(_deep_get(awr, ["sql_change_summary", "sql_regression_flag"]))
    sql_regression_severity = str(learning.get("sql_regression_severity") or _deep_get(awr, ["sql_change", "sql_regression_severity"]) or _deep_get(awr, ["sql_change_summary", "sql_regression_severity"]) or "").upper()
    sql_elapsed_delta = abs(_to_float(learning.get("sql_elapsed_delta")))
    sql_cpu_delta = abs(_to_float(learning.get("sql_cpu_delta")))
    top_elapsed_s = _to_float(latest_metrics.get("top_elapsed_sql_elapsed_s"))
    db_time_s = _to_float(latest_metrics.get("db_time_s")) or _to_float(_deep_get(awr, ["db_time_s"]))
    elapsed_spike = _to_bool(_deep_get(awr, ["sql_change", "elapsed_per_exec_spike"])) or _to_bool(_deep_get(awr, ["sql_change_summary", "elapsed_per_exec_spike"]))
    cpu_spike = _to_bool(_deep_get(awr, ["sql_change", "cpu_per_exec_spike"])) or _to_bool(_deep_get(awr, ["sql_change_summary", "cpu_per_exec_spike"]))
    plan_changed = _to_bool(_deep_get(awr, ["sql_change", "plan_hash_changed_flag"])) or _to_bool(_deep_get(awr, ["sql_change_summary", "plan_hash_changed_flag"]))
    material_delta = bool(
        elapsed_spike
        or cpu_spike
        or sql_elapsed_delta >= 15.0
        or sql_cpu_delta >= 15.0
        or top_elapsed_s >= 30.0
        or db_time_s >= 60.0
        or (plan_changed and (elapsed_spike or cpu_spike))
    )
    severe = sql_regression_severity in {"MEDIUM", "HIGH", "CRITICAL", "WARNING"}
    if not (sql_regression_flag or severe or material_delta):
        return {"present": False}
    if top_elapsed_s < 30.0 and db_time_s < 60.0 and not (
        elapsed_spike or cpu_spike or sql_elapsed_delta >= 15.0 or sql_cpu_delta >= 15.0 or (plan_changed and (sql_elapsed_delta >= 15.0 or sql_cpu_delta >= 15.0))
    ):
        return {"present": False}
    primary = []
    if sql_regression_flag:
        primary.append("SQL regression flag is asserted by transition intelligence.")
    if severe:
        primary.append(f"SQL regression severity is `{sql_regression_severity}`.")
    if material_delta:
        primary.append(f"Material SQL delta observed (elapsed_delta={sql_elapsed_delta:.2f}, cpu_delta={sql_cpu_delta:.2f}).")
    supporting = []
    if elapsed_spike or cpu_spike:
        primary.append(f"Per-exec spike evidence exists (elapsed_per_exec_spike={elapsed_spike}, cpu_per_exec_spike={cpu_spike}).")
    if plan_changed:
        supporting.append("Plan hash churn/regression indicators are present.")
    return {
        "present": True,
        "strength": min(78.0 + (8.0 if severe else 0.0) + (8.0 if material_delta else 0.0), 95.0),
        "primary_evidence": primary,
        "supporting_evidence": supporting,
        "reasoning": "Top SQL behavior changed materially, with regression signals consistent with plan/runtime degradation.",
        "impacted_components": ["SQL execution", "optimizer plan stability", "response latency"],
        "next_validation_step": "Compare previous/current plan hash and per-exec elapsed for the dominant SQL_ID, then validate bind/plan stability.",
        "current_evidence_count": len(primary) + len(supporting),
    }


def _detect_sql_performance_pattern_signal(
    report_text: str,
    learning: dict[str, Any],
    awr: dict[str, Any],
    latest_metrics: dict[str, Any],
) -> dict[str, Any]:
    regression_flag = _to_bool(learning.get("sql_regression_flag")) or _to_bool(_deep_get(awr, ["sql_change", "sql_regression_flag"]))
    if regression_flag:
        return {"present": False}
    top_cpu_sql_s = _to_float(latest_metrics.get("top_cpu_sql_cpu_s"))
    top_elapsed_sql_s = _to_float(latest_metrics.get("top_elapsed_sql_elapsed_s"))
    sql_cpu_delta = abs(_to_float(learning.get("sql_cpu_delta")))
    sql_elapsed_delta = abs(_to_float(learning.get("sql_elapsed_delta")))
    present = (
        top_cpu_sql_s >= 20.0
        or top_elapsed_sql_s >= 45.0
        or sql_cpu_delta >= 10.0
        or sql_elapsed_delta >= 10.0
    )
    if not present:
        return {"present": False}
    primary = []
    if top_cpu_sql_s >= 20.0:
        primary.append(f"Top SQL CPU footprint is material (`top_cpu_sql_cpu_s={top_cpu_sql_s:.2f}`).")
    if top_elapsed_sql_s >= 45.0:
        primary.append(f"Top SQL elapsed time is material (`top_elapsed_sql_elapsed_s={top_elapsed_sql_s:.2f}`).")
    if sql_cpu_delta >= 10.0 or sql_elapsed_delta >= 10.0:
        primary.append(f"SQL runtime deltas increased (elapsed_delta={sql_elapsed_delta:.2f}, cpu_delta={sql_cpu_delta:.2f}).")
    if not primary:
        primary.append("SQL workload pattern is dominant in available evidence.")
    return {
        "present": True,
        "strength": min(68.0 + (8.0 if top_cpu_sql_s >= 60.0 else 0.0) + (6.0 if sql_cpu_delta >= 20.0 else 0.0), 88.0),
        "primary_evidence": primary,
        "supporting_evidence": ["SQL-centric pressure pattern detected without requiring host CPU saturation."],
        "reasoning": "Dominant incident signal is SQL behavior/performance pattern rather than host-wide CPU saturation.",
        "impacted_components": ["SQL execution profile", "response latency", "database workload mix"],
        "next_validation_step": "Run SQL_ID deep-dive for top contributors and compare per-exec elapsed/cpu against previous healthy runs.",
        "current_evidence_count": len(primary) + 1,
    }


def _detect_cpu_signal(
    report_text: str,
    learning: dict[str, Any],
    awr: dict[str, Any],
    latest_metrics: dict[str, Any],
    host_check: dict[str, Any],
) -> dict[str, Any]:
    host_cpu_pct = _to_float(latest_metrics.get("host_cpu_pct"))
    container_cpu_pct = _to_float(latest_metrics.get("container_cpu_pct"))
    sql_cpu_delta = abs(_to_float(learning.get("sql_cpu_delta")))
    top_cpu_sql_s = _to_float(latest_metrics.get("top_cpu_sql_cpu_s"))
    active_sessions = _to_int(latest_metrics.get("active_sessions"))
    true_active = _to_int(latest_metrics.get("true_active_non_idle"))
    idle_active = _to_int(latest_metrics.get("active_idle_waiting"))
    has_true_active_metric = "true_active_non_idle" in latest_metrics
    activity_anchor = true_active if has_true_active_metric else active_sessions
    cpu_flag = _to_bool(_deep_get(awr, ["host_cpu_state", "cpu_pressure_flag"]))
    cpu_hotspot_text = "cpu hotspot" in report_text or "cpu pressure" in report_text or "db cpu" in report_text
    scope = str(host_check.get("host_check_scope") or "local_app_host")
    mode = str(host_check.get("host_check_mode") or "local_app_host")
    if mode == "ssh_remote" and scope == "unavailable":
        return {"present": False}
    host_saturated = host_cpu_pct >= 75.0 or container_cpu_pct >= 75.0
    oracle_cpu_corroboration = bool(
        cpu_flag
        or sql_cpu_delta >= 25.0
        or ("on cpu" in report_text and activity_anchor >= 3)
        or ("db cpu" in report_text and activity_anchor >= 3)
    )
    present = bool(host_saturated or (oracle_cpu_corroboration and cpu_hotspot_text))
    if scope == "local_app_host":
        present = bool(host_saturated and oracle_cpu_corroboration)
    if scope in {"disabled", "unavailable"}:
        present = bool(oracle_cpu_corroboration and (cpu_flag or "on cpu" in report_text))
    if not present:
        return {"present": False}
    primary = []
    if host_cpu_pct >= 75.0 or container_cpu_pct >= 75.0:
        if scope == "local_app_host":
            primary.append(
                f"Local app host/container CPU is elevated (`host_cpu_pct={host_cpu_pct:.2f}`, `container_cpu_pct={container_cpu_pct:.2f}`), not automatically the Oracle DB host."
            )
        else:
            primary.append(f"Host/container CPU is elevated (`host_cpu_pct={host_cpu_pct:.2f}`, `container_cpu_pct={container_cpu_pct:.2f}`).")
    if cpu_flag:
        primary.append("AWR host CPU pressure flag is set.")
    if sql_cpu_delta >= 25.0 or ("on cpu" in report_text and activity_anchor >= 3):
        primary.append(
            "Database CPU corroboration exists "
            f"(sql_cpu_delta={sql_cpu_delta:.2f}, top_cpu_sql_cpu_s={top_cpu_sql_s:.2f}, "
            f"true_active_non_idle={true_active}, active_sessions={active_sessions}, active_idle_waiting={idle_active})."
        )
    if not primary:
        primary.append("CPU pressure pattern is present in current workload evidence.")
    supporting = ["CPU-heavy workload indicators align across SQL/runtime evidence."]
    if scope == "local_app_host":
        supporting.append("Host scope is local AutoDBA runtime; DB-host attribution requires Oracle-side corroboration.")
    return {
        "present": True,
        "strength": min(
            72.0 + (10.0 if host_cpu_pct >= 85.0 and scope == "remote_db_host_ssh" else 0.0) + (6.0 if cpu_flag else 0.0),
            92.0,
        ),
        "primary_evidence": primary,
        "supporting_evidence": supporting,
        "reasoning": "CPU-bound behavior is present across host and DB workload indicators.",
        "impacted_components": ["CPU scheduler", "foreground workers", "latency-sensitive sessions"],
        "next_validation_step": "Validate top CPU SQL_ID/module and confirm whether CPU normalizes after reducing hotspot workload.",
        "current_evidence_count": len(primary) + len(supporting),
    }


def _detect_memory_signal(
    report_text: str,
    learning: dict[str, Any],
    awr: dict[str, Any],
    latest_metrics: dict[str, Any],
    host_check: dict[str, Any],
    supporting: dict[str, Any] | None = None,
) -> dict[str, Any]:
    memory_pct = _to_float(latest_metrics.get("memory_pct"))
    if memory_pct <= 0:
        memory_pct = _to_float(latest_metrics.get("host_memory_pct"))
    container_memory_pct = _to_float(latest_metrics.get("container_memory_pct"))
    temp_usage_pct = _to_float(latest_metrics.get("temp_usage_pct"))
    mem_flag = _to_bool(learning.get("memory_pressure_flag")) or _to_bool(_deep_get(awr, ["memory_state", "memory_pressure_flag"]))
    scope = str(host_check.get("host_check_scope") or "local_app_host")
    mode = str(host_check.get("host_check_mode") or "local_app_host")
    if mode == "ssh_remote" and scope == "unavailable":
        return {"present": False}

    memory_cfg = (supporting or {}).get("memory_config") if isinstance((supporting or {}).get("memory_config"), dict) else {}
    pga_sga_pct = _to_float(latest_metrics.get("pga_sga_pct")) or _to_float(latest_metrics.get("pga_to_sga_pct")) or _to_float(memory_cfg.get("pga_to_sga_pct"))
    pga_mb = _to_float(latest_metrics.get("pga_mb")) or _to_float(memory_cfg.get("pga_mb"))
    temp_consumers = _to_int(latest_metrics.get("temp_consumer_count")) or _to_int(memory_cfg.get("temp_consumer_count"))
    memory_hotspot_triggered = _to_bool(latest_metrics.get("memory_hotspot_triggered"))
    ora_memory_error = "ora-04030" in report_text or "ora-04031" in report_text
    top_pga_sessions = memory_cfg.get("top_pga_sessions") if isinstance(memory_cfg.get("top_pga_sessions"), list) else []
    top_session_memory_high = False
    for row in top_pga_sessions[:10]:
        if not isinstance(row, dict):
            continue
        if _to_float(row.get("pga_used_mb")) >= 512.0 or _to_float(row.get("temp_used_mb")) >= 512.0:
            top_session_memory_high = True
            break

    indicator_flags = {
        "pga_sga_pct_high": pga_sga_pct >= 25.0,
        "pga_in_use_high": pga_mb >= 2048.0,
        "temp_consumers_or_usage": temp_consumers > 0 or temp_usage_pct >= 70.0,
        "os_or_container_memory_high": max(memory_pct, container_memory_pct) >= 85.0,
        "memory_hotspot_triggered": memory_hotspot_triggered,
        "ora_memory_error": ora_memory_error,
        "top_sessions_high_pga_temp": top_session_memory_high,
    }
    current_indicator_count = sum(1 for active in indicator_flags.values() if active)
    has_oracle_memory_evidence = bool(current_indicator_count >= 2 or mem_flag)
    present = current_indicator_count >= 2

    if scope in {"disabled", "unavailable"} and not has_oracle_memory_evidence:
        present = False
    if scope == "local_app_host" and not has_oracle_memory_evidence:
        present = False
    if not present:
        return {"present": False}

    primary = []
    if indicator_flags["pga_sga_pct_high"]:
        primary.append(f"PGA/SGA ratio is elevated (`pga_sga_pct={pga_sga_pct:.2f}`).")
    if indicator_flags["pga_in_use_high"]:
        primary.append(f"PGA in-use is materially high (`pga_mb={pga_mb:.2f}`).")
    if indicator_flags["temp_consumers_or_usage"]:
        if temp_consumers > 0:
            primary.append(f"TEMP consumers are active (`temp_consumer_count={temp_consumers}`).")
        else:
            primary.append(f"TEMP utilization is high (`temp_usage_pct={temp_usage_pct:.2f}`).")
    if indicator_flags["os_or_container_memory_high"]:
        if scope == "local_app_host":
            primary.append(
                f"Local app host/container memory is elevated (`host_memory_pct={memory_pct:.2f}`, "
                f"`container_memory_pct={container_memory_pct:.2f}`), not automatically the Oracle DB host."
            )
        else:
            primary.append(
                f"Host/container memory is elevated (`host_memory_pct={memory_pct:.2f}`, "
                f"`container_memory_pct={container_memory_pct:.2f}`)."
            )
    if indicator_flags["memory_hotspot_triggered"]:
        primary.append("Memory hotspot trigger is active in current host evidence.")
    if indicator_flags["ora_memory_error"]:
        primary.append("ORA-04030/ORA-04031 memory error signals were observed in current diagnostics.")
    if indicator_flags["top_sessions_high_pga_temp"]:
        primary.append("Top sessions show high PGA/TEMP usage.")

    supporting_rows = []
    if mem_flag:
        supporting_rows.append("AWR/transition memory-pressure flag exists and supports current indicators.")
    if "pga" in report_text:
        supporting_rows.append("PGA usage evidence appears in current report details.")
    if scope == "local_app_host":
        supporting_rows.append("Host scope is local AutoDBA runtime; DB-host attribution requires Oracle-side corroboration.")

    return {
        "present": True,
        "strength": min(
            70.0 + (8.0 if max(memory_pct, container_memory_pct) >= 90.0 and scope == "remote_db_host_ssh" else 0.0) + (6.0 if mem_flag else 0.0),
            90.0,
        ),
        "primary_evidence": primary,
        "supporting_evidence": supporting_rows,
        "reasoning": "Memory pressure indicators suggest constrained working-set resources for Oracle workload.",
        "impacted_components": ["memory management", "PGA/SGA consumers", "session runtime"],
        "next_validation_step": "Validate top PGA/TEMP consumers and memory parameters, then confirm pressure drops after workload correction.",
        "current_evidence_count": len(primary) + len(supporting_rows),
    }


def _detect_storage_or_alert_signal(report_text: str, latest_metrics: dict[str, Any]) -> dict[str, Any]:
    hottest_ts_pct = _to_float(latest_metrics.get("hottest_tablespace_pct"))
    fra_pct = _to_float(latest_metrics.get("fra_pct"))
    alert_count = _to_int(latest_metrics.get("alert_ora_tns_count")) or _to_int(latest_metrics.get("alert_log_count"))
    listener_count = _to_int(latest_metrics.get("listener_error_count"))
    archive_error_count = _to_int(latest_metrics.get("archive_dest_error_count"))
    ora_1653 = "ora-01653" in report_text
    present = hottest_ts_pct >= 90.0 or fra_pct >= 85.0 or alert_count > 0 or listener_count > 0 or archive_error_count > 0
    if not present:
        return {"present": False}
    primary = []
    if ora_1653 and alert_count > 0:
        primary.append("Allocation failure detected (`ORA-01653`).")
    if hottest_ts_pct >= 90.0:
        primary.append(f"Tablespace pressure is high (`hottest_tablespace_pct={hottest_ts_pct:.2f}`).")
    if fra_pct >= 85.0:
        primary.append(f"FRA/archive pressure is elevated (`fra_pct={fra_pct:.2f}`).")
    if alert_count > 0 or listener_count > 0 or archive_error_count > 0:
        primary.append(
            "Alert/listener/archive errors are present "
            f"(`alert_log_count={alert_count}`, `listener_error_count={listener_count}`, `archive_dest_error_count={archive_error_count}`)."
        )
    if not primary:
        primary.append("Storage or alert-log error signals are present in current evidence.")
    return {
        "present": True,
        "strength": min(74.0 + (10.0 if ora_1653 else 0.0) + (8.0 if hottest_ts_pct >= 95.0 else 0.0), 93.0),
        "primary_evidence": primary,
        "supporting_evidence": ["Storage or alert-log failure patterns align with incident symptoms."],
        "reasoning": "Storage-capacity or error-log evidence indicates operational risk affecting workload continuity.",
        "impacted_components": ["tablespace/FRA capacity", "archive/logging pipeline", "session reliability"],
        "next_validation_step": "Verify free space/autoextend/archive destinations and clear recurring ORA/TNS sources, then re-check error counts.",
        "current_evidence_count": len(primary) + 1,
    }


def _detect_investigation_likely_cause_signal(supporting: dict[str, Any]) -> dict[str, Any]:
    likely_cause = str(_deep_get(supporting, ["likely_cause"]) or "").strip()
    evidence = supporting.get("evidence") if isinstance(supporting.get("evidence"), list) else []
    step_count = len(supporting.get("steps") or []) if isinstance(supporting.get("steps"), list) else 0
    if not likely_cause:
        return {"present": False}
    category = _category_from_text(likely_cause)
    return {
        "present": True,
        "category": category,
        "strength": min(64.0 + (8.0 if evidence else 0.0) + (6.0 if step_count >= 2 else 0.0), 86.0),
        "primary_evidence": [f"Likely cause from investigation: {likely_cause}", f"Investigation steps executed: {step_count}"],
        "supporting_evidence": [str(item) for item in evidence[:3]],
        "reasoning": "Investigation likely-cause statement is consistent with SQL-step evidence captured during analysis.",
        "impacted_components": _components_for_category(category),
        "next_validation_step": _default_next_validation_step(category),
        "current_evidence_count": 1 + (1 if evidence else 0),
    }


def _build_inconclusive_signal(latest_metrics: dict[str, Any], learning: dict[str, Any], recurring_patterns: list[str]) -> dict[str, Any]:
    supporting = []
    if latest_metrics:
        supporting.append(f"metrics_available={len(latest_metrics)}")
    if learning:
        supporting.append(f"learning_features_available={len(learning)}")
    if recurring_patterns:
        supporting.append(f"recurrence_count={len(recurring_patterns)}")
    if not supporting:
        supporting.append("signal_collection=limited")
    return {
        "present": True,
        "strength": 35.0,
        "primary_evidence": ["No dominant current incident signal exceeded deterministic thresholds."],
        "supporting_evidence": supporting,
        "reasoning": "Collected signals are weak, mixed, or incomplete for strong root-cause attribution.",
        "impacted_components": ["requires additional evidence collection"],
        "next_validation_step": _default_next_validation_step("inconclusive"),
        "current_evidence_count": 0,
    }


def _extract_recurring_patterns(supporting: dict[str, Any], state_transition: dict[str, Any]) -> list[str]:
    recurring = state_transition.get("recurring_patterns_ranked") if isinstance(state_transition.get("recurring_patterns_ranked"), list) else []
    if recurring:
        return [str(item) for item in recurring if str(item).strip()]
    history_context = supporting.get("history_context") if isinstance(supporting.get("history_context"), dict) else {}
    raw = history_context.get("recurring_findings")
    if isinstance(raw, list):
        return [str(item) for item in raw if str(item).strip()]
    return []


def _build_recurrence_support(recurring_patterns: list[str]) -> list[str]:
    if not recurring_patterns:
        return []
    lines = [f"Recurring historical pattern count: {len(recurring_patterns)}."]
    if recurring_patterns:
        lines.append(f"Top recurring pattern: {recurring_patterns[0]}")
    if len(recurring_patterns) > 1:
        lines.append(f"Additional recurring pattern: {recurring_patterns[1]}")
    return lines


def _category_contradictions(
    *,
    category: str,
    latest_metrics: dict[str, Any],
    report_text: str,
    signal: dict[str, Any],
) -> list[str]:
    out: list[str] = []
    if category == "memory_pressure":
        host_mem = _to_float(latest_metrics.get("memory_pct")) or _to_float(latest_metrics.get("host_memory_pct"))
        container_mem = _to_float(latest_metrics.get("container_memory_pct"))
        temp_consumers = _to_int(latest_metrics.get("temp_consumer_count"))
        temp_pct = _to_float(latest_metrics.get("temp_usage_pct"))
        pga_sga = _to_float(latest_metrics.get("pga_sga_pct")) or _to_float(latest_metrics.get("pga_to_sga_pct"))
        if max(host_mem, container_mem) < 85.0 and temp_consumers <= 0 and temp_pct < 70.0 and pga_sga < 25.0 and "ora-0403" not in report_text:
            out.append("Current memory indicators contradict memory_pressure (host/container/PGA/TEMP are not materially high).")
    if category == "blocking_lock":
        if _to_int(latest_metrics.get("blocking_count")) <= 0 and _to_int(signal.get("current_evidence_count")) <= 0:
            out.append("Current metrics contradict blocking_lock (blocking_count=0).")
    if category == "storage_or_alert_error":
        alert_count = _to_int(latest_metrics.get("alert_ora_tns_count")) or _to_int(latest_metrics.get("alert_log_count"))
        listener_count = _to_int(latest_metrics.get("listener_error_count"))
        if alert_count <= 0 and listener_count <= 0 and _to_float(latest_metrics.get("hottest_tablespace_pct")) < 90.0 and _to_float(latest_metrics.get("fra_pct")) < 85.0:
            out.append("Current metrics contradict storage_or_alert_error (no current ORA/TNS/storage pressure signals).")
    if category == "sql_regression":
        top_elapsed = _to_float(latest_metrics.get("top_elapsed_sql_elapsed_s"))
        db_time_s = _to_float(latest_metrics.get("db_time_s"))
        if top_elapsed < 30.0 and db_time_s < 60.0:
            out.append("Current metrics contradict high SQL regression impact (DB Time/top elapsed are below incident thresholds).")
    return _dedupe_cap_lines(out, cap=4)


def _resolve_confidence(
    *,
    score: float,
    category: str,
    host_check_scope: str,
    current_evidence_count: int,
    recurrence_count: int,
    data_completeness: float,
    contradictions: list[str] | None = None,
) -> str:
    adjusted = score
    if current_evidence_count >= 2:
        adjusted += 6.0
    if current_evidence_count >= 3:
        adjusted += 4.0
    if recurrence_count > 0 and category != "historical_recurrence":
        adjusted += min(6.0, float(recurrence_count) * 1.5)
    adjusted += (data_completeness - 0.5) * 10.0

    if category == "historical_recurrence":
        if recurrence_count >= 3 and data_completeness >= 0.6:
            return "MEDIUM"
        return "LOW"
    if category == "inconclusive":
        return "LOW"
    resolved = _score_to_confidence(adjusted)
    contradictions = contradictions or []
    if contradictions and resolved == "HIGH":
        resolved = "MEDIUM"
    if any("contradicts" in item.lower() for item in contradictions):
        resolved = "LOW"
    if category in {"cpu_pressure", "memory_pressure"} and host_check_scope == "local_app_host" and resolved == "HIGH":
        return "MEDIUM"
    if category in {"cpu_pressure", "memory_pressure"} and host_check_scope in {"disabled", "unavailable"}:
        return "LOW"
    return resolved


def _estimate_data_completeness(latest_metrics: dict[str, Any], learning: dict[str, Any], state_transition: dict[str, Any]) -> float:
    score = 0.0
    if latest_metrics:
        score += 0.4
    if learning:
        score += 0.3
    if state_transition:
        score += 0.3
    return min(score, 1.0)


def _friendly_category_label(category: str) -> str:
    return {
        "blocking_lock": "Blocking / lock contention",
        "sql_regression": "SQL regression / top SQL change",
        "sql_performance_pattern": "SQL performance pattern",
        "cpu_pressure": "CPU pressure",
        "memory_pressure": "Memory pressure",
        "storage_or_alert_error": "Storage / alert-log error",
        "historical_recurrence": "Recurring historical pattern",
        "inconclusive": "Inconclusive",
    }.get(category, category.replace("_", " ").strip().title())


def _category_from_text(text: str) -> str:
    lowered = (text or "").lower()
    if "lock" in lowered or "blocking" in lowered:
        return "blocking_lock"
    if "sql" in lowered and ("regression" in lowered or "plan" in lowered):
        return "sql_regression"
    if "sql" in lowered:
        return "sql_performance_pattern"
    if "cpu" in lowered:
        return "cpu_pressure"
    if "memory" in lowered or "pga" in lowered or "sga" in lowered:
        return "memory_pressure"
    if "ora-01653" in lowered or "tablespace" in lowered or "fra" in lowered or "tns" in lowered:
        return "storage_or_alert_error"
    return "inconclusive"


def _components_for_category(category: str) -> list[str]:
    mapping = {
        "blocking_lock": ["session concurrency", "transaction locks"],
        "sql_regression": ["SQL execution", "optimizer plan"],
        "sql_performance_pattern": ["SQL execution profile", "database workload mix"],
        "cpu_pressure": ["CPU scheduler", "foreground workers"],
        "memory_pressure": ["memory management", "session memory"],
        "storage_or_alert_error": ["tablespace/FRA capacity", "alert-log stability"],
        "historical_recurrence": ["historical workload stability"],
        "inconclusive": ["requires additional evidence collection"],
    }
    return list(mapping.get(category, ["investigation evidence"]))


def _default_next_validation_step(category: str) -> str:
    mapping = {
        "blocking_lock": "Validate blocker session identity and confirm blocked-session release after remediation.",
        "sql_regression": "Compare dominant SQL plan hash and per-exec elapsed against previous healthy runs.",
        "sql_performance_pattern": "Deep dive top SQL contributors and validate whether execution profile aligns with observed latency.",
        "cpu_pressure": "Correlate top CPU SQL/session evidence with host/container CPU and re-check after throttling workload.",
        "memory_pressure": "Inspect top PGA/TEMP consumers and memory configuration before and after load normalization.",
        "storage_or_alert_error": "Check tablespace/FRA capacity and recent ORA/TNS errors, then verify error-rate reduction.",
        "historical_recurrence": "Run another health cycle and verify whether the same recurring fingerprint reappears.",
        "inconclusive": "Collect an additional run with ASH/AWR and active-session evidence to refine attribution.",
    }
    return mapping.get(category, mapping["inconclusive"])


def _dedupe_cap_lines(values: list[Any], *, cap: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = _normalize_evidence_line(value)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= max(1, cap):
            break
    return out


def _normalize_evidence_line(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.replace("\n", " ").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:240]
