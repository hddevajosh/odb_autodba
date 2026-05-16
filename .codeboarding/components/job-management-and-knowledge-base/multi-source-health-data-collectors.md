---
component_id: 5.2
component_name: Multi-Source Health Data Collectors
---

# Multi-Source Health Data Collectors

## Component Description

Executes low-level telemetry collection across Oracle databases and host operating systems to provide the raw data for diagnostic jobs.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/db/extended_health_checks.py (lines 33-144)
```
def collect_extended_health(window_hours: int = 24) -> tuple[list[HealthCheckSection], list[ActionableHealthItem], dict[str, Any]]:
    hours = max(int(window_hours or 24), 1)
    raw: dict[str, Any] = {}
    sections: list[HealthCheckSection] = []
    actions: list[ActionableHealthItem] = []

    db_status = _db_status()
    raw["db_status"] = db_status
    sections.append(_section("Database Status", _db_status_level(db_status), _db_status_summary(db_status), [db_status] if db_status else []))

    alert_check = _alert_log_check(hours)
    alert_rows = alert_check["rows"]
    raw["alert_log"] = alert_rows
    raw["alert_log_check"] = alert_check
    alert_section = _alert_section(alert_check, hours)
    sections.append(alert_section)
    actions.extend(_alert_actions(alert_rows, hours))

    storage_rows = _tablespace_rows()
    raw["tablespaces"] = storage_rows
    tablespace_section = _tablespace_section(storage_rows)
    anomaly_note = _tablespace_allocation_note(alert_rows=alert_rows, tablespace_rows=storage_rows)
    if anomaly_note:
        tablespace_section.notes.append(anomaly_note)
        alert_section.notes.append(anomaly_note)
        raw["tablespace_allocation_failure_with_low_pct"] = True
    sections.append(tablespace_section)
    actions.extend(_tablespace_actions(storage_rows))

    temp = _temp_summary()
    raw["temp"] = temp
    sections.append(_temp_section(temp))
    actions.extend(_temp_actions(temp))

    locks, lock_err = _lock_pairs()
    raw["lock_pairs"] = locks
    lock_section: HealthCheckSection
    if lock_err and not locks:
        sections.append(
            _section(
                "Locks And Blocking",
                "WARNING",
                "Blocking-session query could not be completed.",
                [],
                notes=[lock_err],
            )
        )
    else:
        lock_notes = [f"Query warning: {lock_err}"] if lock_err else []
        lock_section = _section(
            "Locks And Blocking",
            "CRITICAL" if locks else "OK",
            "No blocking sessions detected." if not locks else f"{len(locks)} blocked session(s) detected.",
            locks[:10],
            notes=lock_notes,
        )
        sections.append(lock_section)
    if locks:
        actions.append(ActionableHealthItem(category="blocking", title="Blocking locks detected", severity="CRITICAL", detail=f"{len(locks)} blocked session(s) found.", recommendation="Review blocker SQL and user before using the guarded remediation flow.", evidence=[_lock_evidence(row) for row in locks[:3]]))

    invalids = _invalid_objects()
    raw["invalid_objects"] = invalids
    sections.append(_section("Objects And Validity", "CRITICAL" if invalids else "OK", "No invalid non-system objects found." if not invalids else f"{len(invalids)} invalid non-system object sample row(s).", invalids[:20]))
    if invalids:
        actions.append(ActionableHealthItem(category="objects", title="Invalid objects present", severity="CRITICAL", detail=f"{len(invalids)} invalid non-system object sample row(s).", recommendation="Compile invalid objects and investigate dependency failures.", evidence=[f"{row.get('owner')}.{row.get('object_name')} {row.get('object_type')}" for row in invalids[:5]]))

    redo = _redo_archive(hours)
    raw["redo_archive"] = redo
    sections.append(_redo_section(redo, hours))
    actions.extend(_redo_actions(redo, hours))

    recovery = _recovery(hours)
    raw["recovery"] = recovery
    sections.append(_recovery_section(recovery, hours))
    actions.extend(_recovery_actions(recovery, hours))

    scheduler = _scheduler_failures(hours)
    raw["scheduler_failures"] = scheduler
    sections.append(_section("Scheduler Jobs", "CRITICAL" if scheduler else "OK", "No scheduler failures found in the health window." if not scheduler else f"{len(scheduler)} scheduler failure sample row(s).", scheduler[:10]))
    if scheduler:
        actions.append(ActionableHealthItem(category="scheduler", title="Scheduler job failures", severity="CRITICAL", detail=f"{len(scheduler)} failed job run sample row(s) in the last {hours}h.", recommendation="Review failed job logs and fix job-specific errors.", evidence=[str(row) for row in scheduler[:3]]))

    performance = _performance(hours)
    raw["performance"] = performance
    performance_sections = _performance_sections(performance)
    sections.extend(performance_sections)
    actions.extend(_performance_actions(performance, hours))
    lock_wait_note = _lock_wait_without_blocker_note(
        wait_rows=(performance.get("current_waits") or []) + (performance.get("awr_waits") or []),
        has_blockers=bool(locks),
    )
    if lock_wait_note:
        raw["blocking_interpretation_note"] = lock_wait_note
        for section in sections:
            if section.name in {"Locks And Blocking", "Current Wait Profile", "AWR Wait Events"}:
                section.notes.append(lock_wait_note)

    transactions = _transactions()
    raw["transactions"] = transactions
    sections.append(_transaction_section(transactions))
    actions.extend(_transaction_actions(transactions))

    memory = _memory_config()
    raw["memory_config"] = memory
    sections.append(_memory_section(memory))
    actions.extend(_memory_actions(memory))

    init_params = _init_params()
    raw["init_params"] = init_params
    sections.append(_section("Init Parameters", "INFO", f"{len(init_params.get('non_default', []))} non-default parameter row(s), {len(init_params.get('key', []))} key parameter row(s).", init_params.get("key", [])[:25], notes=[f"Non-default parameters captured: {len(init_params.get('non_default', []))}"]))

    return sections, actions, raw
```

### /home/neha/projects/agents/odb_autodba/host/health_checks.py (lines 114-182)
```
def collect_host_snapshot() -> HostSnapshot:
    filesystems = _collect_filesystems()
    notes: list[str] = []

    top_n = _env_int("PROCESS_TOP_N", 5)
    cpu_threshold = _env_float("HOST_CPU_HOTSPOT_THRESHOLD_PCT", 70.0)
    mem_threshold = _env_float("HOST_MEMORY_HOTSPOT_THRESHOLD_PCT", 80.0)
    container_cpu_threshold = _env_float("CONTAINER_CPU_HOTSPOT_THRESHOLD_PCT", 70.0)
    container_mem_threshold = _env_float("CONTAINER_MEMORY_HOTSPOT_THRESHOLD_PCT", 80.0)

    top_cpu_processes = _collect_process_rows(sort_key="cpu", limit=top_n)
    top_memory_processes = _collect_process_rows(sort_key="memory", limit=top_n)

    loadavg = _run(["cat", "/proc/loadavg"]) if os.path.exists("/proc/loadavg") else ""
    cpu_pct = _host_cpu_pct()
    memory_pct, swap_pct = _memory_percentages()

    mount_points = _collect_mount_points()
    docker_container = _detect_oracle_docker_container()
    docker_stats: dict[str, Any] = {}
    if docker_container:
        docker_stats = _docker_stats(docker_container) or {}
        docker_mounts = _docker_mount_points(docker_container)
        if docker_mounts:
            mount_points["container"] = docker_mounts
    else:
        notes.append("Docker Oracle container was not detected or Docker is not accessible.")

    container_cpu_pct = _as_float((docker_stats or {}).get("cpu_pct"))
    container_mem_pct = _as_float((docker_stats or {}).get("memory_pct"))

    cpu_hotspot = _build_cpu_hotspot_section(
        host_cpu_pct=cpu_pct,
        container_cpu_pct=container_cpu_pct,
        top_processes=top_cpu_processes,
        top_n=top_n,
        threshold_pct=cpu_threshold,
        container_threshold_pct=container_cpu_threshold,
    )
    memory_hotspot = _build_memory_hotspot_section(
        host_memory_pct=memory_pct,
        container_memory_pct=container_mem_pct,
        top_processes=top_memory_processes,
        top_n=top_n,
        threshold_pct=mem_threshold,
        container_threshold_pct=container_mem_threshold,
    )

    return HostSnapshot(
        host_check_mode=HOST_CHECK_MODE_LOCAL_APP_HOST,
        host_check_scope=HOST_CHECK_MODE_LOCAL_APP_HOST,
        host_check_label="Local AutoDBA app host",
        host_check_warning=(
            "These metrics describe the AutoDBA runtime machine, not necessarily the Oracle DB server."
        ),
        cpu_pct=cpu_pct,
        memory_pct=memory_pct,
        swap_pct=swap_pct,
        filesystems=filesystems,
        top_processes=top_cpu_processes,
        docker_container=docker_container,
        docker_stats=docker_stats,
        top_memory_processes=top_memory_processes,
        cpu_hotspot=cpu_hotspot,
        memory_hotspot=memory_hotspot,
        load_average=loadavg,
        mount_points=mount_points,
        notes=notes,
    )
```


## Source Files:

- `db/extended_health_checks.py`
- `host/health_checks.py`

