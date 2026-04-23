from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, ConfigDict

MetricStatus = Literal["OK", "WARNING", "CRITICAL"]
ReviewConfidence = Literal["LOW", "MEDIUM", "HIGH"]
BlockerClassification = Literal[
    "application_session",
    "idle_in_transaction_blocker",
    "batch_job",
    "dbms_scheduler",
    "maintenance_session",
    "sys_or_background",
    "unknown",
]
PlannerResponseMode = Literal[
    "full_health_report",
    "investigation_report",
    "history_report",
    "focused_domain_report",
]
RemediationReviewerStatus = Literal["pending", "approved", "rejected", "not_needed"]
RemediationExecutionStatus = Literal["not_started", "succeeded", "failed", "skipped"]


class InstanceInfo(BaseModel):
    instance_name: str = ""
    host_name: str = ""
    version: str = ""
    startup_time: str = ""
    db_name: str = ""
    db_unique_name: str = ""
    open_mode: str = ""
    database_role: str = ""
    platform_name: str = ""
    rac_enabled: bool = False
    cdb: str | None = None


class SessionSummary(BaseModel):
    total_sessions: int = 0
    active_sessions: int = 0
    inactive_sessions: int = 0
    blocked_sessions: int = 0
    blocking_sessions: int = 0
    user_sessions: int = 0
    long_running_sessions: int = 0


class SessionRow(BaseModel):
    inst_id: int | None = None
    sid: int
    serial_num: int | None = None
    username: str | None = None
    status: str | None = None
    sql_id: str | None = None
    event: str | None = None
    wait_class: str | None = None
    module: str | None = None
    program: str | None = None
    machine: str | None = None
    seconds_in_wait: int | None = None
    last_call_et: int | None = None
    blocking_instance: int | None = None
    blocking_session: int | None = None

    model_config = ConfigDict(populate_by_name=True)


class BlockingChain(BaseModel):
    blocker_inst_id: int | None = None
    blocker_sid: int | None = None
    blocker_serial: int | None = None
    blocker_user: str | None = None
    blocker_sql_id: str | None = None
    blocked_inst_id: int | None = None
    blocked_sid: int | None = None
    blocked_serial: int | None = None
    blocked_user: str | None = None
    blocked_sql_id: str | None = None
    event: str | None = None
    wait_class: str | None = None
    seconds_in_wait: int | None = None
    blocker_status: str | None = None
    blocked_status: str | None = None
    blocker_event: str | None = None
    blocker_wait_class: str | None = None
    blocker_seconds_in_wait: int | None = None
    blocker_blocking_session: int | None = None
    blocker_blocking_instance: int | None = None
    blocker_final_blocking_session: int | None = None
    blocker_final_blocking_instance: int | None = None
    blocker_program: str | None = None
    blocker_module: str | None = None
    blocker_machine: str | None = None
    blocker_osuser: str | None = None
    blocker_logon_time: str | None = None
    blocker_last_call_et: int | None = None
    blocker_row_wait_obj: int | None = None
    blocker_row_wait_file: int | None = None
    blocker_row_wait_block: int | None = None
    blocker_row_wait_row: int | None = None
    blocker_spid: str | None = None
    blocker_has_transaction: bool | None = None
    blocker_idle_in_transaction: bool | None = None
    blocked_blocking_session: int | None = None
    blocked_blocking_instance: int | None = None
    blocked_final_blocking_session: int | None = None
    blocked_final_blocking_instance: int | None = None
    blocked_program: str | None = None
    blocked_module: str | None = None
    blocked_machine: str | None = None
    blocked_osuser: str | None = None
    blocked_logon_time: str | None = None
    blocked_last_call_et: int | None = None
    blocked_row_wait_obj: int | None = None
    blocked_row_wait_file: int | None = None
    blocked_row_wait_block: int | None = None
    blocked_row_wait_row: int | None = None
    blocked_spid: str | None = None
    held_lock_type: str | None = None
    held_lock_mode: int | None = None
    requested_lock_type: str | None = None
    requested_lock_mode: int | None = None
    blocked_session_count: int | None = None
    max_blocked_wait_seconds: int | None = None
    object_owner: str | None = None
    object_name: str | None = None
    object_type: str | None = None
    blocker_sql_text: str | None = None
    blocked_sql_text: str | None = None
    blocker_classification: BlockerClassification = "unknown"
    evidence_complete: bool = False


class BlockingSessionDetail(BaseModel):
    inst_id: int | None = None
    sid: int | None = None
    serial_num: int | None = None
    username: str | None = None
    status: str | None = None
    sql_id: str | None = None
    sql_text: str | None = None
    event: str | None = None
    wait_class: str | None = None
    seconds_in_wait: int | None = None
    blocking_session: int | None = None
    blocking_instance: int | None = None
    final_blocking_session: int | None = None
    final_blocking_instance: int | None = None
    program: str | None = None
    module: str | None = None
    machine: str | None = None
    osuser: str | None = None
    logon_time: str | None = None
    last_call_et: int | None = None
    row_wait_obj: int | None = None
    row_wait_file: int | None = None
    row_wait_block: int | None = None
    row_wait_row: int | None = None
    held_lock_type: str | None = None
    held_lock_mode: int | None = None
    requested_lock_type: str | None = None
    requested_lock_mode: int | None = None
    spid: str | None = None
    has_transaction: bool | None = None
    idle_in_transaction: bool | None = None


class BlockingChainDetail(BaseModel):
    blocker: BlockingSessionDetail = Field(default_factory=BlockingSessionDetail)
    blocked: BlockingSessionDetail = Field(default_factory=BlockingSessionDetail)
    blocked_session_count: int = 0
    max_blocked_wait_seconds: int | None = None
    blocker_classification: BlockerClassification = "unknown"
    object_owner: str | None = None
    object_name: str | None = None
    object_type: str | None = None
    evidence_complete: bool = False
    notes: list[str] = Field(default_factory=list)


class WaitEventRow(BaseModel):
    event: str
    total_waits: int | None = None
    time_waited_s: float | None = None
    wait_class: str | None = None


class WaitClassSummary(BaseModel):
    wait_class: str
    session_count: int


class TopSqlRow(BaseModel):
    sql_id: str
    plan_hash_value: int | None = None
    parsing_schema_name: str | None = None
    username: str | None = None
    module: str | None = None
    program: str | None = None
    machine: str | None = None
    elapsed_s: float | None = None
    cpu_s: float | None = None
    ela_per_exec_s: float | None = None
    cpu_per_exec_s: float | None = None
    buffer_gets: int | None = None
    buffer_gets_per_exec: float | None = None
    disk_reads: int | None = None
    disk_reads_per_exec: float | None = None
    executions: int | None = None
    rows_processed: int | None = None
    rows_processed_per_exec: float | None = None
    last_active_time: str | None = None
    sql_classification: str | None = None
    workload_interpretation: str | None = None
    sql_text: str | None = None


class TablespaceUsageRow(BaseModel):
    tablespace_name: str
    used_pct: float
    used_mb: float | None = None
    free_mb: float | None = None
    total_mb: float | None = None
    contents: str | None = None
    bigfile: str | None = None


class TempUsageRow(BaseModel):
    username: str | None = None
    sql_id: str | None = None
    segtype: str | None = None
    mb_used: float | None = None
    tablespace: str | None = None


class OraErrorRow(BaseModel):
    message: str
    source: str = "alert_log"
    matched_pattern: str | None = None
    count: int = 1


class ListenerErrorRow(BaseModel):
    message: str
    source: str = "listener"
    count: int = 1


class SessionProcessCorrelationRow(BaseModel):
    os_pid: str | None = None
    spid: str | None = None
    inst_id: int | None = None
    sid: int | None = None
    serial_num: int | None = None
    username: str | None = None
    status: str | None = None
    sql_id: str | None = None
    event: str | None = None
    wait_class: str | None = None
    module: str | None = None
    program: str | None = None
    machine: str | None = None
    osuser: str | None = None
    pga_used_mb: float | None = None
    pga_alloc_mb: float | None = None
    temp_used_mb: float | None = None
    logon_time: str | None = None


class HotspotProcessRow(BaseModel):
    os_pid: str | None = None
    spid: str | None = None
    sid: int | None = None
    serial_num: int | None = None
    inst_id: int | None = None
    username: str | None = None
    status: str | None = None
    sql_id: str | None = None
    event: str | None = None
    wait_class: str | None = None
    module: str | None = None
    program: str | None = None
    machine: str | None = None
    osuser: str | None = None
    cpu_pct: float | None = None
    memory_pct: float | None = None
    rss_mb: float | None = None
    pga_used_mb: float | None = None
    pga_alloc_mb: float | None = None
    temp_used_mb: float | None = None
    process_group: Literal[
        "oracle_fg",
        "oracle_bg",
        "oracle_foreground",
        "oracle_background",
        "non_oracle",
        "unknown",
    ] = "unknown"


class OracleHotspotCandidate(BaseModel):
    sql_id: str | None = None
    parsing_schema_name: str | None = None
    username: str | None = None
    module: str | None = None
    program: str | None = None
    machine: str | None = None
    osuser: str | None = None
    status: str | None = None
    event: str | None = None
    wait_class: str | None = None
    inst_id: int | None = None
    sid: int | None = None
    serial_num: int | None = None
    sql_classification: str | None = None
    workload_interpretation: str | None = None
    cpu_s: float | None = None
    cpu_per_exec_s: float | None = None
    elapsed_s: float | None = None
    ela_per_exec_s: float | None = None
    pga_used_mb: float | None = None
    pga_alloc_mb: float | None = None
    temp_used_mb: float | None = None
    process_group: Literal[
        "oracle_fg",
        "oracle_bg",
        "oracle_foreground",
        "oracle_background",
        "non_oracle",
        "unknown",
    ] | None = None
    source_metric: Literal["cpu", "memory", "mixed"] | None = None
    source: str = "top_sql_by_cpu"


class HotspotCorrelationSummary(BaseModel):
    attempted_count: int = 0
    correlation_success_count: int = 0
    hotspot_correlation_success: str = "0/0"
    correlation_ratio: float = 0.0
    correlation_confidence: Literal["high", "medium", "low", "none"] = "none"
    direct_oracle_mapping_found: bool = False
    oracle_evidence_available: bool = False
    correlation_incomplete: bool = False
    top_oracle_candidate_sql_ids: list[str] = Field(default_factory=list)
    oracle_cpu_candidate_sql_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class TablespaceAllocationAnomaly(BaseModel):
    tablespace_allocation_failure_with_low_pct: bool = False
    error_code: str | None = None
    tablespace_name: str | None = None
    highest_used_pct: float | None = None
    interpretation: str = ""
    evidence: list[str] = Field(default_factory=list)


class BlockingInterpretationNote(BaseModel):
    lock_wait_observed: bool = False
    active_blocker_present: bool = False
    note: str = ""
    evidence: list[str] = Field(default_factory=list)


class HostProcessRow(BaseModel):
    pid: str | None = None
    spid: str | None = None
    cpu_pct: float | None = None
    memory_pct: float | None = None
    rss_mb: float | None = None
    vsz_mb: float | None = None
    swap_mb: float | None = None
    command: str | None = None
    process_name: str | None = None
    process_group: Literal[
        "oracle_fg",
        "oracle_bg",
        "oracle_foreground",
        "oracle_background",
        "non_oracle",
        "unknown",
    ] = "unknown"
    oracle_process_type_guess: str | None = None
    session_correlations: list[SessionProcessCorrelationRow] = Field(default_factory=list)


class CpuHotspotSection(BaseModel):
    triggered: bool = False
    threshold_pct: float = 70.0
    container_threshold_pct: float = 70.0
    host_cpu_pct: float | None = None
    container_cpu_pct: float | None = None
    top_n: int = 5
    top_processes: list[HostProcessRow] = Field(default_factory=list)
    correlation_success_count: int = 0
    top_oracle_foreground: str | None = None
    top_oracle_background: str | None = None
    top_non_oracle: str | None = None
    correlation_confidence: Literal["high", "medium", "low", "none"] = "none"
    correlation_summary: HotspotCorrelationSummary = Field(default_factory=HotspotCorrelationSummary)
    oracle_correlated_rows: list[HotspotProcessRow] = Field(default_factory=list)
    oracle_candidate_sql: list[OracleHotspotCandidate] = Field(default_factory=list)
    interpretation: str = ""
    notes: list[str] = Field(default_factory=list)


class MemoryHotspotSection(BaseModel):
    triggered: bool = False
    threshold_pct: float = 80.0
    container_threshold_pct: float = 80.0
    host_memory_pct: float | None = None
    container_memory_pct: float | None = None
    top_n: int = 5
    top_processes: list[HostProcessRow] = Field(default_factory=list)
    correlation_success_count: int = 0
    top_oracle_foreground: str | None = None
    top_oracle_background: str | None = None
    top_non_oracle: str | None = None
    correlation_confidence: Literal["high", "medium", "low", "none"] = "none"
    correlation_summary: HotspotCorrelationSummary = Field(default_factory=HotspotCorrelationSummary)
    oracle_correlated_rows: list[HotspotProcessRow] = Field(default_factory=list)
    oracle_candidate_sql: list[OracleHotspotCandidate] = Field(default_factory=list)
    interpretation: str = ""
    notes: list[str] = Field(default_factory=list)


class HostSnapshot(BaseModel):
    cpu_pct: float | None = None
    memory_pct: float | None = None
    swap_pct: float | None = None
    load_average: str | None = None
    filesystems: list[dict[str, Any]] = Field(default_factory=list)
    top_processes: list[HostProcessRow] = Field(default_factory=list)
    docker_container: str | None = None
    docker_stats: dict[str, Any] = Field(default_factory=dict)
    top_memory_processes: list[HostProcessRow] = Field(default_factory=list)
    cpu_hotspot: CpuHotspotSection = Field(default_factory=CpuHotspotSection)
    memory_hotspot: MemoryHotspotSection = Field(default_factory=MemoryHotspotSection)
    mount_points: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class PlanEvidence(BaseModel):
    sql_id: str
    distinct_plan_hashes: list[int] = Field(default_factory=list)
    current_plan_hash: int | None = None
    plan_count: int = 0
    churn_detected: bool = False
    summary: str = ""


class SqlWaitEventRow(BaseModel):
    event: str
    wait_class: str | None = None
    samples: int = 0
    pct: float | None = None
    source: str | None = None


class SqlWaitProfile(BaseModel):
    available: bool = False
    source_used: str | None = None
    sample_count: int = 0
    top_event: str | None = None
    top_wait_class: str | None = None
    on_cpu_pct: float | None = None
    user_io_pct: float | None = None
    system_io_pct: float | None = None
    concurrency_pct: float | None = None
    cluster_pct: float | None = None
    commit_pct: float | None = None
    configuration_pct: float | None = None
    application_pct: float | None = None
    network_pct: float | None = None
    other_pct: float | None = None
    event_breakdown: list[SqlWaitEventRow] = Field(default_factory=list)
    interpretation: str = ""
    notes: list[str] = Field(default_factory=list)


class SqlClassification(BaseModel):
    classification: Literal[
        "application_sql",
        "oracle_internal_sql",
        "dictionary_sql",
        "maintenance_sql",
        "recursive_sql",
        "unknown",
    ] = "unknown"
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = "LOW"
    explanation: str = ""
    evidence: list[str] = Field(default_factory=list)


class SqlImpactSummary(BaseModel):
    executions: int | None = None
    executions_source: str | None = None
    elapsed_s_total: float | None = None
    cpu_s_total: float | None = None
    ela_per_exec_s: float | None = None
    buffer_gets_total: int | None = None
    buffer_gets_per_exec: float | None = None
    disk_reads_total: int | None = None
    disk_reads_per_exec: float | None = None
    rows_processed_total: int | None = None
    rows_processed_per_exec: float | None = None
    active_now: bool = False
    appears_in_top_sql: bool = False
    impact_summary: str = ""
    notes: list[str] = Field(default_factory=list)


class FormattedPlanSection(BaseModel):
    available: bool = False
    source_used: str | None = None
    child_number: int | None = None
    plan_hash_value: int | None = None
    format_used: str | None = None
    lines: list[str] = Field(default_factory=list)
    interpretation: str = ""
    join_types: list[str] = Field(default_factory=list)
    access_paths: list[str] = Field(default_factory=list)
    full_scan_objects: list[str] = Field(default_factory=list)
    index_access_objects: list[str] = Field(default_factory=list)
    predicate_summary: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class SqlDbaRecommendation(BaseModel):
    severity: MetricStatus | Literal["INFO"] = "INFO"
    recommendation: str = ""
    rationale: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)


class SqlIdDeepDive(BaseModel):
    sql_id: str
    sql_text: str | None = None
    current_stats: dict[str, Any] = Field(default_factory=dict)
    child_cursors: list[dict[str, Any]] = Field(default_factory=list)
    plan_lines: list[dict[str, Any]] = Field(default_factory=list)
    ash: dict[str, Any] = Field(default_factory=dict)
    awr: dict[str, Any] = Field(default_factory=dict)
    active_queries: list[dict[str, Any]] = Field(default_factory=list)
    wait_profile: SqlWaitProfile = Field(default_factory=SqlWaitProfile)
    classification: SqlClassification = Field(default_factory=SqlClassification)
    impact_summary: SqlImpactSummary = Field(default_factory=SqlImpactSummary)
    execution_plan: FormattedPlanSection = Field(default_factory=FormattedPlanSection)
    lock_analysis: dict[str, Any] = Field(default_factory=dict)
    plan_analysis: dict[str, Any] = Field(default_factory=dict)
    history_analysis: dict[str, Any] = Field(default_factory=dict)
    risk_summary: dict[str, Any] = Field(default_factory=dict)
    dba_recommendation: SqlDbaRecommendation = Field(default_factory=SqlDbaRecommendation)
    notes: list[str] = Field(default_factory=list)


class HealthIssue(BaseModel):
    category: str
    title: str
    severity: MetricStatus
    description: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str = ""


class ModuleHealthSummary(BaseModel):
    module_name: str
    status: MetricStatus
    headline: str
    findings: list[str] = Field(default_factory=list)


class HealthCheckSection(BaseModel):
    name: str
    status: MetricStatus | Literal["INFO"] = "INFO"
    summary: str = ""
    rows: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ActionableHealthItem(BaseModel):
    category: str
    title: str
    severity: MetricStatus
    detail: str = ""
    recommendation: str = ""
    evidence: list[str] = Field(default_factory=list)


class MetricTrendSummary(BaseModel):
    metric_name: str
    values: list[float] = Field(default_factory=list)
    direction: str = "flat"
    summary: str = ""
    latest_value: float | None = None
    previous_value: float | None = None
    min_value: float | None = None
    max_value: float | None = None
    sample_count: int = 0


class HistoricalRun(BaseModel):
    run_id: str
    completed_at: str
    database_name: str | None = None
    overall_status: MetricStatus | Literal["INFO"] | None = None
    trace_path: str | None = None
    summary: str = ""
    issues: list[HealthIssue] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)


class HistoryContext(BaseModel):
    recent_runs: list[HistoricalRun] = Field(default_factory=list)
    recurring_findings: list[str] = Field(default_factory=list)
    trend_summaries: list[MetricTrendSummary] = Field(default_factory=list)
    latest_run: HistoricalRun | None = None
    previous_run: HistoricalRun | None = None
    database_name: str | None = None
    trace_paths: list[str] = Field(default_factory=list)
    history_window_label: str | None = None
    latest_fingerprint: "StateFingerprint | None" = None
    previous_fingerprint: "StateFingerprint | None" = None
    state_transition: "HistoricalStateTransition | None" = None
    awr_capabilities: "AwrCapabilities | None" = None
    history_source_used: str = "raw JSONL only"
    recurrence_computation_mode: str = "raw_scan"
    index_usage_summary: str = "none"
    runs_scanned: int = 0
    index_records_scanned: int = 0
    history_index_status: str = "unknown"
    history_index_freshness: str = "unknown"
    history_index_rebuilt: bool = False
    history_index_notes: list[str] = Field(default_factory=list)


class AwrCapabilities(BaseModel):
    available: bool = False
    ash_available: bool = False
    dbid: int | None = None
    instance_count: int = 1
    rac_enabled: bool = False
    snapshot_interval_minutes: float | None = None
    retention_minutes: float | None = None
    missing_components: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AwrSnapshotWindowMapping(BaseModel):
    dbid: int | None = None
    begin_snap_id: int | None = None
    end_snap_id: int | None = None
    matched_snap_id: int | None = None
    begin_time: str | None = None
    end_time: str | None = None
    matched_begin_time: str | None = None
    matched_end_time: str | None = None
    instance_count: int = 0
    instance_rows_found: int = 0
    mapping_quality: Literal["HIGH", "MEDIUM", "LOW", "NONE"] = "NONE"
    notes: list[str] = Field(default_factory=list)


class AwrRunPairWindowMapping(BaseModel):
    previous: AwrSnapshotWindowMapping = Field(default_factory=AwrSnapshotWindowMapping)
    current: AwrSnapshotWindowMapping = Field(default_factory=AwrSnapshotWindowMapping)
    comparability_score: float = 0.0
    confidence: ReviewConfidence = "LOW"
    notes: list[str] = Field(default_factory=list)
    debug: dict[str, Any] = Field(default_factory=dict)


class AwrMetricDiff(BaseModel):
    metric_name: str
    previous: float | None = None
    current: float | None = None
    delta: float | None = None
    pct_change: float | None = None
    significance: Literal["LOW", "MEDIUM", "HIGH"] = "LOW"
    interpretation: str = ""


class AwrMetricDelta(BaseModel):
    metric_name: str
    previous_value: float | None = None
    current_value: float | None = None
    delta_value: float | None = None
    percent_delta: float | None = None
    significance: Literal["LOW", "MEDIUM", "HIGH"] = "LOW"
    interpretation: str = ""


class AwrWaitClassShift(BaseModel):
    top_foreground_events_previous: list[dict[str, Any]] = Field(default_factory=list)
    top_foreground_events_current: list[dict[str, Any]] = Field(default_factory=list)
    wait_classes_previous: list[dict[str, Any]] = Field(default_factory=list)
    wait_classes_current: list[dict[str, Any]] = Field(default_factory=list)
    db_cpu_pct_previous: float | None = None
    db_cpu_pct_current: float | None = None
    dominant_wait_class_previous: str | None = None
    dominant_wait_class_current: str | None = None
    wait_class_shift_flag: bool = False
    cpu_to_io_shift: bool = False
    cpu_to_concurrency_shift: bool = False
    lock_contention_flag: bool = False
    scheduler_pressure_flag: bool = False
    previous_top_event: str | None = None
    current_top_event: str | None = None
    interpretation: str = ""


class AwrWaitShiftSummary(BaseModel):
    previous_dominant_wait_class: str | None = None
    current_dominant_wait_class: str | None = None
    previous_top_event: str | None = None
    current_top_event: str | None = None
    wait_class_shift_flag: bool = False
    cpu_to_io_shift: bool = False
    cpu_to_concurrency_shift: bool = False
    interpretation: str = ""


class AwrTimeModelState(BaseModel):
    metrics: list[AwrMetricDiff] = Field(default_factory=list)
    sql_elapsed_spike_flag: bool = False
    parse_regression_flag: bool = False
    cpu_growth_flag: bool = False


class AwrHostCpuState(BaseModel):
    metrics: list[AwrMetricDiff] = Field(default_factory=list)
    cpu_pressure_flag: bool = False
    resource_manager_wait_flag: bool = False
    host_iowait_spike: bool = False


class AwrIoProfileState(BaseModel):
    metrics: list[AwrMetricDiff] = Field(default_factory=list)
    io_pressure_flag: bool = False
    redo_spike_flag: bool = False
    buffer_cache_bypass: bool = False


class AwrMemoryState(BaseModel):
    metrics: list[AwrMetricDiff] = Field(default_factory=list)
    memory_pressure_flag: bool = False
    shared_pool_pressure: bool = False
    cursor_reuse_change: bool = False


class AwrSqlChangeIntelligence(BaseModel):
    top_sql_by_elapsed_previous: list[dict[str, Any]] = Field(default_factory=list)
    top_sql_by_elapsed_current: list[dict[str, Any]] = Field(default_factory=list)
    top_sql_by_cpu_previous: list[dict[str, Any]] = Field(default_factory=list)
    top_sql_by_cpu_current: list[dict[str, Any]] = Field(default_factory=list)
    dominant_sql_id_previous: str | None = None
    dominant_sql_id_current: str | None = None
    dominant_sql_schema_previous: str | None = None
    dominant_sql_schema_current: str | None = None
    dominant_sql_module_previous: str | None = None
    dominant_sql_module_current: str | None = None
    dominant_sql_class_previous: str | None = None
    dominant_sql_class_current: str | None = None
    dominant_sql_changed_flag: bool = False
    sql_regression_flag: bool = False
    sql_regression_severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "NONE"
    plan_hash_changed_flag: bool = False
    elapsed_per_exec_spike: bool = False
    cpu_per_exec_spike: bool = False
    interpretation: str = ""


class AwrSqlChangeSummary(BaseModel):
    dominant_sql_id_previous: str | None = None
    dominant_sql_id_current: str | None = None
    dominant_sql_schema_previous: str | None = None
    dominant_sql_schema_current: str | None = None
    dominant_sql_module_previous: str | None = None
    dominant_sql_module_current: str | None = None
    dominant_sql_class_previous: str | None = None
    dominant_sql_class_current: str | None = None
    sql_regression_flag: bool = False
    sql_regression_severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "NONE"
    plan_hash_changed_flag: bool = False
    elapsed_per_exec_spike: bool = False
    cpu_per_exec_spike: bool = False
    interpretation: str = ""


class AwrWorkloadInterpretation(BaseModel):
    summary: str = ""
    material_change_detected: bool = False
    low_significance_majority: bool = False
    high_or_medium_metric_count: int = 0
    low_metric_count: int = 0
    unavailable_metric_count: int = 0


class AwrAshState(BaseModel):
    source: str | None = None
    aas_proxy_previous: float | None = None
    aas_proxy_current: float | None = None
    top_sql_previous: list[dict[str, Any]] = Field(default_factory=list)
    top_sql_current: list[dict[str, Any]] = Field(default_factory=list)
    wait_profile_previous: list[dict[str, Any]] = Field(default_factory=list)
    wait_profile_current: list[dict[str, Any]] = Field(default_factory=list)
    blocking_previous: list[dict[str, Any]] = Field(default_factory=list)
    blocking_current: list[dict[str, Any]] = Field(default_factory=list)


class AwrSnapshotQuality(BaseModel):
    coverage_quality: Literal["HIGH", "MEDIUM", "LOW", "NONE"] = "NONE"
    comparability_score: float = 0.0
    confidence: ReviewConfidence = "LOW"
    notes: list[str] = Field(default_factory=list)


class AwrReportTextSummary(BaseModel):
    available: bool = False
    source: str = ""
    dbid: int | None = None
    instance_number: int | None = None
    begin_snap_id: int | None = None
    end_snap_id: int | None = None
    line_count: int = 0
    load_profile_summary: list[str] = Field(default_factory=list)
    main_bottlenecks: list[str] = Field(default_factory=list)
    sql_contributors: list[str] = Field(default_factory=list)
    recommended_follow_up: list[str] = Field(default_factory=list)
    interpretation_summary: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AwrStateDiff(BaseModel):
    available: bool = False
    awr_mode: Literal["comparison", "single_window_interpretation"] = "comparison"
    capabilities: AwrCapabilities | None = None
    window_mapping: AwrRunPairWindowMapping = Field(default_factory=AwrRunPairWindowMapping)
    load_profile: list[AwrMetricDiff] = Field(default_factory=list)
    workload_metrics: list[AwrMetricDelta] = Field(default_factory=list)
    workload_interpretation: AwrWorkloadInterpretation = Field(default_factory=AwrWorkloadInterpretation)
    wait_class_shift: AwrWaitClassShift = Field(default_factory=AwrWaitClassShift)
    wait_shift_summary: AwrWaitShiftSummary = Field(default_factory=AwrWaitShiftSummary)
    time_model: AwrTimeModelState = Field(default_factory=AwrTimeModelState)
    host_cpu_state: AwrHostCpuState = Field(default_factory=AwrHostCpuState)
    io_profile: AwrIoProfileState = Field(default_factory=AwrIoProfileState)
    memory_state: AwrMemoryState = Field(default_factory=AwrMemoryState)
    sql_change: AwrSqlChangeIntelligence = Field(default_factory=AwrSqlChangeIntelligence)
    sql_change_summary: AwrSqlChangeSummary = Field(default_factory=AwrSqlChangeSummary)
    ash_state: AwrAshState = Field(default_factory=AwrAshState)
    snapshot_quality: AwrSnapshotQuality = Field(default_factory=AwrSnapshotQuality)
    awr_report_text_summary: AwrReportTextSummary = Field(default_factory=AwrReportTextSummary)
    notes: list[str] = Field(default_factory=list)


class StateFingerprint(BaseModel):
    overall_status: str | None = None
    blocking_present: bool = False
    alert_errors_present: bool = False
    dominant_wait_class: str | None = None
    dominant_sql_id: str | None = None
    db_time_bucket: str = "unknown"
    cpu_bucket: str = "unknown"
    io_bucket: str = "unknown"
    tablespace_pressure: str = "normal"
    memory_pressure: str = "normal"
    plan_churn_present: bool = False
    stale_stats_present: bool = False


class TransitionIssueClassification(BaseModel):
    category: str
    title: str
    transition: Literal["new", "worsened", "persistent", "resolved", "improved", "intermittent"]
    previous_severity: str | None = None
    current_severity: str | None = None
    notes: list[str] = Field(default_factory=list)


class TransitionDriver(BaseModel):
    name: str
    driver_type: Literal[
        "blocking",
        "long_transaction",
        "alert",
        "ora_error_emergence",
        "sql",
        "sql_regression",
        "wait",
        "wait_class_shift",
        "cpu",
        "io",
        "memory",
        "resource_pressure",
        "plan",
        "plan_instability",
        "transaction",
        "tablespace_pressure",
        "stale_stats",
        "stale_stats_noise",
        "persistent_background_noise",
        "other",
    ] = "other"
    rank: Literal["primary", "secondary"] = "secondary"
    strength: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class HistoricalTransitionDriver(BaseModel):
    name: str
    category: str
    score: float = 0.0
    rank: Literal["primary", "secondary", "suppressed"] = "secondary"
    evidence: list[str] = Field(default_factory=list)
    transition_relevance_score: float = 0.0
    recurrence_count: int = 0
    persistence_score: float = 0.0
    recency_score: float = 0.0
    severity_overlap_score: float = 0.0


class HistoricalRecoveryDriver(BaseModel):
    title: str
    category: str
    score: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class HistoricalResidualDriver(BaseModel):
    title: str
    category: str
    score: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    follow_up_reason: str = ""


class HistoricalTransitionOutcome(BaseModel):
    transition_outcome: Literal[
        "recovered",
        "improved",
        "worsened",
        "unchanged",
        "persisted_but_worsened",
        "persisted_but_improved",
    ] = "unchanged"
    recovery_detected: bool = False
    residual_risk_present: bool = False


class AwrFallbackInfo(BaseModel):
    fallback_mode: str = "none"
    awr_user_message: str = ""
    awr_debug_message: str = ""


class HistoricalSectionNaming(BaseModel):
    primary_driver_section_title: str = "Recovery Drivers"
    secondary_driver_section_title: str = "Residual Warning Drivers"


class MetricDelta(BaseModel):
    metric_name: str
    previous_value: float | None = None
    current_value: float | None = None
    absolute_delta: float | None = None
    percent_delta: float | None = None
    state_label: Literal[
        "newly_present",
        "no_longer_present",
        "increased",
        "decreased",
        "unchanged",
        "persistent_nonzero",
        "persistent_high",
        "persistent_low",
        "worsened",
        "improved",
        "missing_data",
    ] = "missing_data"
    significance: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    interpretation: str = ""


class HistoricalIssueState(BaseModel):
    category: str
    title: str
    previous_severity: str | None = None
    current_severity: str | None = None
    state_label: Literal[
        "newly_present",
        "no_longer_present",
        "increased",
        "decreased",
        "unchanged",
        "persistent_nonzero",
        "persistent_high",
        "persistent_low",
        "worsened",
        "improved",
        "missing_data",
    ] = "missing_data"
    impact_changed: bool = False
    interpretation: str = ""


class HistoricalConfidence(BaseModel):
    confidence_level: ReviewConfidence = "LOW"
    confidence_reason: str = ""
    coverage_quality: Literal["HIGH", "MEDIUM", "LOW", "NONE"] = "NONE"
    history_source_used: str = "JSONL only"
    fallback_mode: str = "none"
    fallback_reason: str = ""
    notes: list[str] = Field(default_factory=list)


class HistoricalComparisonWindow(BaseModel):
    window_start: str | None = None
    window_end: str | None = None
    window_duration_minutes: float | None = None
    window_overlap_adjusted: bool = False
    window_confidence: ReviewConfidence = "LOW"
    notes: list[str] = Field(default_factory=list)


class HistoricalEventTimelineEntry(BaseModel):
    at: str
    summary: str
    change_notes: list[str] = Field(default_factory=list)
    source: str = "JSONL"
    impact_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"


class LearningFeatureVector(BaseModel):
    status_delta: float = 0.0
    state_persisted_but_worsened_flag: bool = False
    persistent_issue_with_higher_impact_flag: bool = False
    blocking_delta: float = 0.0
    blocking_persistent_flag: bool = False
    alert_delta: float = 0.0
    new_alert_flag: bool = False
    sql_elapsed_delta: float = 0.0
    sql_cpu_delta: float = 0.0
    sql_regression_flag: bool = False
    sql_regression_severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "NONE"
    sql_regression_evidence: list[str] = Field(default_factory=list)
    incident_driver_sql: str | None = None
    sql_amplified_by_blocking_flag: bool = False
    dominant_sql_changed_flag: bool = False
    dominant_sql_persistent_flag: bool = False
    wait_class_shift_flag: bool = False
    cpu_to_io_shift_flag: bool = False
    plan_change_flag: bool = False
    memory_pressure_flag: bool = False
    blocking_amplification_flag: bool = False
    transaction_anomaly_flag: bool = False
    incident_driver_category: str | None = None
    transition_confidence_reason: str = ""
    recovery_detected: bool = False
    residual_risk_present: bool = False
    recovery_driver_category: str | None = None
    residual_driver_category: str | None = None
    transition_outcome: Literal[
        "recovered",
        "improved",
        "worsened",
        "unchanged",
        "persisted_but_worsened",
        "persisted_but_improved",
    ] = "unchanged"


class HistoricalLearningFeatures(LearningFeatureVector):
    pass


class HistoricalTransitionSummary(BaseModel):
    status_transition: str = "unknown"
    primary_drivers: list[HistoricalTransitionDriver] = Field(default_factory=list)
    secondary_drivers: list[HistoricalTransitionDriver] = Field(default_factory=list)
    recovery_drivers: list[HistoricalRecoveryDriver] = Field(default_factory=list)
    residual_warning_drivers: list[HistoricalResidualDriver] = Field(default_factory=list)
    transition_outcome: HistoricalTransitionOutcome = Field(default_factory=HistoricalTransitionOutcome)
    suppressed_background_signals: list[HistoricalTransitionDriver] = Field(default_factory=list)
    issue_states: list[HistoricalIssueState] = Field(default_factory=list)
    metric_deltas: list[MetricDelta] = Field(default_factory=list)
    event_timeline: list[HistoricalEventTimelineEntry] = Field(default_factory=list)
    learning_features: HistoricalLearningFeatures = Field(default_factory=HistoricalLearningFeatures)
    confidence: HistoricalConfidence = Field(default_factory=HistoricalConfidence)
    comparison_window: HistoricalComparisonWindow | None = None


class HistoricalStateTransition(BaseModel):
    available: bool = False
    previous_run_id: str | None = None
    current_run_id: str | None = None
    previous_status: str | None = None
    current_status: str | None = None
    status_transition: str = "unknown"
    transition_outcome: Literal[
        "recovered",
        "improved",
        "worsened",
        "unchanged",
        "persisted_but_worsened",
        "persisted_but_improved",
    ] = "unchanged"
    recovery_detected: bool = False
    residual_risk_present: bool = False
    issue_transitions: list[TransitionIssueClassification] = Field(default_factory=list)
    recovery_drivers: list[HistoricalRecoveryDriver] = Field(default_factory=list)
    residual_warning_drivers: list[HistoricalResidualDriver] = Field(default_factory=list)
    primary_drivers: list[TransitionDriver] = Field(default_factory=list)
    secondary_drivers: list[TransitionDriver] = Field(default_factory=list)
    recurring_patterns_ranked: list[str] = Field(default_factory=list)
    event_timeline: list[str] = Field(default_factory=list)
    learning_features: LearningFeatureVector = Field(default_factory=LearningFeatureVector)
    confidence: ReviewConfidence = "LOW"
    coverage_notes: list[str] = Field(default_factory=list)
    awr_state_diff: AwrStateDiff | None = None
    primary_transition_drivers: list[HistoricalTransitionDriver] = Field(default_factory=list)
    secondary_transition_drivers: list[HistoricalTransitionDriver] = Field(default_factory=list)
    suppressed_background_signals: list[HistoricalTransitionDriver] = Field(default_factory=list)
    metric_deltas: list[MetricDelta] = Field(default_factory=list)
    historical_issue_states: list[HistoricalIssueState] = Field(default_factory=list)
    event_timeline_entries: list[HistoricalEventTimelineEntry] = Field(default_factory=list)
    historical_learning_features: HistoricalLearningFeatures = Field(default_factory=HistoricalLearningFeatures)
    historical_confidence: HistoricalConfidence = Field(default_factory=HistoricalConfidence)
    comparison_window: HistoricalComparisonWindow | None = None
    history_source_summary: str = ""
    awr_source_summary: str = ""
    fallback_summary: str = ""
    section_naming: HistoricalSectionNaming = Field(default_factory=HistoricalSectionNaming)
    awr_workload_interpretation: str = ""
    snapshot_mapping_summary: str = ""
    awr_fallback_info: AwrFallbackInfo | None = None
    summary: HistoricalTransitionSummary | None = None


class HealthSnapshot(BaseModel):
    generated_at: str
    instance_info: InstanceInfo = Field(default_factory=InstanceInfo)
    session_summary: SessionSummary = Field(default_factory=SessionSummary)
    active_sessions: list[SessionRow] = Field(default_factory=list)
    blocking_chains: list[BlockingChain] = Field(default_factory=list)
    top_waits: list[WaitEventRow] = Field(default_factory=list)
    wait_classes: list[WaitClassSummary] = Field(default_factory=list)
    top_sql_by_elapsed: list[TopSqlRow] = Field(default_factory=list)
    top_sql_by_cpu: list[TopSqlRow] = Field(default_factory=list)
    tablespaces: list[TablespaceUsageRow] = Field(default_factory=list)
    temp_usage: list[TempUsageRow] = Field(default_factory=list)
    ora_errors: list[OraErrorRow] = Field(default_factory=list)
    listener_errors: list[ListenerErrorRow] = Field(default_factory=list)
    init_parameters: list[dict[str, Any]] = Field(default_factory=list)
    scheduler_jobs: list[dict[str, Any]] = Field(default_factory=list)
    host_snapshot: HostSnapshot | None = None
    plan_evidence: list[PlanEvidence] = Field(default_factory=list)
    module_summaries: list[ModuleHealthSummary] = Field(default_factory=list)
    health_sections: list[HealthCheckSection] = Field(default_factory=list)
    actionable_items: list[ActionableHealthItem] = Field(default_factory=list)
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    issues: list[HealthIssue] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class JsonlTraceReference(BaseModel):
    path: str
    file_name: str
    recorded_at: str
    database_name: str
    overall_status: MetricStatus | Literal["INFO"] = "INFO"


class JsonlRunSummary(BaseModel):
    trace: JsonlTraceReference | None = None
    run_id: str
    completed_at: str
    database_name: str | None = None
    overall_status: MetricStatus | Literal["INFO"] = "INFO"
    summary: str = ""
    metrics: dict[str, Any] = Field(default_factory=dict)
    issues: list[HealthIssue] = Field(default_factory=list)
    current_metrics: list[str] = Field(default_factory=list)
    current_issues: list[str] = Field(default_factory=list)
    current_top_sql_summary: list[str] = Field(default_factory=list)
    current_host_summary: list[str] = Field(default_factory=list)
    current_storage_summary: list[str] = Field(default_factory=list)
    current_error_summary: list[str] = Field(default_factory=list)


class TraceHealthRunRecord(BaseModel):
    trace_version: str = "1"
    run_id: str
    recorded_at: str
    completed_at: str
    database_name: str
    database_host: str | None = None
    instance_name: str | None = None
    db_unique_name: str | None = None
    database_role: str | None = None
    open_mode: str | None = None
    trace_path: str | None = None
    overall_status: MetricStatus | Literal["INFO"] = "INFO"
    summary: str = ""
    metrics: dict[str, Any] = Field(default_factory=dict)
    issues: list[HealthIssue] = Field(default_factory=list)
    actionable_items: list[ActionableHealthItem] = Field(default_factory=list)
    health_sections: list[HealthCheckSection] = Field(default_factory=list)
    snapshot: HealthSnapshot | None = None
    report_markdown: str = ""
    history_context_summary: dict[str, Any] = Field(default_factory=dict)


class TraceEvidenceChunk(BaseModel):
    chunk_id: str
    trace_path: str | None = None
    recorded_at: str
    database_name: str
    run_overall_status: MetricStatus | Literal["INFO"] = "INFO"
    category: str
    title: str
    summary: str = ""
    facts: list[str] = Field(default_factory=list)
    severity: MetricStatus | Literal["INFO"] = "INFO"
    metric_names: list[str] = Field(default_factory=list)
    sql_ids: list[str] = Field(default_factory=list)


class RecurringIssueIndexRecord(BaseModel):
    fingerprint: str
    database_name: str
    category: str
    title: str
    severity: MetricStatus | Literal["INFO"] = "INFO"
    first_seen: str
    last_seen: str
    run_count: int = 0
    unhealthy_run_count: int = 0
    sample_evidence: list[str] = Field(default_factory=list)
    latest_summary: str | None = None
    trace_paths: list[str] = Field(default_factory=list)


class OracleDatabaseBehaviorProfile(BaseModel):
    database_name: str
    sampled_run_count: int = 0
    healthy_run_count: int = 0
    warning_run_count: int = 0
    critical_run_count: int = 0
    latest_recorded_at: str | None = None
    metric_baselines: dict[str, dict[str, float | int | None]] = Field(default_factory=dict)
    recurring_issue_summary: list[str] = Field(default_factory=list)
    sql_behavior_summary: list[str] = Field(default_factory=list)
    host_behavior_summary: list[str] = Field(default_factory=list)
    storage_behavior_summary: list[str] = Field(default_factory=list)


class OraclePlannerMemoryRecord(BaseModel):
    generated_at: str
    database_name: str
    source_trace_count: int = 0
    latest_trace_recorded_at: str | None = None
    database_behavior_profile: OracleDatabaseBehaviorProfile


class PlannerResponse(BaseModel):
    mode: PlannerResponseMode = "full_health_report"
    summary: str
    body_markdown: str
    issues: list[HealthIssue] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    remediation_proposal: "RemediationProposal | None" = None
    supporting_data: dict[str, Any] = Field(default_factory=dict)


class InvestigationStep(BaseModel):
    step_number: int
    goal: str
    sql: str
    result_preview: str
    row_count: int = 0
    status: str = "success"
    result_columns: list[str] = Field(default_factory=list)
    result_rows: list[dict[str, Any]] = Field(default_factory=list)
    result_truncated: bool = False


class InvestigationReport(BaseModel):
    problem_statement: str
    summary: str
    likely_cause: str
    evidence: list[str] = Field(default_factory=list)
    recommended_next_actions: list[str] = Field(default_factory=list)
    steps: list[InvestigationStep] = Field(default_factory=list)


class PostActionValidationPlan(BaseModel):
    checks: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    rollback_risks: list[str] = Field(default_factory=list)


class BlockingActionProposal(BaseModel):
    action_title: str = ""
    blocker_identity: dict[str, Any] = Field(default_factory=dict)
    blocked_session_count: int = 0
    max_blocked_wait_seconds: int | None = None
    blocker_classification: BlockerClassification = "unknown"
    reason_for_action: str = ""
    risk_summary: list[str] = Field(default_factory=list)
    safer_alternatives: list[str] = Field(default_factory=list)
    post_action_validation_plan: PostActionValidationPlan = Field(default_factory=PostActionValidationPlan)
    execution_sql: str | None = None
    evidence: BlockingChainDetail | None = None
    confidence: ReviewConfidence = "LOW"


class RemediationProposal(BaseModel):
    action_type: str
    title: str
    description: str
    rationale: str
    target: dict[str, Any] = Field(default_factory=dict)
    sql: str | None = None
    risks: list[str] = Field(default_factory=list)
    safer_alternatives: list[str] = Field(default_factory=list)
    validation_plan: list[str] = Field(default_factory=list)
    post_action_validation: PostActionValidationPlan | None = None
    reason_for_action: str = ""
    execution_sql: str | None = None
    blocking_action: BlockingActionProposal | None = None
    confidence: ReviewConfidence = "MEDIUM"


class GuardrailCheckResult(BaseModel):
    check: str
    passed: bool
    message: str


class BlockingActionReview(BaseModel):
    status: RemediationReviewerStatus = "pending"
    confidence: ReviewConfidence = "LOW"
    rationale: str = ""
    guardrail_checks_passed: list[str] = Field(default_factory=list)
    guardrail_checks_failed: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class RemediationReview(BaseModel):
    status: RemediationReviewerStatus = "pending"
    confidence: ReviewConfidence = "LOW"
    rationale: str = ""
    reviewer_notes: list[str] = Field(default_factory=list)
    guardrail_checks_passed: list[str] = Field(default_factory=list)
    guardrail_checks_failed: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    blocking_review: BlockingActionReview | None = None


class RemediationExecution(BaseModel):
    status: RemediationExecutionStatus = "not_started"
    message: str = ""
    executed_at: str | None = None
    validation_summary: str | None = None


class RemediationRecord(BaseModel):
    created_at: str
    proposal: RemediationProposal
    review: RemediationReview
    execution: RemediationExecution


class SQLValidationResult(BaseModel):
    ok: bool
    reason: str = ""
    normalized_sql: str | None = None


class SQLExecutionResult(BaseModel):
    status: Literal["success", "error"]
    elapsed_ms: int
    columns: list[str] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = 0
    truncated: bool = False
    error: str | None = None


PlannerResponse.model_rebuild()
