from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MetricFamilySpec:
    key: str
    title: str
    aliases: tuple[str, ...]
    fields: tuple[str, ...]


METRIC_CATALOG: tuple[MetricFamilySpec, ...] = (
    MetricFamilySpec(
        key="cpu",
        title="CPU Consumption",
        aliases=("cpu", "cpu usage", "cpu consumption", "host cpu", "server cpu"),
        fields=("host_cpu_pct", "container_cpu_pct", "top_cpu_sql_cpu_s"),
    ),
    MetricFamilySpec(
        key="memory",
        title="Memory Usage",
        aliases=(
            "memory",
            "memory usage",
            "memory consumption",
            "host memory",
            "server memory",
            "pga",
            "sga",
        ),
        fields=("host_memory_pct", "container_memory_pct"),
    ),
    MetricFamilySpec(
        key="blocking",
        title="Blocking Summary",
        aliases=(
            "blocking",
            "blocking lock",
            "blocking locks",
            "locks",
            "lock contention",
            "blocker",
            "blocked session",
            "blocked sessions",
            "blocking session",
            "blocking sessions",
        ),
        fields=("blocking_count", "blocking_critical_count", "blocking_warning_count"),
    ),
    MetricFamilySpec(
        key="active_sessions",
        title="Active Sessions",
        aliases=("active sessions", "active session", "sessions", "session count"),
        fields=("active_sessions", "true_active_non_idle", "active_idle_waiting", "on_cpu_sessions"),
    ),
    MetricFamilySpec(
        key="alerts",
        title="Alert / ORA-TNS Errors",
        aliases=("ora errors", "tns errors", "alert log", "errors", "ora", "tns"),
        fields=("alert_log_count", "listener_error_count"),
    ),
    MetricFamilySpec(
        key="tablespace",
        title="Tablespace Usage",
        aliases=("tablespace", "space", "storage", "disk usage"),
        fields=("hottest_tablespace_pct", "highest_tablespace_pct"),
    ),
    MetricFamilySpec(
        key="cache",
        title="Cache Hit Ratios",
        aliases=("cache hit", "buffer cache", "library cache", "dictionary cache", "cache"),
        fields=("buffer_hit_pct", "library_hit_pct", "dictionary_hit_pct"),
    ),
    MetricFamilySpec(
        key="sql_workload",
        title="SQL Workload",
        aliases=("top sql", "sql cpu", "sql elapsed", "elapsed sql", "top sql cpu", "sql workload"),
        fields=("top_cpu_sql_cpu_s", "top_elapsed_sql_elapsed_s"),
    ),
    MetricFamilySpec(
        key="plan_stats",
        title="Plan Churn / Stale Stats",
        aliases=("plan churn", "plan change", "stale stats", "statistics", "stats"),
        fields=("plan_churn_count", "stale_stats_count"),
    ),
    MetricFamilySpec(
        key="redo_fra",
        title="Redo / FRA",
        aliases=("redo", "archive", "fra"),
        fields=("redo_switch_count", "fra_pct"),
    ),
    MetricFamilySpec(
        key="data_guard",
        title="Data Guard / Standby",
        aliases=("data guard", "standby", "apply lag", "transport lag", "archive gap", "mrp", "rfs"),
        fields=(
            "standby_mode_detected",
            "mounted_physical_standby",
            "standby_apply_checked",
            "standby_lag_checked",
            "archive_gap_checked",
            "primary_style_checks_skipped_for_mounted_standby",
        ),
    ),
)


def metric_catalog_by_key() -> dict[str, MetricFamilySpec]:
    return {item.key: item for item in METRIC_CATALOG}


def supported_metric_families() -> list[str]:
    return [item.key for item in METRIC_CATALOG]
