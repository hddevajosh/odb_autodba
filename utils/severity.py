from __future__ import annotations

from odb_autodba.models.schemas import MetricStatus


def severity_rank(status: MetricStatus) -> int:
    return {"OK": 0, "WARNING": 1, "CRITICAL": 2}[status]


def severity_icon(status: MetricStatus) -> str:
    return {"OK": "🟢", "WARNING": "🟠", "CRITICAL": "🔴"}[status]


def worst_status(statuses: list[MetricStatus]) -> MetricStatus:
    return max(statuses or ["OK"], key=severity_rank)
