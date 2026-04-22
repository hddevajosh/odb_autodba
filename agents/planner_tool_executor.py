from __future__ import annotations

from odb_autodba.db.health_checks import collect_health_snapshot
from odb_autodba.db.query_deep_dive import build_sql_id_deep_dive_report
from odb_autodba.db.running_sessions import get_running_sessions_inventory
from odb_autodba.history.service import HistoryService


class PlannerToolExecutor:
    def __init__(self) -> None:
        self.history = HistoryService()

    def run(self, tool_name: str, **kwargs):
        if tool_name == "run_oracle_health_check":
            return collect_health_snapshot()
        if tool_name == "compare_recent_runs":
            return self.history.compare_recent_runs(limit=kwargs.get("limit", 5))
        if tool_name == "analyze_sql_id":
            return build_sql_id_deep_dive_report(kwargs["sql_id"])
        if tool_name == "get_running_sessions":
            return get_running_sessions_inventory()
        raise ValueError(f"Unknown tool: {tool_name}")
