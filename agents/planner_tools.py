from __future__ import annotations


def build_planner_tool_schemas() -> list[dict]:
    return [
        {"name": "run_oracle_health_check", "description": "Collect current Oracle health snapshot."},
        {"name": "compare_recent_runs", "description": "Compare current signals with recent JSONL history."},
        {"name": "analyze_sql_id", "description": "Deep dive a SQL_ID."},
        {"name": "get_running_sessions", "description": "Return active Oracle sessions."},
    ]
