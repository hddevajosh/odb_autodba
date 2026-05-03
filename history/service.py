from __future__ import annotations

from odb_autodba.history.jsonl_service import JsonlHistoryService


class HistoryService:
    def __init__(self) -> None:
        self.jsonl = JsonlHistoryService()

    def load_recent_runs(self, limit: int = 10, db_key: str | None = None):
        return self.jsonl.load_recent_runs(limit, db_key=db_key)

    def compare_recent_runs(self, limit: int = 5, database_name: str | None = None, time_scope: dict | None = None, db_key: str | None = None):
        return self.jsonl.compare_recent_runs(limit=limit, database_name=database_name, time_scope=time_scope, db_key=db_key)

    def answer_history_question(
        self,
        user_query: str,
        database_name: str | None = None,
        requested_domain: str | None = None,
        db_key: str | None = None,
    ):
        return self.jsonl.answer_history_question_from_jsonl(
            user_query=user_query,
            database_name=database_name,
            requested_domain=requested_domain,
            db_key=db_key,
        )

    def route_history_metric_question(
        self,
        user_query: str,
        requested_domain: str | None = None,
    ) -> dict | None:
        return self.jsonl.route_history_metric_question(
            user_query=user_query,
            requested_domain=requested_domain,
        )

    def answer_history_question_from_index(
        self,
        *,
        user_query: str,
        database_name: str | None = None,
        requested_domain: str | None = None,
        db_key: str | None = None,
    ) -> dict | None:
        return self.jsonl.answer_history_question_from_index(
            user_query=user_query,
            database_name=database_name,
            requested_domain=requested_domain,
            db_key=db_key,
        )

    def audit_history_pipeline(
        self,
        *,
        user_query: str | None = None,
        database_name: str | None = None,
        auto_rebuild: bool = True,
        db_key: str | None = None,
    ) -> dict:
        time_scope = self.jsonl.resolve_time_scope(user_query)
        return self.jsonl.audit_history_pipeline(
            database_name=database_name,
            time_scope=time_scope,
            auto_rebuild=auto_rebuild,
            db_key=db_key,
        )

    def get_latest_state_transition(self, *, database_name: str | None = None, db_key: str | None = None):
        context = self.jsonl.compare_recent_runs(limit=10, database_name=database_name, db_key=db_key)
        return context.state_transition
