---
component_id: 1.4.1
component_name: Historical Query Orchestrator
---

# Historical Query Orchestrator

## Component Description

Acts as the primary interface for the subsystem, translating high-level diagnostic questions into specific data retrieval strategies. It resolves time windows and routes queries to the appropriate metric families or historical snapshots.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/history/service.py (lines 16-28)
```
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
```


## Source Files:

- `history/metric_catalog.py`

