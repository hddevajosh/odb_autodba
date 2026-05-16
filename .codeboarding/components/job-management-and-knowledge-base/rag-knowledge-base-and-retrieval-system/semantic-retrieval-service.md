---
component_id: 5.4.3
component_name: Semantic Retrieval Service
---

# Semantic Retrieval Service

## Component Description

Provides the query interface for the AI Orchestrator. It performs similarity searches across the indices to find relevant evidence, past investigation hits, and recurring patterns to ground the agent's current plan.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/rag/retriever.py (lines 77-106)
```
def retrieve_trace_chunks(
    *,
    query: str,
    limit: int = 6,
    database_name: str | None = None,
    requested_domain: str | None = None,
    time_scope: Any = None,
    db_key: str | None = None,
) -> list[TraceEvidenceChunk]:
    chunks = read_trace_evidence_chunks(
        database_name=database_name,
        completed_after=getattr(time_scope, "completed_after", None),
        completed_before=getattr(time_scope, "completed_before", None),
        limit=None,
        db_key=db_key,
    )
    if not chunks:
        return []
    terms = _terms(query)
    domain = requested_domain or _infer_domain(query)
    aliases = DOMAIN_ALIASES.get(domain or "", {domain or ""}) if domain else set()
    scored: list[tuple[int, TraceEvidenceChunk]] = []
    for chunk in chunks:
        score = _score_chunk(chunk, terms=terms, aliases=aliases)
        if domain and score <= 0 and chunk.category not in aliases:
            continue
        if score > 0 or not domain:
            scored.append((score, chunk))
    scored.sort(key=lambda item: (item[0], item[1].recorded_at), reverse=True)
    return [chunk for _, chunk in scored[:limit]]
```

### /home/neha/projects/agents/odb_autodba/rag/retriever.py (lines 109-121)
```
def retrieve_recurring_issue_hits(
    limit: int = 5,
    *,
    database_name: str | None = None,
    requested_domain: str | None = None,
    db_key: str | None = None,
) -> list[str]:
    return [_format_recurring(record) for record in retrieve_recurring_issue_records(
        limit=limit,
        database_name=database_name,
        requested_domain=requested_domain,
        db_key=db_key,
    )]
```


## Source Files:

- `rag/retriever.py`

