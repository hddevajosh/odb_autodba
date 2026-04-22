from __future__ import annotations

import re
from typing import Any

from odb_autodba.history.jsonl_service import JsonlHistoryService
from odb_autodba.models.schemas import RecurringIssueIndexRecord, TraceEvidenceChunk
from odb_autodba.rag.trace_store import (
    read_recurring_issue_index,
    read_trace_evidence_chunks,
)


DOMAIN_ALIASES: dict[str, set[str]] = {
    "blocking": {"blocking", "lock", "locks"},
    "cpu": {"cpu", "ash", "top_sql", "top sql", "host"},
    "memory": {"memory", "pga", "sga", "swap", "host_memory"},
    "errors": {"ora", "tns", "alert", "listener", "error", "errors"},
    "storage": {"tablespace", "temp", "fra", "archive", "storage"},
    "backup": {"rman", "backup", "recovery", "fra"},
    "jobs": {"scheduler", "job", "jobs"},
    "sql": {"sql", "sql_id", "plan", "elapsed", "awr", "ash", "wait"},
    "awr": {"awr", "snapshot", "db time", "wait class", "load profile"},
    "transition": {"transition", "changed", "driver", "previous", "current", "delta", "evolution"},
    "learning": {"learning", "feature", "vector", "ml", "label"},
    "config": {"init", "spfile", "parameter", "sga", "pga", "config"},
}


def retrieve_trace_evidence(
    query: str,
    limit: int = 5,
    *,
    database_name: str | None = None,
    requested_domain: str | None = None,
) -> list[str]:
    chunks = retrieve_trace_chunks(
        query=query,
        limit=limit,
        database_name=database_name,
        requested_domain=requested_domain,
    )
    if chunks:
        return [_format_chunk(chunk) for chunk in chunks]

    history = JsonlHistoryService().load_recent_runs(limit=20, database_name=database_name)
    q = (query or "").lower()
    out: list[str] = []
    if requested_domain in {"transition", "awr", "learning"} or any(token in q for token in {"transition", "driver", "feature", "awr"}):
        context = JsonlHistoryService().compare_recent_runs(limit=20, database_name=database_name)
        if context.state_transition and context.state_transition.available:
            out.append(
                "Transition summary: "
                f"{context.state_transition.status_transition} "
                f"(confidence={context.state_transition.confidence})."
            )
            for driver in context.state_transition.primary_drivers[:3]:
                out.append(f"Primary driver: {driver.name} [{driver.driver_type}] strength={driver.strength}.")
            if context.state_transition.learning_features:
                features = context.state_transition.learning_features.model_dump(mode="json")
                compact = ", ".join(f"{k}={v}" for k, v in list(features.items())[:8])
                out.append(f"Learning features: {compact}")
            if context.state_transition.coverage_notes:
                out.append("Coverage: " + "; ".join(context.state_transition.coverage_notes[:2]))
        if out:
            return out[:limit]
    for run in history:
        if q in run.summary.lower() or any(q in issue.title.lower() for issue in run.issues):
            out.append(f"{run.completed_at}: {run.summary}")
        if len(out) >= limit:
            break
    return out


def retrieve_trace_chunks(
    *,
    query: str,
    limit: int = 6,
    database_name: str | None = None,
    requested_domain: str | None = None,
    time_scope: Any = None,
) -> list[TraceEvidenceChunk]:
    chunks = read_trace_evidence_chunks(
        database_name=database_name,
        completed_after=getattr(time_scope, "completed_after", None),
        completed_before=getattr(time_scope, "completed_before", None),
        limit=None,
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


def retrieve_recurring_issue_hits(
    limit: int = 5,
    *,
    database_name: str | None = None,
    requested_domain: str | None = None,
) -> list[str]:
    return [_format_recurring(record) for record in retrieve_recurring_issue_records(
        limit=limit,
        database_name=database_name,
        requested_domain=requested_domain,
    )]


def retrieve_recurring_issue_records(
    limit: int = 5,
    *,
    database_name: str | None = None,
    requested_domain: str | None = None,
) -> list[RecurringIssueIndexRecord]:
    records = read_recurring_issue_index(database_name=database_name, limit=None)
    if requested_domain:
        aliases = DOMAIN_ALIASES.get(requested_domain, {requested_domain})
        records = [
            record
            for record in records
            if record.category in aliases
            or any(alias in record.title.lower() for alias in aliases)
            or any(alias in (record.latest_summary or "").lower() for alias in aliases)
        ]
    return records[:limit]


def summarize_recurring_issue_index(
    *,
    database_name: str | None = None,
    requested_domain: str | None = None,
    sampled_runs: int | None = None,
    limit: int = 8,
) -> dict[str, Any]:
    records = retrieve_recurring_issue_records(
        limit=10000,
        database_name=database_name,
        requested_domain=requested_domain,
    )
    lines: list[str] = []
    for record in records[:limit]:
        denominator = sampled_runs if sampled_runs and sampled_runs > 0 else record.run_count
        lines.append(
            f"{record.title} recurred in {record.run_count}/{denominator} saved health run(s)."
        )
    return {
        "records_scanned": len(records),
        "lines": lines,
    }


def _score_chunk(chunk: TraceEvidenceChunk, *, terms: list[str], aliases: set[str]) -> int:
    text = " ".join([chunk.category, chunk.title, chunk.summary, " ".join(chunk.facts), " ".join(chunk.sql_ids)]).lower()
    score = 0
    for alias in aliases:
        if alias and alias in text:
            score += 4
    for term in terms:
        if term and term in text:
            score += 2
    if chunk.severity == "CRITICAL":
        score += 2
    elif chunk.severity == "WARNING":
        score += 1
    return score


def _format_chunk(chunk: TraceEvidenceChunk) -> str:
    facts = "; ".join(chunk.facts[:3])
    suffix = f" Evidence: {facts}" if facts else ""
    return f"{chunk.recorded_at} [{chunk.severity}] {chunk.title}: {chunk.summary}{suffix}"


def _format_recurring(record: RecurringIssueIndexRecord) -> str:
    evidence = "; ".join(record.sample_evidence[:2])
    suffix = f" Evidence: {evidence}" if evidence else ""
    return (
        f"{record.title} recurred in {record.run_count} run(s) "
        f"({record.unhealthy_run_count} unhealthy). Latest: {record.latest_summary or 'n/a'}.{suffix}"
    )


def _infer_domain(text: str) -> str | None:
    lowered = (text or "").lower()
    for domain, aliases in DOMAIN_ALIASES.items():
        if any(_contains_alias(lowered, alias) for alias in aliases):
            return domain
    return None


def _contains_alias(text: str, alias: str) -> bool:
    if alias == "ora":
        return "ora-" in text or re.search(r"\bora\b", text) is not None
    if alias == "tns":
        return "tns-" in text or re.search(r"\btns\b", text) is not None
    if " " in alias:
        return alias in text
    return re.search(rf"\b{re.escape(alias)}\b", text) is not None


def _terms(text: str) -> list[str]:
    return [term for term in re.findall(r"[a-z0-9_#$-]{3,}", (text or "").lower()) if term not in {"the", "and", "for", "with"}]
