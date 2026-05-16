---
component_id: 6.1.2
component_name: Remediation Strategy Logic
---

# Remediation Strategy Logic

## Component Description

Contains the domain-specific heuristics for different database issues. It analyzes session chains for blocking locks or usage percentages for tablespaces to decide what needs to be done (e.g., kill session X or extend tablespace Y).

---

## Key References:

### /home/neha/projects/agents/odb_autodba/tools/action_proposals.py (lines 41-212)
```
def _blocking_lock_proposal(snapshot: HealthSnapshot) -> RemediationProposal | None:
    if not snapshot.blocking_chains:
        return None

    warning_threshold = _env_int("BLOCKING_WAIT_WARNING_SECONDS", BLOCKING_WAIT_WARNING_SECONDS)
    kill_threshold = _env_int("BLOCKING_WAIT_KILL_THRESHOLD_SECONDS", BLOCKING_WAIT_KILL_THRESHOLD_SECONDS)
    kill_count_threshold = _env_int("BLOCKED_SESSION_COUNT_KILL_THRESHOLD", BLOCKED_SESSION_COUNT_KILL_THRESHOLD)

    grouped = _group_blockers(snapshot.blocking_chains)
    if not grouped:
        return None
    grouped.sort(
        key=lambda item: (
            int(item.get("max_wait_seconds") or 0),
            int(item.get("blocked_count") or 0),
        ),
        reverse=True,
    )
    selected = grouped[0]

    sid = _as_int(selected.get("sid"))
    serial = _as_int(selected.get("serial"))
    inst = _as_int(selected.get("inst_id"))
    if sid is None or serial is None:
        return None

    blocker_user = str(selected.get("username") or "-")
    blocker_program = str(selected.get("program") or "-")
    blocker_module = str(selected.get("module") or "-")
    blocker_machine = str(selected.get("machine") or "-")
    blocker_classification = str(selected.get("classification") or "unknown")
    blocked_count = int(selected.get("blocked_count") or 0)
    max_wait_seconds = int(selected.get("max_wait_seconds") or 0)
    idle_in_tx = bool(selected.get("idle_in_transaction"))
    has_tx = bool(selected.get("has_transaction"))
    evidence_complete = bool(selected.get("evidence_complete"))
    protected = blocker_classification == "sys_or_background" or blocker_user.upper() in {"SYS", "SYSTEM"}

    recommendation_mode = _recommendation_mode(
        protected=protected,
        evidence_complete=evidence_complete,
        classification=blocker_classification,
        max_wait_seconds=max_wait_seconds,
        blocked_count=blocked_count,
        idle_in_transaction=idle_in_tx,
        warning_threshold=warning_threshold,
        kill_threshold=kill_threshold,
        kill_count_threshold=kill_count_threshold,
    )
    action_title = _blocking_action_title(recommendation_mode, sid, blocker_classification)
    reason_for_action = _reason_for_action(
        recommendation_mode=recommendation_mode,
        sid=sid,
        blocker_user=blocker_user,
        blocker_classification=blocker_classification,
        blocked_count=blocked_count,
        max_wait_seconds=max_wait_seconds,
        warning_threshold=warning_threshold,
        kill_threshold=kill_threshold,
    )
    confidence = _proposal_confidence(
        recommendation_mode=recommendation_mode,
        evidence_complete=evidence_complete,
        classification=blocker_classification,
        max_wait_seconds=max_wait_seconds,
        kill_threshold=kill_threshold,
    )

    sql = None if protected else build_clear_blocking_lock_sql(sid=sid, serial_num=serial, inst_id=inst)
    detail = _blocking_chain_detail(selected)
    post_validation = PostActionValidationPlan(
        checks=[
            "Re-run blocking-chain check and confirm no waiter references this blocker SID.",
            "Verify blocked sessions are no longer waiting on TX row lock contention.",
            "Confirm target session is absent or marked as KILLED in gv$session.",
            "Check for replacement/final blocker emergence in the same workload path.",
        ],
        success_criteria=[
            "blocked_session_count drops to zero for the affected blocker identity.",
            "Former waiter sessions resume progress or complete normally.",
            "No new blocker with equal/higher wait severity appears immediately after action.",
        ],
        rollback_risks=[
            "Killed transaction may rollback and consume undo/redo while releasing locks.",
            "Application requests may retry or fail until rollback completes.",
        ],
    )

    risks = [
        "The target transaction may roll back and increase temporary undo/redo pressure.",
        "Killing a foreground session can impact in-flight application work and user latency.",
        "Validate blocker ownership with the application team before terminating the session.",
    ]
    if not evidence_complete:
        risks.append("Evidence is incomplete; prefer review-first handling before execution.")
    if protected:
        risks.append("Target appears protected/internal; automated kill is not recommended.")

    safer_alternatives = [
        f"Monitor blocking for another {warning_threshold} seconds if business impact is low.",
        "Validate session ownership and transaction intent with application owner first.",
        "Capture blocker SQL text and object ownership evidence before escalation.",
    ]
    if idle_in_tx:
        safer_alternatives.append("Attempt application-side COMMIT/ROLLBACK for the blocker owner before kill.")
    if not evidence_complete:
        safer_alternatives.append("Run a fresh health snapshot to improve evidence completeness before acting.")

    blocker_summary = (
        f"Blocker SID {sid} (serial {serial}, inst {inst}) user={blocker_user}, "
        f"class={blocker_classification}, blocked_sessions={blocked_count}, "
        f"max_wait={max_wait_seconds}s."
    )
    if detail.object_name:
        blocker_summary += f" Locked object sample: {detail.object_owner}.{detail.object_name} ({detail.object_type})."

    target_payload = {
        "sid": sid,
        "serial#": serial,
        "inst_id": inst,
        "username": blocker_user,
        "program": blocker_program,
        "module": blocker_module,
        "machine": blocker_machine,
        "status": selected.get("status"),
        "blocker_sql_id": selected.get("blocker_sql_id"),
        "blocker_sql_text": selected.get("blocker_sql_text"),
        "is_blocker": True,
        "blocked_session_count": blocked_count,
        "max_blocked_wait_seconds": max_wait_seconds,
        "blocker_classification": blocker_classification,
        "blocker_has_transaction": has_tx,
        "blocker_idle_in_transaction": idle_in_tx,
        "evidence_complete": evidence_complete,
        "recommendation_mode": recommendation_mode,
        "blocked_session_details": selected.get("blocked_sessions") or [],
        "object_owner": detail.object_owner,
        "object_name": detail.object_name,
        "object_type": detail.object_type,
    }

    blocking_action = BlockingActionProposal(
        action_title=action_title,
        blocker_identity={"sid": sid, "serial#": serial, "inst_id": inst},
        blocked_session_count=blocked_count,
        max_blocked_wait_seconds=max_wait_seconds,
        blocker_classification=blocker_classification,
        reason_for_action=reason_for_action,
        risk_summary=risks,
        safer_alternatives=safer_alternatives,
        post_action_validation_plan=post_validation,
        execution_sql=sql,
        evidence=detail,
        confidence=confidence,
    )

    return RemediationProposal(
        action_type="clear_blocking_lock",
        title=action_title,
        description="Blocking-lock remediation candidate generated from live blocker/waiter evidence.",
        rationale=blocker_summary,
        reason_for_action=reason_for_action,
        sql=sql,
        execution_sql=sql,
        target=target_payload,
        risks=risks,
        safer_alternatives=safer_alternatives,
        validation_plan=post_validation.checks,
        post_action_validation=post_validation,
        blocking_action=blocking_action,
        confidence=confidence,
    )
```

### /home/neha/projects/agents/odb_autodba/tools/action_proposals.py (lines 215-281)
```
def _tablespace_extend_proposal(snapshot: HealthSnapshot) -> RemediationProposal | None:
    if not snapshot.tablespaces:
        return None
    trigger_pct = _env_float("ODB_AUTODBA_TABLESPACE_EXTEND_TRIGGER_PCT", 85.0)
    protected = {"SYSTEM", "SYSAUX"}
    hottest: TablespaceUsageRow | None = None
    for candidate in snapshot.tablespaces:
        name = str(candidate.tablespace_name or "").upper()
        if name in protected:
            continue
        if candidate.used_pct >= trigger_pct:
            hottest = candidate
            break
    if hottest is None:
        return None

    initial_gb = _env_int("ODB_AUTODBA_TABLESPACE_EXTEND_INITIAL_GB", 1)
    next_mb = _env_int("ODB_AUTODBA_TABLESPACE_EXTEND_NEXT_MB", 256)
    max_gb = _env_int("ODB_AUTODBA_TABLESPACE_EXTEND_MAX_GB", 32)

    tablespace_name = str(hottest.tablespace_name or "").upper()
    sql, notes = build_extend_tablespace_sql(
        tablespace_name=tablespace_name,
        initial_gb=initial_gb,
        next_mb=next_mb,
        max_gb=max_gb,
        bigfile_hint=str(hottest.bigfile or "").upper() in {"YES", "Y", "TRUE", "1"},
    )
    rationale = (
        f"Tablespace {tablespace_name} usage is {hottest.used_pct:.1f}% "
        f"({hottest.used_mb} MB used of {hottest.total_mb} MB total)."
    )
    if notes:
        rationale += " SQL generation used fallback metadata because full datafile metadata was unavailable."
    return RemediationProposal(
        action_type="extend_tablespace",
        title=f"Extend tablespace {tablespace_name}",
        description="Tablespace utilization is high and may cause allocation failures.",
        rationale=rationale,
        sql=sql,
        execution_sql=sql,
        target={
            "tablespace_name": tablespace_name,
            "used_pct": hottest.used_pct,
            "used_mb": hottest.used_mb,
            "free_mb": hottest.free_mb,
            "total_mb": hottest.total_mb,
            "bigfile": hottest.bigfile,
            "initial_gb": initial_gb,
            "next_mb": next_mb,
            "max_gb": max_gb,
            "generation_notes": notes,
        },
        risks=[
            "Storage growth may impact capacity planning and backup windows.",
            "Validate storage headroom before applying autoextend or adding datafiles.",
        ],
        safer_alternatives=[
            "Check segment growth trend before immediate extension.",
            "Review retention/purge options for non-critical data segments.",
        ],
        validation_plan=[
            "Re-run tablespace usage checks after execution.",
            "Confirm free space trend and autoextend settings are as expected.",
        ],
        confidence="MEDIUM",
    )
```

### /home/neha/projects/agents/odb_autodba/tools/action_proposals.py (lines 284-352)
```
def _group_blockers(chains: list[BlockingChain]) -> list[dict[str, Any]]:
    grouped: dict[tuple[int | None, int | None, int | None], dict[str, Any]] = {}
    for chain in chains:
        key = (chain.blocker_inst_id, chain.blocker_sid, chain.blocker_serial)
        current = grouped.setdefault(
            key,
            {
                "inst_id": chain.blocker_inst_id,
                "sid": chain.blocker_sid,
                "serial": chain.blocker_serial,
                "username": chain.blocker_user,
                "program": chain.blocker_program,
                "module": chain.blocker_module,
                "machine": chain.blocker_machine,
                "status": chain.blocker_status,
                "blocker_sql_id": chain.blocker_sql_id,
                "blocker_sql_text": chain.blocker_sql_text,
                "classification": chain.blocker_classification,
                "has_transaction": chain.blocker_has_transaction,
                "idle_in_transaction": chain.blocker_idle_in_transaction,
                "evidence_complete": chain.evidence_complete,
                "blocked_sessions": [],
                "blocked_count": 0,
                "max_wait_seconds": 0,
                "object_owner": None,
                "object_name": None,
                "object_type": None,
                "sample_chain": chain,
            },
        )
        blocked_key = (chain.blocked_inst_id, chain.blocked_sid, chain.blocked_serial)
        known_keys = {
            (row.get("inst_id"), row.get("sid"), row.get("serial#"))
            for row in current["blocked_sessions"]
        }
        if blocked_key not in known_keys:
            current["blocked_sessions"].append(
                {
                    "inst_id": chain.blocked_inst_id,
                    "sid": chain.blocked_sid,
                    "serial#": chain.blocked_serial,
                    "username": chain.blocked_user,
                    "status": chain.blocked_status,
                    "sql_id": chain.blocked_sql_id,
                    "event": chain.event,
                    "wait_class": chain.wait_class,
                    "seconds_in_wait": chain.seconds_in_wait,
                    "program": chain.blocked_program,
                    "module": chain.blocked_module,
                    "machine": chain.blocked_machine,
                }
            )
        current["blocked_count"] = max(
            int(current["blocked_count"] or 0),
            int(chain.blocked_session_count or 0),
            len(current["blocked_sessions"]),
        )
        current["max_wait_seconds"] = max(
            int(current["max_wait_seconds"] or 0),
            int(chain.max_blocked_wait_seconds or 0),
            int(chain.seconds_in_wait or 0),
        )
        if chain.object_name and not current.get("object_name"):
            current["object_owner"] = chain.object_owner
            current["object_name"] = chain.object_name
            current["object_type"] = chain.object_type
        current["classification"] = current.get("classification") or "unknown"
        current["evidence_complete"] = bool(current.get("evidence_complete")) and bool(chain.evidence_complete)
    return list(grouped.values())
```


## Source Files:

- `db/remediation_sql.py`
- `tools/action_proposals.py`

