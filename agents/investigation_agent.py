from __future__ import annotations

from odb_autodba.db.investigation_sql import execute_investigation_sql, validate_investigation_sql
from odb_autodba.models.schemas import InvestigationReport, InvestigationStep
from odb_autodba.rag.investigation_trace_store import append_investigation_trace
from odb_autodba.utils.sql_analysis import extract_sql_id


class InvestigationAgent:
    RESULT_ROW_PREVIEW_LIMIT = 20

    def investigate(self, problem_statement: str, max_steps: int = 4) -> InvestigationReport:
        intents = self._detect_intents(problem_statement)
        sql_steps = self._plan_steps(problem_statement, intents)[:max_steps]
        steps: list[InvestigationStep] = []
        evidence: list[str] = []
        for idx, item in enumerate(sql_steps, start=1):
            validation = validate_investigation_sql(item["sql"])
            if not validation.ok:
                steps.append(
                    InvestigationStep(
                        step_number=idx,
                        goal=item["goal"],
                        sql=item["sql"],
                        result_preview=validation.reason,
                        status="error",
                    )
                )
                break
            result = execute_investigation_sql(validation.normalized_sql or item["sql"])
            preview = result.error if result.status == "error" else f"Returned {result.row_count} row(s). Columns: {', '.join(result.columns[:8])}"
            if result.status == "success" and result.rows:
                evidence.append(f"Step {idx} {item['goal']}: first row {result.rows[0]}")
            rows_preview = list(result.rows[: self.RESULT_ROW_PREVIEW_LIMIT]) if result.status == "success" else []
            steps.append(
                InvestigationStep(
                    step_number=idx,
                    goal=item["goal"],
                    sql=validation.normalized_sql or item["sql"],
                    result_preview=preview,
                    row_count=result.row_count,
                    status=result.status,
                    result_columns=list(result.columns or []),
                    result_rows=rows_preview,
                    result_truncated=bool(result.truncated or (result.status == "success" and result.row_count > len(rows_preview))),
                )
            )
            if result.status == "error":
                break
        likely_cause = self._derive_cause(problem_statement, intents, steps, evidence)
        report = InvestigationReport(
            problem_statement=problem_statement,
            summary=f"Ran {len(steps)} Oracle investigation step(s).",
            likely_cause=likely_cause,
            evidence=evidence,
            recommended_next_actions=self._recommended_next_actions(intents, steps),
            steps=steps,
        )
        append_investigation_trace(problem_statement, [step.model_dump() for step in steps])
        return report

    def _plan_steps(self, problem_statement: str, intents: set[str]) -> list[dict[str, str]]:
        lowered = (problem_statement or "").lower()
        sql_id = extract_sql_id(problem_statement)
        steps: list[dict[str, str]] = []

        if sql_id:
            steps.extend(
                [
                {"goal": "Inspect current SQL statistics", "sql": f"select sql_id, plan_hash_value, executions, round(elapsed_time/1e6,3) elapsed_s, round(cpu_time/1e6,3) cpu_s from v$sqlstats where sql_id = '{sql_id}'"},
                {"goal": "Inspect child cursors", "sql": f"select child_number, plan_hash_value, executions from v$sql where sql_id = '{sql_id}' order by child_number"},
                ]
            )
        if "blocking" in intents:
            steps.extend(
                [
                {"goal": "Identify blocking sessions", "sql": "select inst_id, sid, serial#, username, sql_id, blocking_instance, blocking_session, event, wait_class from gv$session where blocking_session is not null"},
                {"goal": "Inspect blocker sessions", "sql": "select inst_id, sid, serial#, username, status, sql_id, event, wait_class, module, program from gv$session where sid in (select blocking_session from gv$session where blocking_session is not null)"},
                ]
            )
        if "errors" in intents:
            steps.append({"goal": "Review recent alert log errors", "sql": "select originating_timestamp, message_text from v$diag_alert_ext where regexp_like(message_text, 'ORA-|TNS-', 'i') order by originating_timestamp desc fetch first 20 rows only"})
        if "user_count" in intents:
            steps.append(
                {
                    "goal": "Count database users",
                    "sql": "select count(*) as total_users, sum(case when nvl(oracle_maintained,'N')='N' then 1 else 0 end) as non_oracle_maintained_users from dba_users",
                }
            )
        if "db_size" in intents:
            steps.append(
                {
                    "goal": "Measure allocated database size",
                    "sql": "select round((select nvl(sum(bytes),0) from dba_data_files)/1024/1024/1024,2) as datafiles_gb, round((select nvl(sum(bytes),0) from dba_temp_files)/1024/1024/1024,2) as tempfiles_gb, round((select nvl(sum(bytes),0) from v$log)/1024/1024/1024,2) as redo_gb, round(((select nvl(sum(bytes),0) from dba_data_files)+(select nvl(sum(bytes),0) from dba_temp_files)+(select nvl(sum(bytes),0) from v$log))/1024/1024/1024,2) as total_allocated_gb from dual",
                }
            )
            steps.append(
                {
                    "goal": "Estimate used segment size",
                    "sql": "select round(nvl(sum(bytes),0)/1024/1024/1024,2) as used_segments_gb from dba_segments",
                }
            )
        if "sessions" in intents:
            steps.append(
                {
                    "goal": "Inspect active sessions",
                    "sql": "select inst_id, sid, serial#, username, status, sql_id, event, wait_class, module, program, machine from gv$session where status = 'ACTIVE' and username is not null fetch first 20 rows only",
                }
            )
        if "top_sql_cpu" in intents:
            steps.append(
                {
                    "goal": "Inspect top SQL by CPU",
                    "sql": "select sql_id, plan_hash_value, round(cpu_time/1e6,3) cpu_s, round(elapsed_time/1e6,3) elapsed_s, executions from v$sqlstats order by cpu_time desc fetch first 10 rows only",
                }
            )

        if steps:
            return self._dedupe_steps(steps)

        if "ora" in lowered or "error" in lowered:
            return [{"goal": "Review recent alert log errors", "sql": "select originating_timestamp, message_text from v$diag_alert_ext where regexp_like(message_text, 'ORA-|TNS-', 'i') order by originating_timestamp desc fetch first 20 rows only"}]
        return [
            {"goal": "Inspect active sessions", "sql": "select inst_id, sid, serial#, username, status, sql_id, event, wait_class, module, program, machine from gv$session where status = 'ACTIVE' and username is not null fetch first 20 rows only"},
            {"goal": "Inspect top SQL by CPU", "sql": "select sql_id, plan_hash_value, round(cpu_time/1e6,3) cpu_s, round(elapsed_time/1e6,3) elapsed_s, executions from v$sqlstats order by cpu_time desc fetch first 10 rows only"},
        ]

    def _derive_cause(self, problem_statement: str, intents: set[str], steps: list[InvestigationStep], evidence: list[str]) -> str:
        if not steps:
            return "No investigation steps were planned from the request."
        if any(step.status == "error" for step in steps):
            return "The investigation hit one or more SQL execution errors; results may be incomplete."
        if not evidence:
            return "The investigation did not gather enough evidence to isolate a finding."
        if "blocking" in intents:
            return "Blocking or lock contention is the leading cause candidate based on the investigation path."
        if "top_sql_cpu" in intents or "sessions" in intents:
            return "Runtime workload evidence was collected for active sessions and SQL resource usage."
        if "user_count" in intents and "db_size" in intents:
            return "Requested inventory metrics were collected: database user count and database size estimates."
        if "user_count" in intents:
            return "Requested inventory metric was collected: database user count."
        if "db_size" in intents:
            return "Requested inventory metric was collected: database size estimate."
        lowered = (problem_statement or "").lower()
        if "cpu" in lowered or "slow" in lowered:
            return "One or more high-cost SQL statements appear to be contributing to the slowdown."
        return "Investigation completed with read-only evidence collection based on your request."

    def _recommended_next_actions(self, intents: set[str], steps: list[InvestigationStep]) -> list[str]:
        if any(step.status == "error" for step in steps):
            return [
                "Review the failed step and verify privileges on referenced v$/dba_ views.",
                "Retry investigation after privilege or connectivity fixes.",
            ]
        if "user_count" in intents and "db_size" in intents:
            return [
                "Use the returned user counts to validate expected account inventory.",
                "Use the size breakdown (datafiles/tempfiles/redo) for capacity planning baselines.",
            ]
        if "user_count" in intents:
            return ["Review user count results and reconcile with expected account inventory."]
        if "db_size" in intents:
            return ["Use the size metrics as a baseline for growth and storage capacity planning."]
        if "blocking" in intents:
            return [
                "Review blocker and waiter SQL_ID/session owners together before intervention.",
                "If blocker termination is necessary, use guarded remediation with operator confirmation.",
            ]
        if "top_sql_cpu" in intents or "sessions" in intents:
            return [
                "Correlate active sessions with top SQL to confirm the dominant workload source.",
                "Run SQL_ID deep dive on the highest-impact SQL_ID for plan and wait analysis.",
            ]
        return ["Review the SQL steps and confirm whether additional targeted investigation is needed."]

    def _detect_intents(self, problem_statement: str) -> set[str]:
        lowered = (problem_statement or "").lower()
        intents: set[str] = set()
        if self._contains_any(lowered, ("block", "blocking", "lock", "locked", "contention")):
            intents.add("blocking")
        if self._contains_any(lowered, ("ora", "tns", "error", "errors", "alert log", "listener")):
            intents.add("errors")
        if self._contains_any(lowered, ("active session", "active sessions", "session")):
            intents.add("sessions")
        if self._contains_any(lowered, ("cpu", "top sql", "slow", "slowness", "performance")):
            intents.add("top_sql_cpu")
        if self._contains_any(lowered, ("how many users", "database users", "user count", "users exist", "schemas", "accounts")):
            intents.add("user_count")
        if self._contains_any(lowered, ("database size", "size of database", "db size", "how big", "storage size", "space used", "size")):
            intents.add("db_size")
        return intents

    def _contains_any(self, text: str, tokens: tuple[str, ...]) -> bool:
        return any(token in text for token in tokens)

    def _dedupe_steps(self, steps: list[dict[str, str]]) -> list[dict[str, str]]:
        seen: set[str] = set()
        deduped: list[dict[str, str]] = []
        for step in steps:
            sql = " ".join((step.get("sql") or "").split()).strip().lower()
            if not sql or sql in seen:
                continue
            seen.add(sql)
            deduped.append(step)
        return deduped
