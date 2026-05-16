---
component_id: 5.3
component_name: Historical Analysis & Interpretation Engine
---

# Historical Analysis & Interpretation Engine

## Component Description

Transforms raw JSONL telemetry and AWR data into structured timelines and interpreted performance insights, serving as the analytical "memory" for the agent.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 2250-2334)
```
    def _build_event_timeline(
        self,
        *,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        recovery_drivers: list[HistoricalRecoveryDriver],
        residual_drivers: list[HistoricalResidualDriver],
        transition_outcome: str,
        learning: LearningFeatureVector,
        awr_user_message: str,
        awr_diff: AwrStateDiff | None,
    ) -> list[HistoricalEventTimelineEntry]:
        previous_notes: list[str] = []
        current_notes: list[str] = []
        current_notes.extend(driver.title for driver in recovery_drivers[:2])
        current_notes.extend(driver.title for driver in residual_drivers[:2])
        if learning.state_persisted_but_worsened_flag:
            current_notes.append("State persisted with worsening internal impact.")
        if awr_user_message and "fallback" in awr_user_message.lower():
            current_notes.append(awr_user_message)

        transition_label = transition_outcome.replace("_", " ")
        awr_mild = bool(
            awr_diff
            and awr_diff.available
            and awr_diff.workload_interpretation
            and awr_diff.workload_interpretation.low_significance_majority
        )
        awr_material = bool(
            awr_diff
            and awr_diff.available
            and awr_diff.workload_interpretation
            and awr_diff.workload_interpretation.material_change_detected
        )
        if transition_outcome in {"recovered", "improved", "persisted_but_improved"}:
            recovery_text = recovery_drivers[0].title.lower() if recovery_drivers else "material pressure eased"
            residual_text = residual_drivers[0].title.lower() if residual_drivers else "no residual warning drivers remained"
            current_summary = (
                f"Status improved to {str(current.overall_status or 'INFO').upper()} after {recovery_text}; "
                f"residual signal: {residual_text}."
            )
        elif transition_outcome in {"worsened", "persisted_but_worsened"}:
            residual_text = residual_drivers[0].title.lower() if residual_drivers else "warning pressure increased"
            if awr_mild:
                current_summary = (
                    f"Status worsened to {str(current.overall_status or 'INFO').upper()}. "
                    f"AWR workload deltas were mild, but {residual_text} remained the primary risk driver."
                )
            elif awr_material:
                current_summary = (
                    f"Status worsened to {str(current.overall_status or 'INFO').upper()} with material AWR workload change and primary driver: {residual_text}."
                )
            else:
                current_summary = (
                    f"Status worsened to {str(current.overall_status or 'INFO').upper()} with primary driver: {residual_text}."
                )
        else:
            if transition_outcome == "persisted_but_worsened":
                current_summary = (
                    f"Status remained {str(current.overall_status or 'INFO').upper()} with stronger internal pressure and persistent warning drivers."
                )
            elif transition_outcome == "persisted_but_improved":
                current_summary = (
                    f"Status remained {str(current.overall_status or 'INFO').upper()} with measurable internal recovery drivers."
                )
            else:
                current_summary = (
                    f"Status stayed {str(current.overall_status or 'INFO').upper()} ({transition_label}); no dominant directional shift was detected."
                )
        return [
            HistoricalEventTimelineEntry(
                at=previous.completed_at,
                summary=previous.summary or "Previous health run",
                change_notes=previous_notes or ["Baseline reference run."],
                source="JSONL",
                impact_level="MEDIUM" if str(previous.overall_status or "INFO") in {"WARNING", "CRITICAL"} else "LOW",
            ),
            HistoricalEventTimelineEntry(
                at=current.completed_at,
                summary=current_summary,
                change_notes=current_notes or ["No major incident-driver transition detected."],
                source="JSONL+AWR" if "run-pair" in awr_user_message.lower() else "JSONL",
                impact_level="CRITICAL" if str(current.overall_status or "INFO") == "CRITICAL" else "HIGH",
            ),
        ]
```


## Source Files:

- `history/jsonl_service.py`

