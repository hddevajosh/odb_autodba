---
component_id: 5.3.4
component_name: Semantic Timeline & Interpretation Engine
---

# Semantic Timeline & Interpretation Engine

## Component Description

The core logic center that synthesizes trends and AWR data into high-level state transitions, identifying the primary drivers and severity of system changes.

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

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 1041-1248)
```
    def _build_state_transition(
        self,
        *,
        previous: TraceHealthRunRecord | None,
        current: TraceHealthRunRecord | None,
        recurring: list[str],
        traces: list[TraceHealthRunRecord],
    ) -> HistoricalStateTransition:
        if previous is None or current is None:
            return HistoricalStateTransition(
                available=False,
                coverage_notes=["At least two historical runs are required for state transition analysis."],
            )

        previous_status = str(previous.overall_status or "INFO")
        current_status = str(current.overall_status or "INFO")
        status_transition = f"{previous_status.lower()} -> {current_status.lower()}"
        comparison_window = self._build_comparison_window(previous, current)

        issue_transitions = self._classify_issue_transitions(previous.issues, current.issues)
        awr_result = self._build_optional_awr_diff(previous, current, comparison_window=comparison_window)
        awr_diff: AwrStateDiff | None
        awr_notes: list[str]
        fallback_mode: str
        awr_debug_message = ""
        if len(awr_result) == 3:
            awr_diff, awr_notes, fallback_mode = awr_result
        else:
            awr_diff, awr_notes, fallback_mode, awr_debug_message = awr_result
        sql_regression = self._sql_regression_signal(previous, current, awr_diff)
        metric_deltas = self._build_metric_deltas(previous, current)
        outcome = self._determine_transition_outcome(
            previous_status=previous_status,
            current_status=current_status,
            issue_transitions=issue_transitions,
            metric_deltas=metric_deltas,
        )
        recovery_drivers = self._build_recovery_drivers(
            previous,
            current,
            issue_transitions=issue_transitions,
        )
        residual_drivers = self._build_residual_warning_drivers(
            previous,
            current,
            issue_transitions=issue_transitions,
            awr_diff=awr_diff,
            sql_regression=sql_regression,
        )
        outcome = outcome.model_copy(
            update={
                "recovery_detected": bool(recovery_drivers),
                "residual_risk_present": bool(residual_drivers),
            }
        )
        ranked_primary, ranked_secondary = self._rank_transition_drivers(
            previous,
            current,
            issue_transitions,
            awr_diff,
            sql_regression,
        )
        primary_drivers, secondary_drivers = self._compose_transition_drivers(
            transition_outcome=outcome.transition_outcome,
            recovery_drivers=recovery_drivers,
            residual_drivers=residual_drivers,
            fallback_primary=ranked_primary,
            fallback_secondary=ranked_secondary,
        )
        suppressed = self._suppressed_background_signals(
            traces=traces,
            issue_transitions=issue_transitions,
            primary_drivers=primary_drivers,
        )
        learning = self._learning_features(
            previous,
            current,
            issue_transitions,
            awr_diff,
            sql_regression,
            primary_drivers,
            fallback_mode=fallback_mode,
        )
        learning = learning.model_copy(
            update={
                "recovery_detected": outcome.recovery_detected,
                "residual_risk_present": outcome.residual_risk_present,
                "recovery_driver_category": recovery_drivers[0].category if recovery_drivers else None,
                "residual_driver_category": residual_drivers[0].category if residual_drivers else None,
                "transition_outcome": outcome.transition_outcome,
            }
        )
        issue_states = self._historical_issue_states(issue_transitions)
        awr_user_message = self._awr_user_message(awr_diff=awr_diff, fallback_mode=fallback_mode, notes=awr_notes)
        awr_source_summary = self._awr_source_summary(awr_diff=awr_diff, fallback_mode=fallback_mode)
        awr_workload_interpretation = self._awr_workload_interpretation(awr_diff=awr_diff, fallback_mode=fallback_mode)
        snapshot_mapping_summary = self._snapshot_mapping_summary(awr_diff=awr_diff)
        section_naming = self._section_naming_for_outcome(outcome.transition_outcome)
        fallback_summary = awr_user_message if fallback_mode != "none" else "No fallback required."
        timeline_entries = self._build_event_timeline(
            previous=previous,
            current=current,
            recovery_drivers=recovery_drivers,
            residual_drivers=residual_drivers,
            transition_outcome=outcome.transition_outcome,
            learning=learning,
            awr_user_message=awr_user_message,
            awr_diff=awr_diff,
        )

        confidence, confidence_reason = self._transition_confidence(
            primary_drivers=primary_drivers,
            awr_diff=awr_diff,
            metric_deltas=metric_deltas,
            fallback_mode=fallback_mode,
        )
        learning.transition_confidence_reason = confidence_reason

        coverage_notes = [note for note in awr_notes if note]
        coverage_notes.extend(
            self._interpret_transition_patterns(
                issue_transitions=issue_transitions,
                primary_drivers=primary_drivers,
                learning=learning,
            )
        )
        if not primary_drivers:
            coverage_notes.append("No dominant transition drivers were identified from available evidence.")
        coverage_notes.extend(item.interpretation for item in metric_deltas[:4] if item.interpretation)

        confidence_block = HistoricalConfidence(
            confidence_level=confidence,
            confidence_reason=confidence_reason,
            coverage_quality=(awr_diff.snapshot_quality.coverage_quality if awr_diff and awr_diff.snapshot_quality else ("HIGH" if fallback_mode == "jsonl_inference_only" else "LOW")),
            history_source_used="raw run metrics from JSONL traces",
            fallback_mode=fallback_mode,
            fallback_reason=fallback_summary,
            notes=coverage_notes[:8],
        )

        primary_transition_drivers = [self._to_historical_driver(driver, rank="primary") for driver in primary_drivers]
        secondary_transition_drivers = [self._to_historical_driver(driver, rank="secondary") for driver in secondary_drivers]

        summary = HistoricalTransitionSummary(
            status_transition=status_transition,
            primary_drivers=primary_transition_drivers,
            secondary_drivers=secondary_transition_drivers,
            recovery_drivers=recovery_drivers,
            residual_warning_drivers=residual_drivers,
            transition_outcome=outcome,
            suppressed_background_signals=suppressed,
            issue_states=issue_states,
            metric_deltas=metric_deltas,
            event_timeline=timeline_entries,
            learning_features=HistoricalLearningFeatures.model_validate(learning.model_dump(mode="json")),
            confidence=confidence_block,
            comparison_window=comparison_window,
        )

        recurring_ranked = self._rank_recurring_patterns(
            traces=traces,
            primary_drivers=primary_drivers,
            suppressed=suppressed,
        )

        return HistoricalStateTransition(
            available=True,
            previous_run_id=previous.run_id,
            current_run_id=current.run_id,
            previous_status=previous_status,
            current_status=current_status,
            status_transition=status_transition,
            transition_outcome=outcome.transition_outcome,
            recovery_detected=outcome.recovery_detected,
            residual_risk_present=outcome.residual_risk_present,
            issue_transitions=issue_transitions,
            recovery_drivers=recovery_drivers,
            residual_warning_drivers=residual_drivers,
            primary_drivers=primary_drivers,
            secondary_drivers=secondary_drivers,
            recurring_patterns_ranked=recurring_ranked,
            event_timeline=[f"{item.at}: {item.summary}" for item in timeline_entries],
            learning_features=learning,
            confidence=confidence,
            coverage_notes=coverage_notes,
            awr_state_diff=awr_diff,
            primary_transition_drivers=primary_transition_drivers,
            secondary_transition_drivers=secondary_transition_drivers,
            suppressed_background_signals=suppressed,
            metric_deltas=metric_deltas,
            historical_issue_states=issue_states,
            event_timeline_entries=timeline_entries,
            historical_learning_features=summary.learning_features,
            historical_confidence=confidence_block,
            comparison_window=comparison_window,
            history_source_summary="raw run metrics from JSONL traces",
            awr_source_summary=awr_source_summary,
            fallback_summary=fallback_summary,
            section_naming=section_naming,
            awr_workload_interpretation=awr_workload_interpretation,
            snapshot_mapping_summary=snapshot_mapping_summary,
            awr_fallback_info=AwrFallbackInfo(
                fallback_mode=fallback_mode,
                awr_user_message=awr_user_message,
                awr_debug_message=awr_debug_message,
            ),
            summary=summary,
        )
```

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 1365-1402)
```
    def _classify_issue_transitions(
        self,
        previous_issues: list[HealthIssue],
        current_issues: list[HealthIssue],
    ) -> list[TransitionIssueClassification]:
        out: list[TransitionIssueClassification] = []
        previous_map = {self._issue_key(issue): issue for issue in previous_issues}
        current_map = {self._issue_key(issue): issue for issue in current_issues}
        all_keys = sorted(set(previous_map) | set(current_map))
        for key in all_keys:
            prev_issue = previous_map.get(key)
            curr_issue = current_map.get(key)
            if prev_issue and not curr_issue:
                transition = "resolved"
            elif curr_issue and not prev_issue:
                transition = "new"
            else:
                prev_rank = _severity_rank(str(prev_issue.severity if prev_issue else "INFO"))
                curr_rank = _severity_rank(str(curr_issue.severity if curr_issue else "INFO"))
                if curr_rank > prev_rank:
                    transition = "worsened"
                elif curr_rank < prev_rank:
                    transition = "improved"
                else:
                    transition = "persistent"
            issue = curr_issue or prev_issue
            if issue is None:
                continue
            out.append(
                TransitionIssueClassification(
                    category=issue.category,
                    title=issue.title,
                    transition=transition,
                    previous_severity=(str(prev_issue.severity) if prev_issue else None),
                    current_severity=(str(curr_issue.severity) if curr_issue else None),
                )
            )
        return out
```

### /home/neha/projects/agents/odb_autodba/history/jsonl_service.py (lines 1250-1304)
```
    def _build_optional_awr_diff(
        self,
        previous: TraceHealthRunRecord,
        current: TraceHealthRunRecord,
        *,
        comparison_window: HistoricalComparisonWindow,
    ) -> tuple[AwrStateDiff | None, list[str], str, str]:
        notes: list[str] = []
        debug_message = ""
        if not _awr_feature_enabled():
            notes.append("AWR workload comparison is disabled; JSONL fallback used.")
            return None, notes, "awr_disabled", debug_message
        try:
            caps = get_awr_capabilities()
        except Exception as exc:
            debug_message = str(exc)
            return None, ["AWR workload comparison unavailable because capability metadata could not be collected; JSONL fallback used."], "awr_capability_failure", debug_message
        if not caps.available:
            notes.append("AWR source unavailable, JSONL fallback used.")
            return AwrStateDiff(available=False, capabilities=caps), notes, "awr_unavailable", debug_message
        try:
            mapping = map_run_pair_to_awr_windows(
                previous.completed_at,
                current.completed_at,
                dbid=caps.dbid,
                previous_window_start=comparison_window.window_start,
                previous_window_end=previous.completed_at,
                current_window_start=current.completed_at,
                current_window_end=comparison_window.window_end,
            )
            notes.extend(mapping.notes[:4])
            debug_message = json.dumps(mapping.debug or {}, ensure_ascii=True, default=str)
            awr_diff = build_awr_state_diff(window_mapping=mapping, capabilities=caps)
            notes.extend(awr_diff.snapshot_quality.notes[:4] if awr_diff.snapshot_quality else [])
            awr_diff = self._enrich_awr_with_report_text_if_needed(awr_diff=awr_diff, mapping=mapping, capabilities=caps, notes=notes)
            if not awr_diff.available:
                notes.append("AWR snapshot mapping was weak; JSONL fallback used for transition reasoning.")
                return awr_diff, notes, "awr_mapping_weak", debug_message
            same_window = (
                mapping.previous.begin_snap_id is not None
                and mapping.previous.end_snap_id is not None
                and mapping.previous.begin_snap_id == mapping.current.begin_snap_id
                and mapping.previous.end_snap_id == mapping.current.end_snap_id
            )
            if same_window or bool((mapping.debug or {}).get("same_snap_selected")):
                notes.append("AWR snapshots mapped successfully but same-window comparison is weak.")
                return awr_diff, notes, "awr_same_window_weak", debug_message
            if awr_diff.snapshot_quality and awr_diff.snapshot_quality.coverage_quality in {"LOW", "NONE"}:
                notes.append("AWR snapshots mapped successfully but metric rows were incomplete; partial AWR comparison shown.")
                return awr_diff, notes, "awr_metric_incomplete", debug_message
            return awr_diff, notes, "none", debug_message
        except Exception as exc:
            debug_message = str(exc)
            notes.append("AWR query failed while building workload comparison; JSONL fallback used.")
            return None, notes, "awr_query_failure", debug_message
```


## Source Files:

- `history/jsonl_service.py`

