from __future__ import annotations

from odb_autodba.models.schemas import HistoryContext


def build_cause_evolution_output(history_context: HistoryContext) -> list[str]:
    lines = list(history_context.recurring_findings)
    lines.extend(trend.summary for trend in history_context.trend_summaries)
    transition = history_context.state_transition
    if transition and transition.available:
        lines.append(
            f"State transition {transition.status_transition} with {transition.confidence} confidence."
        )
        lines.append(f"Transition outcome: {transition.transition_outcome}.")
        lines.extend(
            f"Recovery driver: {driver.title} ({driver.category})."
            for driver in transition.recovery_drivers[:2]
        )
        lines.extend(
            f"Residual warning driver: {driver.title} ({driver.category})."
            for driver in transition.residual_warning_drivers[:2]
        )
    return lines
