"""
crewui/_helpers.py - Pure functions extracted from CrewAIPipelineTUI.

The TUI class itself (CrewAIPipelineTUI) is App + widgets + threading and needs
a textual.pilot harness to test properly. The pure-logic helpers it relies on -
truncation, log routing, step-message formatting, sidebar layout, metrics
block formatting - have no Textual or threading dependency and live here so
they can be branch-covered by ordinary unit tests.
"""

from __future__ import annotations

from crewai.agents.parser import AgentAction, AgentFinish


def truncate(text: str, limit: int) -> str:
    """Return ``text`` truncated to ``limit`` characters.

    Returns the input unchanged when it is already at or below the limit.
    """
    return text[:limit] if len(text) > limit else text


def route_log_record(record_name: str, prefix: str) -> str:
    """Decide which TUI log pane a logging record belongs in.

    Returns ``"agent"`` when ``record_name`` starts with ``prefix`` (the host
    app's record prefix), else ``"crew"``.
    """
    return "agent" if record_name.startswith(prefix) else "crew"


def task_phase_layout(
    task_names: list[str], task_map: dict[str, str]
) -> list[tuple[str | None, str]]:
    """Build the sidebar layout entries for a sequential pipeline.

    For each task name in order, return a ``(phase_heading, task_name)`` pair.
    ``phase_heading`` is the phase label the first time that phase is seen,
    and ``None`` for any subsequent task that shares the same phase (so the
    caller emits the heading once per phase, not once per task).

    Tasks with no entry in ``task_map`` fall back to using their own name as
    the phase label - i.e. they always emit a heading.
    """
    layout: list[tuple[str | None, str]] = []
    seen: set[str] = set()
    for name in task_names:
        phase = task_map.get(name, name)
        if phase in seen:
            layout.append((None, name))
        else:
            seen.add(phase)
            layout.append((phase, name))
    return layout


def format_metrics_block(total_tokens: int, estimated_cost_usd: float, run_id: str) -> str:
    """Render the fixed-width metrics summary shown in the sidebar."""
    return (
        f" Tokens:  {total_tokens:,}\n"
        f" Cost:    ${estimated_cost_usd:.4f}\n"
        f" Run:     {run_id}\n"
        f" Status:  done"
    )


def format_step_message(step: object) -> str:
    """Format a CrewAI step (AgentAction / AgentFinish / other) as rich-text.

    AgentAction yields a Thought + tool-call line and an optional result block.
    AgentFinish yields an Answer line. Anything else is rendered as its
    truncated ``str()``. Trusts the crewai parser types - the caller's
    callback is responsible for swallowing any unexpected exceptions, since
    the step-callback contract is fire-and-forget telemetry.
    """
    if isinstance(step, AgentAction):
        tool_call = f"[cyan]> {step.tool}[/cyan]({truncate(step.tool_input, 120)})"
        msg = f"[yellow]Thought:[/yellow] {step.thought}\n{tool_call}"
        if step.result:
            msg += f"\n[dim]{truncate(step.result, 300)}[/dim]"
        return msg
    if isinstance(step, AgentFinish):
        return f"[bold green]Answer:[/bold green] {truncate(str(step.output), 500)}"
    return truncate(str(step), 300)
