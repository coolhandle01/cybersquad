"""
tools/tui/_helpers.py - Pure functions extracted from CrewAIPipelineTUI.

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


def task_layout(tasks: list) -> list[tuple[str, str]]:
    """Build the sidebar entries for a sequential pipeline.

    For each task that has an assigned agent, return a ``(heading, role)``
    pair in pipeline order. ``heading`` is the task's display name
    (``Task.name``), falling back to the agent role when a task carries no
    name; ``role`` is the agent role shown on the task's status row. Because
    the heading is per-task rather than per-agent, an agent that runs more than
    one task in the pipeline gets a distinct heading for each.

    Tasks with no agent are skipped, so a partially-wired crew never raises.
    """
    layout: list[tuple[str, str]] = []
    for task in tasks:
        agent = getattr(task, "agent", None)
        if agent is None:
            continue
        role = agent.role
        layout.append((task.name or role, role))
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
