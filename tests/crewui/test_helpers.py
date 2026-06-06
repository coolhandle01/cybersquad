"""
tests/crewui/test_helpers.py - branch-coverage of the pure helpers in crewui.

The Textual App / widget / threading layer in crewui/__init__.py is exercised
by the textual.pilot harness in test_app.py; the helpers here are pure
functions so every conditional path can be covered by ordinary unit tests.
"""

from __future__ import annotations

import pytest
from crewai.agents.parser import AgentAction, AgentFinish

from crewui._helpers import (
    format_metrics_block,
    format_step_message,
    route_log_record,
    task_phase_layout,
    truncate,
)

pytestmark = pytest.mark.unit


def _make_action(
    tool: str = "recon",
    tool_input: str = "example.com",
    thought: str = "planning",
    result: str | None = "found 2 hosts",
) -> AgentAction:
    """Construct a real AgentAction for tests - it's a Pydantic model, no
    LLM call or token cost involved."""
    return AgentAction(thought=thought, tool=tool, tool_input=tool_input, text="", result=result)


class TestTruncate:
    def test_returns_text_unchanged_when_under_limit(self) -> None:
        assert truncate("hello", 10) == "hello"

    def test_returns_text_unchanged_when_at_limit(self) -> None:
        assert truncate("hello", 5) == "hello"

    def test_truncates_when_over_limit(self) -> None:
        assert truncate("hello world", 5) == "hello"


class TestRouteLogRecord:
    def test_routes_to_agent_when_record_starts_with_prefix(self) -> None:
        assert route_log_record("cybersquad.osint_analyst", "cybersquad") == "agent"

    def test_routes_to_crew_when_record_does_not_start_with_prefix(self) -> None:
        assert route_log_record("urllib3.connectionpool", "cybersquad") == "crew"

    def test_empty_prefix_routes_everything_to_agent(self) -> None:
        # Every string starts with "" so the prefix-empty case lands on agent.
        assert route_log_record("anything", "") == "agent"


class TestTaskPhaseLayout:
    def test_empty_input_yields_empty_layout(self) -> None:
        assert task_phase_layout([], {"x": "y"}) == []

    def test_single_task_emits_phase_heading(self) -> None:
        assert task_phase_layout(["Recon"], {"Recon": "Reconnaissance"}) == [
            ("Reconnaissance", "Recon")
        ]

    def test_two_tasks_same_phase_dedups_heading(self) -> None:
        layout = task_phase_layout(
            ["Sweep", "Probe"],
            {"Sweep": "Reconnaissance", "Probe": "Reconnaissance"},
        )
        assert layout == [("Reconnaissance", "Sweep"), (None, "Probe")]

    def test_two_tasks_different_phases_emit_both_headings(self) -> None:
        layout = task_phase_layout(
            ["Recon", "Triage"],
            {"Recon": "Reconnaissance", "Triage": "Vulnerability Research"},
        )
        assert layout == [
            ("Reconnaissance", "Recon"),
            ("Vulnerability Research", "Triage"),
        ]

    def test_missing_task_in_map_falls_back_to_task_name(self) -> None:
        # No entry in task_map -> uses the task name itself as the phase label.
        layout = task_phase_layout(["Recon"], {})
        assert layout == [("Recon", "Recon")]


class TestFormatMetricsBlock:
    def test_renders_thousands_separator_and_fixed_decimals(self) -> None:
        block = format_metrics_block(
            total_tokens=12345, estimated_cost_usd=0.0418, run_id="20260520-001122-abc123"
        )
        assert " Tokens:  12,345" in block
        assert " Cost:    $0.0418" in block
        assert " Run:     20260520-001122-abc123" in block
        assert " Status:  done" in block


class TestFormatStepMessage:
    def test_agent_action_with_result_includes_thought_tool_call_and_result(self) -> None:
        msg = format_step_message(_make_action())
        assert "[yellow]Thought:[/yellow] planning" in msg
        assert "[cyan]> recon[/cyan](example.com)" in msg
        assert "[dim]found 2 hosts[/dim]" in msg

    def test_agent_action_without_result_omits_result_block(self) -> None:
        msg = format_step_message(_make_action(result=""))
        assert "[dim]" not in msg

    def test_agent_action_long_inputs_are_truncated(self) -> None:
        msg = format_step_message(_make_action(tool_input="x" * 500, result="y" * 1000))
        # tool_input clipped to 120 chars inside the parens
        assert "[cyan]> recon[/cyan](" + "x" * 120 + ")" in msg
        # result clipped to 300 chars inside [dim]...[/dim]
        assert msg.endswith("[dim]" + "y" * 300 + "[/dim]")

    def test_agent_finish_returns_answer_prefixed_truncation(self) -> None:
        finish = AgentFinish(thought="done", output="y" * 700, text="t")
        msg = format_step_message(finish)
        assert msg.startswith("[bold green]Answer:[/bold green] ")
        assert msg.count("y") == 500

    def test_other_step_type_returns_truncated_repr(self) -> None:
        msg = format_step_message("random output " + "z" * 500)
        assert msg.startswith("random output ")
        assert len(msg) == 300
