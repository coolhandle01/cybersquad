"""
tests/test_tui_helpers.py - branch-coverage of the pure helpers extracted from
the CrewAIPipelineTUI class.

The Textual App / widget / threading layer in tools/tui/__init__.py needs a
textual.pilot harness to test (tracked separately); the helpers here are pure
functions so every conditional path can be exercised by ordinary unit tests.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from crewai.agents.parser import AgentAction, AgentFinish

from tools.tui._helpers import (
    format_metrics_block,
    format_step_message,
    route_log_record,
    task_layout,
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


def _task(name: str | None, role: str | None) -> SimpleNamespace:
    """Stand-in for a crewai.Task: only ``.name`` and ``.agent.role`` are read
    by ``task_layout``. ``role=None`` models a task with no assigned agent."""
    agent = SimpleNamespace(role=role) if role is not None else None
    return SimpleNamespace(name=name, agent=agent)


class TestTaskLayout:
    def test_empty_input_yields_empty_layout(self) -> None:
        assert task_layout([]) == []

    def test_uses_task_name_as_heading_and_role_as_row(self) -> None:
        assert task_layout([_task("Reconnaissance", "osint_analyst")]) == [
            ("Reconnaissance", "osint_analyst")
        ]

    def test_one_agent_two_tasks_keep_distinct_headings(self) -> None:
        # The VR runs research then triage: same role, distinct per-task names.
        layout = task_layout(
            [
                _task("Vulnerability Research", "vulnerability_researcher"),
                _task("Findings Triage", "vulnerability_researcher"),
            ]
        )
        assert layout == [
            ("Vulnerability Research", "vulnerability_researcher"),
            ("Findings Triage", "vulnerability_researcher"),
        ]

    def test_missing_name_falls_back_to_role(self) -> None:
        # A task with no name (None) uses the agent role as the heading.
        assert task_layout([_task(None, "programme_manager")]) == [
            ("programme_manager", "programme_manager")
        ]

    def test_task_without_agent_is_skipped(self) -> None:
        layout = task_layout([_task("Orphan", None), _task("Recon", "osint_analyst")])
        assert layout == [("Recon", "osint_analyst")]


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


class TestCybersquadTUIWrapper:
    """Cover tui.py's CybersquadTUI - the cybersquad-specific binding of the
    generic CrewAIPipelineTUI. The Textual App itself needs textual.pilot to
    exercise meaningfully; here we only verify that the wrapper passes
    build_crew() output, record_prefix='cybersquad', and the verbose/dry_run
    flags through to the base class init. The sidebar reads task names and
    roles off the crew, so there is no task map to forward.
    """

    def test_wires_crew_prefix_and_flags(self) -> None:
        from unittest.mock import MagicMock

        captured: dict[str, object] = {}

        def fake_base_init(self, **kw):
            captured.update(kw)

        fake_crew = MagicMock(tasks=[])

        with (
            patch("crew.build_crew", return_value=fake_crew) as mb,
            patch("tools.tui.CrewAIPipelineTUI.__init__", new=fake_base_init),
        ):
            from tui import CybersquadTUI

            CybersquadTUI(verbose=True, dry_run=False)

        mb.assert_called_once_with(verbose=True, mcp_tools=None)
        assert captured["crew"] is fake_crew
        assert "task_map" not in captured
        assert captured["record_prefix"] == "cybersquad"
        assert captured["verbose"] is True
        assert captured["dry_run"] is False

    def test_forwards_mcp_tools_to_build_crew(self) -> None:
        from unittest.mock import MagicMock

        captured: dict[str, object] = {}

        def fake_base_init(self, **kw):
            captured.update(kw)

        fake_crew = MagicMock(tasks=[])
        sentinel_mcp = MagicMock(name="provisioned_mcp_registry")

        with (
            patch("crew.build_crew", return_value=fake_crew) as mb,
            patch("tools.tui.CrewAIPipelineTUI.__init__", new=fake_base_init),
        ):
            from tui import CybersquadTUI

            CybersquadTUI(verbose=False, mcp_tools=sentinel_mcp)

        mb.assert_called_once_with(verbose=False, mcp_tools=sentinel_mcp)
