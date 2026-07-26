"""
tests/test_tui_helpers.py - branch-coverage of the pure helpers extracted from
the CybersquadTUI class.

The Textual App / widget / threading layer in tools/tui/__init__.py needs a
textual.pilot harness to test (tracked separately); the helpers here are pure
functions so every conditional path can be exercised by ordinary unit tests.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from tools.tui import CybersquadTUI

import pytest
from crewai.agents.parser import AgentAction, AgentFinish

from tools.tui._helpers import (
    dispatch_on_ui_thread,
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


class TestDispatchOnUiThread:
    """Guards the human-review-gate crash: a log record emitted while already
    on the UI thread must dispatch directly, because Textual's
    ``call_from_thread`` refuses same-thread calls."""

    def test_same_thread_dispatches_directly(self) -> None:
        # Caller thread == the app's captured UI thread -> call fn directly.
        assert dispatch_on_ui_thread(42, 42) is True

    def test_worker_thread_uses_call_from_thread(self) -> None:
        # Caller thread != UI thread (a worker) -> bounce via call_from_thread.
        assert dispatch_on_ui_thread(7, 42) is False

    def test_unmounted_app_uses_call_from_thread(self) -> None:
        # Before on_mount captures the id there is no UI-thread code running.
        assert dispatch_on_ui_thread(42, None) is False


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
        block = format_metrics_block(total_tokens=12345, estimated_cost_usd=0.0418)
        assert " Tokens:  12,345" in block
        assert " Cost:    $0.0418" in block
        assert " Status:  done" in block
        assert "Run:" not in block

    def test_status_override_renders_custom_status(self) -> None:
        # The dry-run sidebar renders the block zeroed with a "dry run" status.
        block = format_metrics_block(total_tokens=0, estimated_cost_usd=0.0, status="dry run")
        assert " Tokens:  0" in block
        assert " Cost:    $0.0000" in block
        assert " Status:  dry run" in block


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


class TestThemeOwnership:
    """CybersquadTUI owns its default stylesheet. The path is absolute because
    Textual resolves a relative CSS_PATH against the concrete class's module
    file, so a derived class would otherwise look for it next to its own module.
    """

    def test_owns_absolute_default_stylesheet(self) -> None:
        from pathlib import Path

        from tools.tui import CybersquadTUI

        css = Path(CybersquadTUI.CSS_PATH)
        assert css.is_absolute()
        assert css.name == "default.tcss"
        assert css.is_file()


class TestHumanInputProvider:
    """The TUI's human-input provider routes CrewAI's feedback prompt to the
    app's input-box bridge (``_await_feedback``) instead of a terminal
    ``input()``. The threading/widget bridge itself needs a textual.pilot
    harness; this pins the routing seam, which is the load-bearing contract.
    """

    def test_prompt_input_delegates_to_app_bridge(self) -> None:
        from unittest.mock import MagicMock

        from tools.tui import _make_tui_human_input_provider

        app = MagicMock()
        app._await_feedback.return_value = "tighten the title"
        provider = _make_tui_human_input_provider(app)

        # crewai calls _prompt_input(crew) and, since 1.15.x, also passes the
        # answer under review as output_to_review. Both shapes must reach the
        # bridge unchanged; the review text is ignored (the step-callback
        # already streamed it into the agent-log pane).
        assert provider._prompt_input(crew=None) == "tighten the title"
        assert (
            provider._prompt_input(crew=None, output_to_review="The sky is blue.")
            == "tighten the title"
        )
        assert app._await_feedback.call_count == 2


class TestLogHandlerDispatch:
    """The log handler must hand every record to the app's thread-aware
    ``_ui_dispatch`` - never call ``call_from_thread`` directly - so a record
    emitted on the UI thread (the human-review gate) does not crash the run.
    """

    def test_agent_record_dispatched_via_ui_dispatch(self) -> None:
        from unittest.mock import MagicMock

        from tools.tui import _TUILogHandler

        app = MagicMock()
        app._record_prefix = "cybersquad"
        handler = _TUILogHandler(app)
        record = logging.LogRecord(
            "cybersquad.osint_analyst", logging.INFO, __file__, 1, "hi", None, None
        )

        handler.emit(record)

        app._ui_dispatch.assert_called_once_with(app._write_agent, "hi")
        app.call_from_thread.assert_not_called()

    def test_crew_record_routed_to_crew_pane(self) -> None:
        from unittest.mock import MagicMock

        from tools.tui import _TUILogHandler

        app = MagicMock()
        app._record_prefix = "cybersquad"
        handler = _TUILogHandler(app)
        record = logging.LogRecord(
            "urllib3.connectionpool", logging.INFO, __file__, 1, "noise", None, None
        )

        handler.emit(record)

        app._ui_dispatch.assert_called_once_with(app._write_crew, "noise")
        app.call_from_thread.assert_not_called()


class TestUiDispatch:
    """``_ui_dispatch`` picks the hand-off for the current thread: a caller on
    the UI thread calls the widget method directly (``call_from_thread`` would
    crash there), a worker-thread caller bounces through ``call_from_thread``.
    Exercised against a light stand-in so no Textual event loop is needed.
    """

    def test_direct_call_when_on_ui_thread(self) -> None:
        import threading

        from tools.tui import CybersquadTUI

        calls: list[tuple[str, str]] = []
        stub = SimpleNamespace(
            _ui_thread_id=threading.get_ident(),
            call_from_thread=lambda fn, msg: calls.append(("bounced", msg)),
        )

        CybersquadTUI._ui_dispatch(
            cast("CybersquadTUI", stub), lambda m: calls.append(("direct", m)), "hi"
        )

        assert calls == [("direct", "hi")]

    def test_bounces_through_call_from_thread_when_off_ui_thread(self) -> None:
        from tools.tui import CybersquadTUI

        calls: list[tuple[str, str]] = []
        stub = SimpleNamespace(
            _ui_thread_id=-1,  # never matches a real thread id
            call_from_thread=lambda fn, msg: calls.append(("bounced", msg)),
        )

        CybersquadTUI._ui_dispatch(
            cast("CybersquadTUI", stub), lambda m: calls.append(("direct", m)), "hi"
        )

        assert calls == [("bounced", "hi")]
