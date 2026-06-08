"""
tools/tui/__init__.py - Cybersquad's Textual TUI for the CrewAI pipeline.

CybersquadTUI is a Textual App that renders a sidebar task tracker, an agent
output log, and a pipeline log for the squad's sequential crew. ``main.py``
builds the crew inside the provisioned-MCP scope and hands it in, so the TUI
stays out of crew construction and MCP provisioning.

The package depends only on ``crewai`` and ``textual``. Live metrics come
straight from CrewAI (token usage off ``kickoff()``'s result); everything
cybersquad-specific is delegated to injected callbacks, so nothing here reaches
up into ``runtime`` / ``config`` / ``tools.metrics``:

- ``on_start()`` - fired in the worker thread right before kickoff (e.g. to
  bind a run id and stamp the start time)
- ``on_complete(result)`` - fired right after kickoff (e.g. to persist run
  metrics)
- ``get_token_cost(input_tokens, output_tokens)`` - returns the USD estimate to
  display; cost is not a CrewAI metric, so the host supplies it

Human review (``Task(human_input=True)``) is handled by routing CrewAI's
feedback prompt to the input box instead of a blocking terminal ``input()`` -
see ``_make_tui_human_input_provider`` and ``_await_feedback``.

The class owns a default theme (``CSS_PATH`` below); a derived class ships its
own look by setting its own ``CSS_PATH``.

The sidebar title is the host-supplied ``pipeline_name``; ``record_prefix`` is
used only to route log records to the agent vs pipeline pane. The sidebar reads
each task's display name (``Task.name``) and agent role straight off
``crew.tasks``, so the caller only wires the crew - no separate task map.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from crewai import Crew
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Input, Label, RichLog, Static

from tools.tui._helpers import (
    format_metrics_block,
    format_step_message,
    route_log_record,
    task_layout,
    truncate,
)

if TYPE_CHECKING:
    from crewai.core.providers.human_input import SyncHumanInputProvider

logger = logging.getLogger(__name__)


class CybersquadTUI(App):
    # The class owns the default theme. Absolute (not the bare "default.tcss")
    # because Textual resolves a relative CSS_PATH against the *concrete*
    # class's module file - so a derived class would otherwise look for the
    # stylesheet next to its own module. A derived class overrides the theme
    # by setting its own CSS_PATH.
    CSS_PATH = str(Path(__file__).parent / "default.tcss")

    def __init__(
        self,
        crew: Crew,
        record_prefix: str = "pipeline",
        pipeline_name: str = "",
        dry_run: bool = False,
        on_start: Callable[[], None] | None = None,
        on_complete: Callable[[object], None] | None = None,
        get_token_cost: Callable[[int, int], float] | None = None,
    ) -> None:
        super().__init__()
        self._crew = crew
        self._record_prefix = record_prefix
        self._pipeline_name = pipeline_name
        self._dry_run = dry_run
        self._on_start = on_start
        self._on_complete = on_complete
        self._get_token_cost = get_token_cost
        self._task_widgets: list[tuple[Label, Label]] = []
        # Human-review bridge: the worker thread parks on this event while the
        # operator types feedback into the input box on the UI thread.
        self._feedback_event: threading.Event | None = None
        self._feedback_value: str = ""
        self._crew.step_callback = self._make_step_callback()

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label(self._pipeline_name, id="sidebar-title")

                for heading, role in task_layout(self._crew.tasks):
                    yield Label(heading, classes="phase-heading")
                    name_lbl = Label(role, classes="task-name")
                    status_lbl = Label("Waiting", classes="task-status")
                    self._task_widgets.append((name_lbl, status_lbl))
                    yield name_lbl
                    yield status_lbl

                yield Static("", id="metrics")

            with Vertical(id="main"):
                with Vertical(id="messages-pane"):
                    yield Label("Agent Output", classes="pane-title")
                    yield RichLog(id="agent-log", highlight=True, markup=True, wrap=True)
                    yield Input(
                        placeholder="Human review (idle)",
                        disabled=True,
                        id="human-input",
                    )
                with Vertical(id="logs-pane"):
                    yield Label("Pipeline Logs", id="logs-title", classes="pane-title")
                    yield RichLog(id="crew-log", highlight=True, markup=True)

    def on_mount(self) -> None:
        logging.getLogger().addHandler(_TUILogHandler(self))
        if self._dry_run:
            self._write_crew("[yellow]Dry run mode: pipeline not started.[/yellow]")
            # Render the metrics block zeroed so the sidebar reads as a complete
            # preview rather than a blank panel - no run happened, so the
            # figures are zero and the status says so.
            self.query_one("#metrics", Static).update(
                format_metrics_block(total_tokens=0, estimated_cost_usd=0.0, status="dry run")
            )
        else:
            self._start_run()

    @work(thread=True)
    def _start_run(self) -> None:
        from crewai.core.providers.human_input import reset_provider, set_provider

        if self._on_start is not None:
            self._on_start()

        for i, task in enumerate(self._crew.tasks):
            orig: Callable[..., None] | None = task.callback
            task.callback = self._make_task_callback(i, orig)

        self.call_from_thread(self._set_task_running, 0)

        # Route CrewAI's human_input feedback prompt to the input box instead of
        # a blocking terminal input(). Set in this (worker) thread so kickoff's
        # get_provider() - same thread - picks it up; reset when the run ends.
        token = set_provider(_make_tui_human_input_provider(self))
        try:
            result = self._crew.kickoff()
            self.call_from_thread(self._on_done, result)
        except Exception as exc:
            self.call_from_thread(self._write_agent, f"[bold red]Pipeline error: {exc}[/bold red]")
            self.call_from_thread(self._write_crew, f"[bold red]Pipeline error: {exc}[/bold red]")
        finally:
            reset_provider(token)

    def _make_task_callback(
        self, idx: int, orig: Callable[..., None] | None
    ) -> Callable[..., None]:
        def _cb(output: object) -> None:
            self.call_from_thread(self._set_task_done, idx)
            if orig is not None:
                orig(output)

        return _cb

    def _make_step_callback(self) -> Callable[[object], None]:
        def _cb(step: object) -> None:
            try:
                msg = format_step_message(step)
            except Exception as exc:
                logger.debug("step callback error: %s", exc)
                return
            self.call_from_thread(self._write_agent, msg)

        return _cb

    def _set_task_running(self, idx: int) -> None:
        if idx < len(self._task_widgets):
            name_lbl, status_lbl = self._task_widgets[idx]
            name_lbl.add_class("running")
            status_lbl.add_class("running")
            status_lbl.update("Running...")

    def _set_task_done(self, idx: int) -> None:
        if idx < len(self._task_widgets):
            name_lbl, status_lbl = self._task_widgets[idx]
            name_lbl.remove_class("running")
            name_lbl.add_class("done")
            status_lbl.remove_class("running")
            status_lbl.add_class("done")
            status_lbl.update("Done")
        next_idx = idx + 1
        if next_idx < len(self._task_widgets):
            self._set_task_running(next_idx)

    def _on_done(self, result: object) -> None:
        raw = getattr(result, "raw", str(result))
        self._write_agent("[bold green]Pipeline complete.[/bold green]")
        self._write_agent(truncate(raw, 2000))

        # Hand the result to the host for persistence; a save failure must not
        # take the UI down, so swallow and surface it in the pipeline log.
        if self._on_complete is not None:
            try:
                self._on_complete(result)
            except Exception as exc:
                logger.debug("on_complete callback error: %s", exc)
                self._write_crew(f"[yellow]Metrics error: {exc}[/yellow]")

        usage = getattr(result, "token_usage", None)
        if usage is None:
            return

        input_tokens = getattr(usage, "prompt_tokens", 0)
        output_tokens = getattr(usage, "completion_tokens", 0)
        cost = self._get_token_cost(input_tokens, output_tokens) if self._get_token_cost else 0.0
        try:
            self.query_one("#metrics", Static).update(
                format_metrics_block(
                    total_tokens=getattr(usage, "total_tokens", input_tokens + output_tokens),
                    estimated_cost_usd=cost,
                )
            )
        except NoMatches:
            logger.debug("metrics widget not mounted")

    def _write_agent(self, msg: str) -> None:
        try:
            self.query_one("#agent-log", RichLog).write(msg)
        except NoMatches:
            logger.debug("agent-log widget not mounted, dropping message")

    def _write_crew(self, msg: str) -> None:
        try:
            self.query_one("#crew-log", RichLog).write(msg)
        except NoMatches:
            logger.debug("crew-log widget not mounted, dropping message")

    # ── human review ──────────────────────────────────────────────────

    def _await_feedback(self) -> str:
        """Worker-thread side of the human-review gate.

        Opens the input box on the UI thread, parks until the operator submits,
        then returns what they typed. Empty (just Enter) means "accept", per
        CrewAI's feedback loop.
        """
        self._feedback_event = threading.Event()
        self._feedback_value = ""
        self.call_from_thread(self._open_feedback_gate)
        self._feedback_event.wait()
        return self._feedback_value

    def _open_feedback_gate(self) -> None:
        self._write_agent(
            "[bold yellow]Human review requested - reply below (Enter to accept).[/bold yellow]"
        )
        inp = self.query_one("#human-input", Input)
        inp.placeholder = "Your feedback - Enter to accept, or type changes"
        inp.disabled = False
        inp.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "human-input" or self._feedback_event is None:
            return
        self._feedback_value = event.value
        event.input.value = ""
        event.input.disabled = True
        event.input.placeholder = "Human review (idle)"
        self._feedback_event.set()


def _make_tui_human_input_provider(app: CybersquadTUI) -> SyncHumanInputProvider:
    """Build a CrewAI human-input provider that routes the feedback prompt to
    the TUI input box instead of a blocking terminal ``input()``.

    Isolated here, with a deferred import, because it leans on crewai's
    semi-internal provider API (``crewai.core.providers.human_input``). That is
    the sanctioned injection point but may move between versions - this is the
    one place to fix if it does. ``result`` is accepted (newer crewai passes the
    answer under review) but unused: the step-callback already streams that
    answer into the agent-log pane before the gate opens.
    """
    from crewai.core.providers.human_input import SyncHumanInputProvider

    class _TUIHumanInputProvider(SyncHumanInputProvider):
        @staticmethod
        def _prompt_input(crew: Crew | None = None, result: str = "") -> str:
            return app._await_feedback()

    return _TUIHumanInputProvider()


class _TUILogHandler(logging.Handler):
    def __init__(self, app: CybersquadTUI) -> None:
        super().__init__()
        self._app = app

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        target = route_log_record(record.name, self._app._record_prefix)
        if target == "agent":
            self._app.call_from_thread(self._app._write_agent, msg)
        else:
            self._app.call_from_thread(self._app._write_crew, msg)
