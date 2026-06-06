"""
crewui - a Textual TUI for any sequential CrewAI crew.

``CrewAIPipelineTUI`` renders a sidebar task tracker (grouped into phases), an
agent output log, and a pipeline log for a CrewAI ``Crew``. It is framework-
generic: the only CrewAI types it touches are ``Crew`` and the step/task
callback contract. Anything application-specific - where a ``run_id`` is
recorded, how run metrics are computed and displayed - is injected via the two
``on_run_*`` callbacks, so the base class has no dependency on any host app.

Typical usage::

    from crewui import CrewAIPipelineTUI, PipelinePhase

    class MyTUI(CrewAIPipelineTUI):
        CSS_PATH = "my_app.tcss"  # optional - defaults to the bundled theme

        def __init__(self) -> None:
            super().__init__(
                crew=build_my_crew(),
                phases=[PipelinePhase(role="My Agent", label="Phase Label")],
                record_prefix="myapp",
            )

The ``phases`` sequence maps each agent role to the phase heading it appears
under in the sidebar; tasks whose role is absent fall back to their own role as
the heading. ``record_prefix`` selects which log records render in the agent
pane vs. the pipeline pane (records whose logger name starts with the prefix
are treated as agent output).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from crewai import Crew
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Input, Label, RichLog, Static

from crewui._helpers import (
    format_metrics_block,
    format_step_message,
    route_log_record,
    task_phase_layout,
    truncate,
)

__all__ = [
    "CrewAIPipelineTUI",
    "PipelinePhase",
    "format_metrics_block",
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelinePhase:
    """One entry in the sidebar flow panel: an agent role and its phase heading.

    ``role`` is the join key - it matches a task's ``agent.role`` in the crew,
    and is the text rendered for that row. ``phase`` is the heading the row is
    grouped under; consecutive rows sharing a ``phase`` render the heading once
    (see ``task_phase_layout``). Two tasks sharing an agent role therefore
    share a phase lookup - fine for one-task-per-agent crews.
    """

    role: str
    phase: str


def _noop_run_start(_run_id: str) -> None:
    """Default ``on_run_start``: record nothing."""


def _noop_run_complete(_result: object, _run_id: str, _started_at: datetime) -> str | None:
    """Default ``on_run_complete``: contribute no sidebar metrics block."""
    return None


class CrewAIPipelineTUI(App):
    # Host apps override CSS_PATH to theme the TUI; the bundled default ships a
    # usable dark theme so the base class is runnable as-is.
    CSS_PATH = "default.tcss"

    def __init__(
        self,
        crew: Crew,
        phases: Sequence[PipelinePhase] = (),
        record_prefix: str = "pipeline",
        verbose: bool = False,
        dry_run: bool = False,
        on_run_start: Callable[[str], None] = _noop_run_start,
        on_run_complete: Callable[[object, str, datetime], str | None] = _noop_run_complete,
    ) -> None:
        super().__init__()
        self._crew = crew
        self._phase_by_role = {p.role: p.phase for p in phases}
        self._record_prefix = record_prefix
        self._verbose = verbose
        self._dry_run = dry_run
        self._on_run_start = on_run_start
        self._on_run_complete = on_run_complete
        self._task_widgets: list[tuple[Label, Label]] = []
        self._task_names = [t.agent.role for t in self._crew.tasks if t.agent is not None]
        self._crew.step_callback = self._make_step_callback()

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label(self._record_prefix, id="sidebar-title")

                for phase, name in task_phase_layout(self._task_names, self._phase_by_role):
                    if phase is not None:
                        yield Label(phase, classes="phase-heading")
                    name_lbl = Label(name, classes="task-name")
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
                        placeholder="Human review input (not yet implemented)",
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
        else:
            self._start_run()

    @work(thread=True)
    def _start_run(self) -> None:
        run_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
        self._on_run_start(run_id)
        started_at = datetime.now(UTC)

        for i, task in enumerate(self._crew.tasks):
            orig: Callable[..., None] | None = task.callback
            task.callback = self._make_task_callback(i, orig)

        self.call_from_thread(self._set_task_running, 0)

        try:
            result = self._crew.kickoff()
            self.call_from_thread(self._on_done, result, run_id, started_at)
        except Exception as exc:
            self.call_from_thread(self._write_agent, f"[bold red]Pipeline error: {exc}[/bold red]")
            self.call_from_thread(self._write_crew, f"[bold red]Pipeline error: {exc}[/bold red]")

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

    def _on_done(self, result: object, run_id: str, started_at: datetime) -> None:
        raw = getattr(result, "raw", str(result))
        self._write_agent("[bold green]Pipeline complete.[/bold green]")
        self._write_agent(truncate(raw, 2000))

        metrics_block = self._on_run_complete(result, run_id, started_at)
        if metrics_block is None:
            return
        try:
            self.query_one("#metrics", Static).update(metrics_block)
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


class _TUILogHandler(logging.Handler):
    def __init__(self, app: CrewAIPipelineTUI) -> None:
        super().__init__()
        self._app = app

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        target = route_log_record(record.name, self._app._record_prefix)
        if target == "agent":
            self._app.call_from_thread(self._app._write_agent, msg)
        else:
            self._app.call_from_thread(self._app._write_crew, msg)
