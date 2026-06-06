"""
tools/tui/__init__.py - Generic CrewAI Pipeline TUI base class.

Provides CrewAIPipelineTUI, a Textual App that renders a sidebar task tracker,
an agent output log, and a pipeline log for any CrewAI sequential crew.

Typical usage in a host application::

    from tools.tui import CrewAIPipelineTUI

    class MyAppTUI(CrewAIPipelineTUI):
        CSS_PATH = "my_app.tcss"

        def __init__(self, verbose: bool = False) -> None:
            crew = build_my_crew(verbose=verbose)
            super().__init__(
                crew=crew,
                record_prefix="myapp",
                verbose=verbose,
            )

The sidebar reads each task's display name (``Task.name``) and agent role
straight off ``crew.tasks``, so a host app needs only to wire the crew - no
separate task map.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

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

logger = logging.getLogger(__name__)


class CrewAIPipelineTUI(App):
    # TODO: implement theming by allowing the client to pass in the path to a .tcss file
    CSS_PATH = ""

    def __init__(
        self,
        crew: Crew,
        record_prefix: str = "pipeline",
        verbose: bool = False,
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._crew = crew
        self._record_prefix = record_prefix
        self._verbose = verbose
        self._dry_run = dry_run
        self._task_widgets: list[tuple[Label, Label]] = []
        self._crew.step_callback = self._make_step_callback()

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label(self._record_prefix, id="sidebar-title")

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
        import runtime

        run_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
        runtime.run_id = run_id
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
        from config import config
        from tools.metrics import build_run_metrics, save_metrics

        raw = getattr(result, "raw", str(result))
        self._write_agent("[bold green]Pipeline complete.[/bold green]")
        self._write_agent(truncate(raw, 2000))

        usage = getattr(result, "token_usage", None)
        if usage is None:
            return

        try:
            metrics = build_run_metrics(
                run_id=run_id,
                started_at=started_at,
                llm_model=config.llm.model,
                input_tokens=getattr(usage, "prompt_tokens", 0),
                output_tokens=getattr(usage, "completion_tokens", 0),
            )
            save_metrics(metrics, config.reports_dir)
            self.query_one("#metrics", Static).update(
                format_metrics_block(
                    total_tokens=metrics.total_tokens,
                    estimated_cost_usd=metrics.estimated_cost_usd,
                    run_id=run_id,
                )
            )
        except OSError as exc:
            self._write_crew(f"[yellow]Metrics error: {exc}[/yellow]")
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
