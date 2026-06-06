"""
main.py - Bounty Squad pipeline entrypoint.

Usage:
    python main.py             # single run, settings from .env / env vars
    python main.py --verbose   # verbose LLM output
    python main.py --dry-run   # show crew layout without executing

Environment variables (see config.py for full list):
    H1_API_USERNAME     HackerOne API username         (required)
    H1_API_TOKEN        HackerOne API token             (required)
    CREWAI_MODEL        LLM model identifier            (see .env.example)
    H1_MIN_BOUNTY       Minimum bounty threshold USD    (default: 500)
    MIN_SEVERITY        Minimum finding severity        (default: medium)
    REPORTS_DIR         Local report output directory   (default: ./reports)
    VERBOSE             Enable verbose LLM output       (default: false)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

console = Console()

logging.basicConfig(
    level=logging.DEBUG if os.getenv("VERBOSE", "").lower() == "true" else logging.INFO,
    format="%(message)s",
    datefmt="[%H:%M:%S]",
    handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
)
logger = logging.getLogger("bounty_squad")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bounty Squad - autonomous bug bounty pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable per-step LLM output")
    parser.add_argument("--dry-run", action="store_true", help="Show crew layout without executing")
    parser.add_argument("--headless", action="store_true", help="Run without the Textual TUI")
    return parser.parse_args()


def check_env() -> None:
    """Fail fast if required environment variables are missing."""
    missing = [v for v in ("H1_API_USERNAME", "H1_API_TOKEN") if not os.getenv(v)]
    if missing:
        logger.error("Missing required environment variables: %s", ", ".join(missing))
        logger.error("Set them in your environment or in a .env file.")
        sys.exit(1)


def dry_run_summary(crew: Any) -> None:  # noqa: ANN401 - Crew is decorator-wrapped by the time the CLI sees it; tighter type buys nothing
    """Render the crew layout as rich tables without executing."""
    console.rule("[bold cyan]BOUNTY SQUAD - DRY RUN[/bold cyan]")
    console.print()

    agents_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    agents_table.add_column("Agent", style="cyan")
    agents_table.add_column("Tools", style="dim")
    for agent in crew.agents:
        tools = ", ".join(t.name for t in agent.tools) if agent.tools else "(none)"
        agents_table.add_row(agent.role, tools)
    console.print(Panel(agents_table, title="Agents"))

    console.print()

    tasks_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tasks_table.add_column("#", style="dim", width=3)
    tasks_table.add_column("Agent", style="cyan")
    tasks_table.add_column("Task")
    tasks_table.add_column("Human review")
    for i, task in enumerate(crew.tasks):
        review_cell = "[yellow]> pauses for feedback[/yellow]" if task.human_input else ""
        tasks_table.add_row(
            str(i + 1),
            task.agent.role,
            task.description[:72].strip() + "...",
            review_cell,
        )
    console.print(Panel(tasks_table, title="Pipeline  [dim](sequential)[/dim]"))
    console.print()


def _present(crew: Any, args: argparse.Namespace) -> None:  # noqa: ANN401 - already-built, decorator-wrapped Crew; see dry_run_summary
    """Dispatch an already-built crew to the chosen renderer.

    One place decides among the three modes - dry-run preview, headless run,
    Textual TUI - so ``main()`` keeps a single run-scope and a single exit. On
    a non-dry run the crew's MCP servers are live for the enclosing
    ``build_pipeline`` block, which spans whichever renderer runs here.
    """
    if args.dry_run:
        _render_dry_run(crew, headless=args.headless)
    elif args.headless:
        _run_headless(crew, verbose=args.verbose)
    else:
        _run_tui(crew, verbose=args.verbose)


def _new_run_id() -> str:
    """Return a fresh run identifier: UTC timestamp plus a short random suffix."""
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]


def _run_tui(crew: Any, *, verbose: bool) -> None:  # noqa: ANN401 - decorator-wrapped Crew; see dry_run_summary
    """Run the crew in the Textual TUI, injecting cybersquad's run lifecycle.

    The TUI package knows only CrewAI + Textual; the cybersquad-specific bits -
    binding the run id, persisting run metrics, estimating USD cost - are passed
    in as callbacks. Token usage for the live display is read off CrewAI inside
    the TUI itself.
    """
    import runtime
    from config import config
    from tools.metrics import build_run_metrics, estimate_cost, save_metrics
    from tools.tui import CybersquadTUI

    runtime.bind_run_id(_new_run_id())
    # Seeded so a freakishly fast run can't race on_start; on_start overwrites
    # it right before kickoff for an accurate duration.
    state: dict[str, datetime] = {"started_at": datetime.now(UTC)}

    def on_start() -> None:
        state["started_at"] = datetime.now(UTC)

    def on_complete(result: object) -> None:
        usage = getattr(result, "token_usage", None)
        if usage is None:
            return
        metrics = build_run_metrics(
            run_id=runtime.run_id,
            started_at=state["started_at"],
            llm_model=config.llm.model,
            input_tokens=getattr(usage, "prompt_tokens", 0),
            output_tokens=getattr(usage, "completion_tokens", 0),
        )
        save_metrics(metrics, config.reports_dir)

    def get_token_cost(input_tokens: int, output_tokens: int) -> float:
        return estimate_cost(config.llm.model, input_tokens, output_tokens)

    CybersquadTUI(
        crew=crew,
        record_prefix="cybersquad",
        run_id=runtime.run_id,
        verbose=verbose,
        on_start=on_start,
        on_complete=on_complete,
        get_token_cost=get_token_cost,
    ).run()


def _render_dry_run(crew: Any, *, headless: bool) -> None:  # noqa: ANN401 - decorator-wrapped Crew; see dry_run_summary
    """Show the crew layout without executing it.

    Rich tables on the CLI; the TUI sidebar (with a zeroed metrics block)
    otherwise. Neither kicks off - ``build_pipeline`` still provisions the MCP
    servers (a dry run is about not executing tasks, not skipping provisioning),
    they just go unused here.
    """
    if headless:
        dry_run_summary(crew)
    else:
        from tools.tui import CybersquadTUI

        CybersquadTUI(crew=crew, record_prefix="cybersquad", dry_run=True).run()


def _run_headless(crew: Any, *, verbose: bool) -> None:  # noqa: ANN401 - decorator-wrapped Crew; see dry_run_summary
    """Kick off the crew on the CLI and report its result and run metrics."""
    import runtime
    from config import config
    from tools.metrics import build_run_metrics, print_metrics, save_metrics

    runtime.bind_run_id(_new_run_id())
    started_at = datetime.now(UTC)

    console.rule("[bold]Bounty Squad[/bold]")
    logger.info(
        "run=%s  model=%s  min_bounty=$%s  min_severity=%s",
        runtime.run_id,
        config.llm.model,
        config.h1.min_bounty_threshold,
        config.scan.min_severity,
    )

    try:
        result = crew.kickoff()
        console.print()
        console.print(
            Panel(
                str(result),
                title="[bold green]  Result  [/bold green]",
                border_style="green",
                padding=(1, 2),
            )
        )
        usage = getattr(result, "token_usage", None)
        if usage is not None:
            metrics = build_run_metrics(
                run_id=runtime.run_id,
                started_at=started_at,
                llm_model=config.llm.model,
                input_tokens=getattr(usage, "prompt_tokens", 0),
                output_tokens=getattr(usage, "completion_tokens", 0),
            )
            print_metrics(metrics)
            save_metrics(metrics, config.reports_dir)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)
    except Exception:
        console.print_exception()
        sys.exit(1)


def main() -> None:
    args = parse_args()
    check_env()

    # Deferred until after check_env so a run missing required credentials
    # fails with check_env's clear message rather than an import-time error
    # from config. build_pipeline opens the provisioned-MCP scope and yields a
    # ready crew; that scope spans the renderer (dry-run still provisions - it
    # just doesn't kick off).
    from crew import build_pipeline

    with build_pipeline(verbose=args.verbose) as crew:
        _present(crew, args)


if __name__ == "__main__":
    main()
