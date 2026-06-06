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


def _present(crew: Any, args: argparse.Namespace) -> None:  # noqa: ANN401 - decorator-wrapped Crew; tighter type buys nothing
    """Hand the built crew to the chosen surface, carrying the dry-run flag.

    Two surfaces, each holding its own dry-run mode: the headless CLI and the
    Textual TUI. The crew's MCP servers are live for the enclosing ``build_crew``
    block, which spans whichever runs here.
    """
    if args.headless:
        _run_headless(crew, verbose=args.verbose, dry_run=args.dry_run)
    else:
        _run_tui(crew, dry_run=args.dry_run)


def _new_run_id() -> str:
    """Return a fresh run identifier: UTC timestamp plus a short random suffix."""
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]


def _run_tui(crew: Any, *, dry_run: bool) -> None:  # noqa: ANN401 - decorator-wrapped Crew; tighter type buys nothing
    """Run, or on a dry run preview, the crew in the Textual TUI.

    The single TUI construction site. The TUI package knows only CrewAI +
    Textual; the cybersquad-specific bits - binding the run id, persisting run
    metrics, estimating USD cost - are passed in as callbacks, and the run id
    surfaces only as the human-readable ``pipeline_name`` title. On a dry run
    nothing kicks off, so the callbacks never fire and no run id is bound.
    """
    import runtime
    from config import config
    from tools.metrics import build_run_metrics, estimate_cost, save_metrics
    from tools.tui import CybersquadTUI

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

    if dry_run:
        pipeline_name = "Bug Bounty"
    else:
        runtime.bind_run_id(_new_run_id())
        pipeline_name = f"Bug Bounty #{runtime.run_id}"

    CybersquadTUI(
        crew=crew,
        record_prefix="cybersquad",
        pipeline_name=pipeline_name,
        dry_run=dry_run,
        on_start=on_start,
        on_complete=on_complete,
        get_token_cost=get_token_cost,
    ).run()


def _run_headless(crew: Any, *, verbose: bool, dry_run: bool) -> None:  # noqa: ANN401 - decorator-wrapped Crew; tighter type buys nothing
    """Kick off the crew on the CLI - or, on a dry run, print the pipeline and stop."""
    import runtime
    from config import config
    from tools.metrics import build_run_metrics, print_metrics, save_metrics

    if dry_run:
        console.rule("[bold cyan]Bounty Squad - dry run (pipeline not executed)[/bold cyan]")
        for i, task in enumerate(crew.tasks, start=1):
            heading = task.name or task.agent.role
            gate = "  [yellow](human review)[/yellow]" if task.human_input else ""
            console.print(f"{i}. [cyan]{heading}[/cyan] - {task.agent.role}{gate}")
        return

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
    # from config. build_crew opens the provisioned-MCP scope and yields a ready
    # crew; that scope spans the renderer (dry-run still provisions).
    from crew import build_crew

    with build_crew(verbose=args.verbose) as crew:
        _present(crew, args)


if __name__ == "__main__":
    main()
