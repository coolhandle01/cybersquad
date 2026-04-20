"""
main.py — Bounty Squad pipeline entrypoint.

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
from datetime import datetime
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
        description="Bounty Squad — autonomous bug bounty pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable per-step LLM output")
    parser.add_argument("--dry-run", action="store_true", help="Show crew layout without executing")
    return parser.parse_args()


def check_env() -> None:
    """Fail fast if required environment variables are missing."""
    missing = [v for v in ("H1_API_USERNAME", "H1_API_TOKEN") if not os.getenv(v)]
    if missing:
        logger.error("Missing required environment variables: %s", ", ".join(missing))
        logger.error("Set them in your environment or in a .env file.")
        sys.exit(1)


def dry_run_summary(crew: Any) -> None:  # noqa: ANN401
    """Render the crew layout as rich tables without executing."""
    console.rule("[bold cyan]BOUNTY SQUAD — DRY RUN[/bold cyan]")
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
        review_cell = "[yellow]▶ pauses for feedback[/yellow]" if task.human_input else ""
        tasks_table.add_row(
            str(i + 1),
            task.agent.role,
            task.description[:72].strip() + "…",
            review_cell,
        )
    console.print(Panel(tasks_table, title="Pipeline  [dim](sequential)[/dim]"))
    console.print()


def main() -> None:
    args = parse_args()
    check_env()

    # Import crew after env check
    from config import config
    from crew import build_crew
    from tools.metrics import build_run_metrics, print_metrics, save_metrics

    crew = build_crew(verbose=args.verbose)

    if args.dry_run:
        dry_run_summary(crew)
        return

    run_id = datetime.utcnow().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
    started_at = datetime.utcnow()

    console.rule("[bold]Bounty Squad[/bold]")
    logger.info(
        "run=%s  model=%s  min_bounty=$%s  min_severity=%s",
        run_id,
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

        try:
            usage = result.token_usage  # type: ignore[union-attr]
            metrics = build_run_metrics(
                run_id=run_id,
                started_at=started_at,
                llm_model=config.llm.model,
                input_tokens=getattr(usage, "prompt_tokens", 0),
                output_tokens=getattr(usage, "completion_tokens", 0),
            )
            print_metrics(metrics)
            save_metrics(metrics, config.reports_dir)
        except AttributeError:
            logger.debug("token_usage not available on this CrewOutput")

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)
    except Exception:
        console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
