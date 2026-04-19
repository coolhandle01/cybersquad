"""
main.py — Bounty Squad pipeline entrypoint.

Usage:
    python main.py                  # single run, settings from .env / env vars
    python main.py --verbose        # verbose LLM output
    python main.py --dry-run        # build crew & print task graph, don't execute
    python main.py --no-approval    # skip human checkpoints (automated/CI use)

Environment variables (see config.py for full list):
    H1_API_USERNAME     HackerOne API username         (required)
    H1_API_TOKEN        HackerOne API token             (required)
    CREWAI_MODEL        LLM model identifier            (see .env.example)
    H1_MIN_BOUNTY       Minimum bounty threshold USD    (default: 500)
    MIN_SEVERITY        Minimum finding severity        (default: medium)
    REPORTS_DIR         Local report output directory   (default: ./reports)
    HUMAN_APPROVAL      Pause for human review          (default: true)
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

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.DEBUG if os.getenv("VERBOSE", "").lower() == "true" else logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("bounty_squad")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bounty Squad — autonomous bug bounty pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable per-step LLM output")
    parser.add_argument(
        "--dry-run", action="store_true", help="Print the task graph without executing"
    )
    parser.add_argument(
        "--no-approval",
        action="store_true",
        help="Skip human approval checkpoints (overrides HUMAN_APPROVAL env var)",
    )
    return parser.parse_args()


def check_env() -> None:
    """Fail fast if required environment variables are missing."""
    missing = [v for v in ("H1_API_USERNAME", "H1_API_TOKEN") if not os.getenv(v)]
    if missing:
        logger.error("Missing required environment variables: %s", ", ".join(missing))
        logger.error("Set them in your environment or in a .env file.")
        sys.exit(1)


def dry_run_summary(crew: Any) -> None:  # noqa: ANN401
    """Print a human-readable summary of the crew without executing."""
    print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  BOUNTY SQUAD — DRY RUN  ")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    print("AGENTS")
    for agent in crew.agents:
        tools = [t.name for t in agent.tools] if agent.tools else ["(none)"]
        print(f"  • {agent.role:<30} tools: {', '.join(tools)}")
    print("\nTASKS (sequential)")
    for i, task in enumerate(crew.tasks, 1):
        hitl = " [HUMAN APPROVAL]" if getattr(task, "human_input", False) else ""
        print(f"  {i}. [{task.agent.role}]{hitl}")
        print(f"     {task.description[:80].strip()}…")
    print()


def main() -> None:
    args = parse_args()
    check_env()

    # Override HUMAN_APPROVAL when --no-approval flag is passed
    if args.no_approval:
        os.environ["HUMAN_APPROVAL"] = "false"

    # Import crew after env check and after env override
    from config import config
    from crew import build_crew
    from tools.metrics import build_run_metrics, print_metrics, save_metrics

    crew = build_crew(verbose=args.verbose)

    if args.dry_run:
        dry_run_summary(crew)
        return

    run_id = datetime.utcnow().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
    started_at = datetime.utcnow()

    logger.info("Bounty Squad — pipeline starting  (run: %s)", run_id)
    logger.info(
        "Model: %s | Min bounty: $%s | Min severity: %s | Human approval: %s",
        config.llm.model,
        config.h1.min_bounty_threshold,
        config.scan.min_severity,
        config.human_approval,
    )

    try:
        result = crew.kickoff()
        logger.info("Pipeline complete.")

        print("\n" + "━" * 50)
        print("FINAL OUTPUT")
        print("━" * 50)
        print(result)

        # Capture token usage from CrewOutput (available in crewai >= 0.28)
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
            logger.debug("CrewOutput has no token_usage — metrics not available for this run")

    except KeyboardInterrupt:
        logger.warning("Pipeline interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        logger.exception("Pipeline failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
