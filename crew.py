"""
crew.py — Assembles the Bounty Squad into a CrewAI Pipeline.

Call build_crew() to get a fully wired crew, then crew.kickoff() to run it.
"""

from __future__ import annotations

from crewai import Crew, Process

from agents import build_agents
from config import config
from tasks import build_tasks


def build_crew(verbose: bool | None = None) -> Crew:
    """
    Instantiate agents and tasks, then wire them into a sequential Crew.

    Args:
        verbose: Override config.verbose for this run.
                 Defaults to the value in config.py.
    """
    be_verbose = verbose if verbose is not None else config.verbose

    agents = build_agents(verbose=be_verbose)
    tasks = build_tasks(agents)

    return Crew(
        agents=list(agents.values()),
        tasks=tasks,
        process=Process.sequential,
        verbose=be_verbose,
        memory=False,
        embedder=None,
    )


# FIX: removed module-level `crew = build_crew()` — it ran at import time,
# triggering env reads before main.py's check_env() had a chance to validate
# required credentials and exit cleanly. Callers must use build_crew() directly.
