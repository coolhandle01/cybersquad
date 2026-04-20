"""
crew.py — Assembles the Bounty Squad into a CrewAI Pipeline.

Call build_crew() to get a fully wired crew, then crew.kickoff() to run it.
"""

from __future__ import annotations

from crewai import LLM, Crew, Process

from config import config
from squad import SquadMember
from squad.disclosure_coordinator import DisclosureCoordinator
from squad.osint_analyst import OsintAnalyst
from squad.penetration_tester import PenetrationTester
from squad.programme_manager import ProgrammeManager
from squad.technical_author import TechnicalAuthor
from squad.vulnerability_researcher import VulnerabilityResearcher
from tasks import build_tasks

_SQUAD: list[type[SquadMember]] = [
    ProgrammeManager,
    OsintAnalyst,
    PenetrationTester,
    VulnerabilityResearcher,
    TechnicalAuthor,
    DisclosureCoordinator,
]


def build_crew(verbose: bool | None = None) -> Crew:
    """
    Instantiate agents and tasks, then wire them into a sequential Crew.

    Args:
        verbose: Override config.verbose for this run.
                 Defaults to the value in config.py.
    """
    be_verbose = verbose if verbose is not None else config.verbose

    llm = LLM(
        model=config.llm.model,
        temperature=config.llm.temperature,
        max_tokens=config.llm.max_tokens,
    )
    agents = {m.slug: m.build_agent(llm, be_verbose) for m in _SQUAD}
    tasks = build_tasks(agents)

    return Crew(
        agents=list(agents.values()),
        tasks=tasks,
        process=Process.sequential,
        verbose=be_verbose,
        memory=False,
        embedder=None,
    )
