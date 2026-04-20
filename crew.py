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

_PM_SQUAD: list[type[SquadMember]] = [ProgrammeManager]
_HUNT_SQUAD: list[type[SquadMember]] = [
    OsintAnalyst,
    PenetrationTester,
    VulnerabilityResearcher,
    TechnicalAuthor,
    DisclosureCoordinator,
]


def build_crew(phase: str = "standup", verbose: bool | None = None) -> Crew:
    """
    Instantiate agents and tasks, then wire them into a sequential Crew.

    Args:
        phase:   Campaign phase to build tasks for.
                 Defaults to "standup" (full hunt pipeline).
        verbose: Override config.verbose for this run.
                 Defaults to the value in config.py.
    """
    be_verbose = verbose if verbose is not None else config.verbose

    llm = LLM(
        model=config.llm.model,
        temperature=config.llm.temperature,
        max_tokens=config.llm.max_tokens,
    )

    squad = _HUNT_SQUAD if phase == "standup" else _PM_SQUAD
    agents = {m.slug: m.build_agent(llm, be_verbose) for m in squad}
    tasks = build_tasks(agents, phase=phase)

    return Crew(
        agents=list(agents.values()),
        tasks=tasks,
        process=Process.sequential,
        verbose=be_verbose,
        memory=False,
        embedder=None,
    )
