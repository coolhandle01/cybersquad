"""
agents.py — Thin assembler: instantiates the LLM and builds all squad members.

The order of _SQUAD_MEMBERS controls which slugs appear in the returned dict
and (transitively) which agents are passed to tasks.py.
"""

from __future__ import annotations

from crewai import Agent
from langchain_anthropic import ChatAnthropic

from config import config
from squad import SquadMember
from squad.disclosure_coordinator import DisclosureCoordinator
from squad.osint_analyst import OsintAnalyst
from squad.penetration_tester import PenetrationTester
from squad.programme_manager import ProgrammeManager
from squad.technical_author import TechnicalAuthor
from squad.vulnerability_researcher import VulnerabilityResearcher

_SQUAD_MEMBERS: list[type[SquadMember]] = [
    ProgrammeManager,
    OsintAnalyst,
    PenetrationTester,
    VulnerabilityResearcher,
    TechnicalAuthor,
    DisclosureCoordinator,
]


def build_agents(verbose: bool = False) -> dict[str, Agent]:
    llm = ChatAnthropic(  # type: ignore[call-arg]
        model=config.llm.model,
        temperature=config.llm.temperature,
        max_tokens=config.llm.max_tokens,
    )
    return {m.slug: m.build_agent(llm, verbose) for m in _SQUAD_MEMBERS}
