"""
tasks.py — Pipeline task wiring.

Delegates prompt loading and Task construction to each SquadMember class.
Context chaining lives here because it is a pipeline concern, not a per-member one.

human_input=True on a task tells CrewAI to pause after the agent finishes and
prompt the operator for feedback before advancing. Empty feedback (Enter) accepts
the result; typed feedback re-invokes the agent with that guidance.
"""

from __future__ import annotations

from crewai import Task

from squad.disclosure_coordinator import DisclosureCoordinator
from squad.osint_analyst import OsintAnalyst
from squad.penetration_tester import PenetrationTester
from squad.programme_manager import ProgrammeManager
from squad.technical_author import TechnicalAuthor
from squad.vulnerability_researcher import VulnerabilityResearcher


def build_tasks(agents: dict) -> list[Task]:
    # Pauses for operator review before any scanning begins.
    select = ProgrammeManager.build_task(agents["programme_manager"], human_input=True)
    recon = OsintAnalyst.build_task(agents["osint_analyst"], context=[select])
    pentest = PenetrationTester.build_task(agents["penetration_tester"], context=[recon])
    triage = VulnerabilityResearcher.build_task(
        agents["vulnerability_researcher"], context=[pentest, select]
    )
    # Pauses for operator review before the report is submitted to H1.
    write = TechnicalAuthor.build_task(
        agents["technical_author"], context=[triage, select], human_input=True
    )
    submit = DisclosureCoordinator.build_task(agents["disclosure_coordinator"], context=[write])
    return [select, recon, pentest, triage, write, submit]
