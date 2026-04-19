"""
tasks.py — Pipeline task wiring.

Delegates prompt loading and Task construction to each SquadMember class.
Context chaining lives here because it is a pipeline concern, not a per-member one.
"""

from __future__ import annotations

from crewai import Task

from squad.disclosure_coordinator import DisclosureCoordinator
from squad.osint_analyst import OsintAnalyst
from squad.penetration_tester import PenetrationTester
from squad.programme_manager import ProgrammeManager
from squad.technical_author import TechnicalAuthor
from squad.vulnerability_researcher import VulnerabilityResearcher


def build_tasks(agents: dict, human_approval: bool = False) -> list[Task]:
    select = ProgrammeManager.build_task(agents["programme_manager"])
    # Checkpoint 1: human reviews selected programme and approves scanning
    recon = OsintAnalyst.build_task(
        agents["osint_analyst"], context=[select], human_input=human_approval
    )
    pentest = PenetrationTester.build_task(agents["penetration_tester"], context=[recon])
    triage = VulnerabilityResearcher.build_task(
        agents["vulnerability_researcher"], context=[pentest, select]
    )
    # Checkpoint 2: human reads draft report and approves submission
    write = TechnicalAuthor.build_task(
        agents["technical_author"], context=[triage, select], human_input=human_approval
    )
    submit = DisclosureCoordinator.build_task(agents["disclosure_coordinator"], context=[write])
    return [select, recon, pentest, triage, write, submit]
