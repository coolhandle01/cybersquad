"""
tasks.py — Pipeline task wiring for each campaign phase.

Phase → task set mapping:
  select_programme  — PM selects the next target programme (human gate)
  campaign_kickoff  — PM briefs the squad with sprint history (human gate)
  standup           — Hunt pipeline: OSINT → pentest → triage → write → submit
  campaign_review   — PM delivers sprint review to the operator (human gate)
  campaign_retro    — PM facilitates lessons-learned debrief (no gate)
"""

from __future__ import annotations

from crewai import Task

from squad.disclosure_coordinator import DisclosureCoordinator
from squad.osint_analyst import OsintAnalyst
from squad.penetration_tester import PenetrationTester
from squad.programme_manager import ProgrammeManager
from squad.technical_author import TechnicalAuthor
from squad.vulnerability_researcher import VulnerabilityResearcher


def build_tasks(agents: dict, phase: str = "standup") -> list[Task]:
    """Return the task list for the given campaign phase."""
    if phase == "select_programme":
        return [ProgrammeManager.build_task(agents["programme_manager"], human_input=True)]
    if phase == "campaign_kickoff":
        return [
            ProgrammeManager.build_task(
                agents["programme_manager"],
                prompt_file="kickoff.md",
                human_input=True,
            )
        ]
    if phase == "campaign_review":
        return [
            ProgrammeManager.build_task(
                agents["programme_manager"],
                prompt_file="review.md",
                human_input=True,
            )
        ]
    if phase == "campaign_retro":
        return [
            ProgrammeManager.build_task(
                agents["programme_manager"],
                prompt_file="retro.md",
            )
        ]
    return _build_standup_tasks(agents)


def _build_standup_tasks(agents: dict) -> list[Task]:
    """Hunt pipeline: OSINT → pentest → triage → write (human gate) → submit."""
    recon = OsintAnalyst.build_task(agents["osint_analyst"])
    pentest = PenetrationTester.build_task(agents["penetration_tester"], context=[recon])
    triage = VulnerabilityResearcher.build_task(
        agents["vulnerability_researcher"], context=[recon, pentest]
    )
    write = TechnicalAuthor.build_task(
        agents["technical_author"], context=[triage], human_input=True
    )
    submit = DisclosureCoordinator.build_task(agents["disclosure_coordinator"], context=[write])
    return [recon, pentest, triage, write, submit]
