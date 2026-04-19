"""
tasks.py — Pipeline task wiring.

Delegates prompt loading and Task construction to each SquadMember class.
Context chaining lives here because it is a pipeline concern, not a per-member one.

CHECKPOINT_INDICES maps zero-based task indices to approval checkpoint names.
The crew's task_callback triggers the ApprovalGate after each indexed task.
"""

from __future__ import annotations

from crewai import Task

from squad.disclosure_coordinator import DisclosureCoordinator
from squad.osint_analyst import OsintAnalyst
from squad.penetration_tester import PenetrationTester
from squad.programme_manager import ProgrammeManager
from squad.technical_author import TechnicalAuthor
from squad.vulnerability_researcher import VulnerabilityResearcher

# Zero-based task index → checkpoint name.
# After task 0 (programme selection): operator approves initiating a scan.
# After task 4 (report writing): operator approves submitting to H1.
CHECKPOINT_INDICES: dict[int, str] = {
    0: "scan-approval",
    4: "submission-approval",
}


def build_tasks(agents: dict) -> list[Task]:
    select = ProgrammeManager.build_task(agents["programme_manager"])
    recon = OsintAnalyst.build_task(agents["osint_analyst"], context=[select])
    pentest = PenetrationTester.build_task(agents["penetration_tester"], context=[recon])
    triage = VulnerabilityResearcher.build_task(
        agents["vulnerability_researcher"], context=[pentest, select]
    )
    write = TechnicalAuthor.build_task(agents["technical_author"], context=[triage, select])
    submit = DisclosureCoordinator.build_task(agents["disclosure_coordinator"], context=[write])
    return [select, recon, pentest, triage, write, submit]
