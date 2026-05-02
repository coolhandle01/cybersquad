"""
tasks.py — Pipeline task wiring.

Context chaining lives here because it is a pipeline concern, not a per-member one.

human_input=True on a task tells CrewAI to pause after the agent finishes and
prompt the operator for feedback before advancing. Empty feedback (Enter) accepts
the result; typed feedback re-invokes the agent with that guidance.
"""

from __future__ import annotations

from crewai import Task

from squad import build_task
from squad.disclosure_coordinator import MEMBER as DISCLOSURE_COORDINATOR
from squad.osint_analyst import MEMBER as OSINT_ANALYST
from squad.penetration_tester import MEMBER as PENETRATION_TESTER
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER
from squad.technical_author import MEMBER as TECHNICAL_AUTHOR
from squad.vulnerability_researcher import MEMBER as VULNERABILITY_RESEARCHER


def build_tasks(agents: dict) -> list[Task]:
    # Pauses for operator review before any scanning begins.
    select = build_task(PROGRAMME_MANAGER, agents["programme_manager"], human_input=True)
    recon = build_task(OSINT_ANALYST, agents["osint_analyst"], context=[select])
    pentest = build_task(PENETRATION_TESTER, agents["penetration_tester"], context=[recon])
    triage = build_task(
        VULNERABILITY_RESEARCHER, agents["vulnerability_researcher"], context=[pentest, select]
    )
    # Pauses for operator review before the report is submitted to H1.
    write = build_task(
        TECHNICAL_AUTHOR, agents["technical_author"], context=[triage, select], human_input=True
    )
    submit = build_task(DISCLOSURE_COORDINATOR, agents["disclosure_coordinator"], context=[write])
    return [select, recon, pentest, triage, write, submit]
