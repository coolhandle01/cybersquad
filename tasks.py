"""
tasks.py - Pipeline task wiring.

Context chaining lives here because it is a pipeline concern, not a per-member one.

human_input=True on a task tells CrewAI to pause after the agent finishes and
prompt the operator for feedback before advancing. Empty feedback (Enter) accepts
the result; typed feedback re-invokes the agent with that guidance.

Set CYBERSQUAD_HUMAN_INPUT=false to disable all gates for unattended runs.
"""

from __future__ import annotations

from crewai import Agent, Task

from config import config
from squad import build_task
from squad.disclosure_coordinator import MEMBER as DISCLOSURE_COORDINATOR
from squad.guardrails import validate_select_output
from squad.osint_analyst import MEMBER as OSINT_ANALYST
from squad.penetration_tester import MEMBER as PENETRATION_TESTER
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER
from squad.technical_author import MEMBER as TECHNICAL_AUTHOR
from squad.vulnerability_researcher import MEMBER as VULNERABILITY_RESEARCHER


def build_tasks(agents: dict[str, Agent]) -> list[Task]:
    hi = config.human_input

    select = build_task(
        "select",
        PROGRAMME_MANAGER,
        agents["programme_manager"],
        human_input=hi,
        guardrail=validate_select_output,
        max_retries=2,
    )

    recon = build_task(
        "recon", OSINT_ANALYST, agents["osint_analyst"], context=[select], human_input=hi
    )

    research = build_task(
        "research",
        VULNERABILITY_RESEARCHER,
        agents["vulnerability_researcher"],
        context=[recon, select],
        human_input=hi,
    )

    pentest = build_task(
        "pentest",
        PENETRATION_TESTER,
        agents["penetration_tester"],
        context=[research, recon, select],
        human_input=hi,
    )

    triage = build_task(
        "triage",
        VULNERABILITY_RESEARCHER,
        agents["vulnerability_researcher"],
        context=[pentest, research, select],
        human_input=hi,
    )

    write = build_task(
        "write",
        TECHNICAL_AUTHOR,
        agents["technical_author"],
        context=[triage, select],
        human_input=hi,
    )

    submit = build_task(
        "submit",
        DISCLOSURE_COORDINATOR,
        agents["disclosure_coordinator"],
        context=[write],
        human_input=hi,
    )

    return [select, recon, research, pentest, triage, write, submit]
