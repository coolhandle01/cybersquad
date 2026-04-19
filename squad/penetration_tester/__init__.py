"""Penetration Tester — scans discovered attack surface for vulnerabilities."""

from __future__ import annotations

from crewai import Agent
from crewai.tools import tool

from squad import SquadMember
from tools.vuln_tools import run_pentest


@tool("Run Penetration Test")
def pentest_tool(recon_result_json: str) -> list[dict]:
    """
    Run nuclei, sqlmap, and custom checks against a serialised ReconResult.
    Returns a list of raw findings as dicts.
    """
    from models import ReconResult

    recon = ReconResult.model_validate_json(recon_result_json)
    findings = run_pentest(recon)
    return [f.model_dump() for f in findings]


class PenetrationTester(SquadMember):
    slug = "penetration_tester"

    @classmethod
    def build_agent(cls, llm: object, verbose: bool = False) -> Agent:
        return Agent(
            role="Penetration Tester",
            goal=(
                "Execute targeted vulnerability scans across the discovered attack "
                "surface, employing nuclei, sqlmap, and bespoke checks to surface "
                "exploitable weaknesses whilst respecting rate limits and scope boundaries."
            ),
            backstory=(
                "You are an offensive security engineer with certifications in OSCP, "
                "CREST CRT, and eWPT. You approach every engagement methodically — "
                "running the right tool for the right target — and you never fire a "
                "payload at an asset that is out of scope. You are efficient, precise, "
                "and deeply familiar with the OWASP Top 10."
            ),
            tools=[pentest_tool],
            allow_delegation=False,
            llm=llm,
            verbose=verbose,
        )
