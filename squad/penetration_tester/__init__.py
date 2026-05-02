"""Penetration Tester — scans discovered attack surface for vulnerabilities."""

from __future__ import annotations

from pathlib import Path

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


MEMBER = SquadMember(
    slug="penetration_tester",
    dir=Path(__file__).parent,
    tools=[pentest_tool],
)
