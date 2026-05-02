"""OSINT Analyst — maps the in-scope attack surface."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from squad import SquadMember
from tools.h1_api import h1
from tools.recon_tools import run_recon


@tool("Run Recon")
def recon_tool(programme_handle: str) -> dict:
    """
    Run full OSINT recon (subdomain enumeration, HTTP probing, port scanning)
    against the in-scope assets of the given programme handle.
    Returns a serialised ReconResult.
    """
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    programme = h1.parse_programme(policy["data"], scope)
    result = run_recon(programme)
    return result.model_dump()


MEMBER = SquadMember(
    slug="osint_analyst",
    dir=Path(__file__).parent,
    tools=[recon_tool],
)
