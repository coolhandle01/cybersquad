"""OSINT Analyst — maps the in-scope attack surface."""

from __future__ import annotations

from crewai import Agent
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


class OsintAnalyst(SquadMember):
    slug = "osint_analyst"

    @classmethod
    def build_agent(cls, llm: object, verbose: bool = False) -> Agent:
        return Agent(
            role="OSINT Analyst",
            goal=(
                "Build a comprehensive, in-scope attack surface map for the target "
                "programme — subdomains, live endpoints, open ports, and technology "
                "stack — using only passive and semi-passive reconnaissance techniques."
            ),
            backstory=(
                "You are an OSINT specialist who has mapped the attack surfaces of "
                "hundreds of organisations. You are meticulous about staying within "
                "authorised scope, and you document everything with the precision of "
                "a cartographer. You know every subdomain enumeration trick in the book."
            ),
            tools=[recon_tool],
            allow_delegation=False,
            llm=llm,
            verbose=verbose,
        )
