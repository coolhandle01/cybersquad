"""Programme Manager — selects the highest-value H1 programme."""

from __future__ import annotations

from crewai import Agent
from crewai.tools import tool

from squad import SquadMember
from tools.h1_api import h1


@tool("List HackerOne Programmes")
def list_programmes_tool(page_size: int = 25) -> list[dict]:
    """Fetch and return a list of active HackerOne bug bounty programmes."""
    return h1.list_programmes(page_size=page_size)


@tool("Get Programme Scope")
def get_scope_tool(handle: str) -> dict:
    """Fetch the structured in-scope and out-of-scope assets for a programme."""
    policy = h1.get_programme_policy(handle)
    scope = h1.get_structured_scope(handle)
    return {"policy": policy, "scope": scope}


class ProgrammeManager(SquadMember):
    slug = "programme_manager"

    @classmethod
    def build_agent(cls, llm: object, verbose: bool = False) -> Agent:
        return Agent(
            role="Programme Manager",
            goal=(
                "Identify the highest-value HackerOne bug bounty programmes — "
                "maximising expected payout relative to attack surface complexity — "
                "whilst rigorously verifying that automated scanning is permitted."
            ),
            backstory=(
                "You are a seasoned security programme manager with a decade of "
                "experience prioritising vulnerability disclosure efforts across "
                "Fortune 500 clients. You have an encyclopaedic knowledge of "
                "HackerOne programme policies and a sharp eye for ROI. You never "
                "authorise work against a programme that prohibits automated tools."
            ),
            tools=[list_programmes_tool, get_scope_tool],
            allow_delegation=False,
            llm=llm,
            verbose=verbose,
        )
