"""Programme Manager — selects the highest-value H1 programme."""

from __future__ import annotations

from pathlib import Path

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


MEMBER = SquadMember(
    slug="programme_manager",
    dir=Path(__file__).parent,
    tools=[list_programmes_tool, get_scope_tool],
)
