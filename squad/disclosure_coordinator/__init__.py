"""Disclosure Coordinator — submits finalised reports to HackerOne."""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from squad import SquadMember
from tools.h1_api import h1
from tools.report_tools import save_report


@tool("Submit Report")
def submit_report_tool(report_json: str) -> dict:
    """Submit a serialised DisclosureReport to HackerOne."""
    from models import DisclosureReport

    report = DisclosureReport.model_validate_json(report_json)
    save_report(report)
    result = h1.submit_report(report)
    return result.model_dump()


MEMBER = SquadMember(
    slug="disclosure_coordinator",
    dir=Path(__file__).parent,
    tools=[submit_report_tool],
)
