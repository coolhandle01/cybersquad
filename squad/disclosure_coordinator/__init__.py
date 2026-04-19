"""Disclosure Coordinator — submits finalised reports to HackerOne."""

from __future__ import annotations

from crewai import Agent
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


class DisclosureCoordinator(SquadMember):
    slug = "disclosure_coordinator"

    @classmethod
    def build_agent(cls, llm: object, verbose: bool = False) -> Agent:
        return Agent(
            role="Disclosure Coordinator",
            goal=(
                "Submit finalised disclosure reports to HackerOne via the API, "
                "confirm successful receipt, and log submission metadata for "
                "tracking and follow-up."
            ),
            backstory=(
                "You are a disclosure coordinator who has managed the responsible "
                "disclosure lifecycle for over 300 vulnerabilities. You are calm "
                "under pressure, precise with API payloads, and you maintain "
                "meticulous records of every submission status. Nothing slips "
                "through your process."
            ),
            tools=[submit_report_tool],
            allow_delegation=False,
            llm=llm,
            verbose=verbose,
        )
