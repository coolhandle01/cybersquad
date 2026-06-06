"""
squad/disclosure_coordinator/tools/submission.py - the report-submission surface.

The Disclosure Coordinator's two tools: ``Submit Report`` (IRREVERSIBLE -
publishes a finalised ``DisclosureReport`` to HackerOne) and ``Check H1
Duplicate`` (a last-chance fuzzy duplicate check against the programme's
existing reports before the irreversible POST).
"""

from pydantic import BaseModel, Field

import runtime
from models import ProgrammeReportSummary
from models.h1 import DisclosureReport, SubmissionResult
from squad import cyber_tool
from tools.h1_api import h1
from tools.report_tools import save_report


class _SubmitReportArgs(BaseModel):
    """Explicit args_schema for the Submit Report tool.

    IRREVERSIBLE: a successful call publishes a report to hackerone.com.
    Once filed the report is visible to the programme's triage team and
    cannot be silently retried - the field description below names the
    consequences the agent must reason about before calling.
    """

    report: DisclosureReport = Field(
        description=(
            "The fully-built ``DisclosureReport`` to submit. Built by the"
            " Technical Author and passed as a typed model - CrewAI"
            " serialises and re-validates against the ``DisclosureReport``"
            " schema upstream, so mis-shaped reports reject before the"
            " HTTP POST. IRREVERSIBLE: a successful submission publishes"
            " the report to hackerone.com and cannot be silently retried."
            " A well-shaped report with the wrong ``programme_handle``"
            " inside it files against the wrong target - a public scope"
            " violation the operator has to apologise for. Double-check"
            " ``programme_handle`` against the selected programme and"
            " verify ``title``, ``vulnerability.severity``,"
            " ``weakness_id``, and ``structured_scope_id`` - all four are"
            " submission-time authoritative; H1 records them verbatim and"
            " there is no quiet edit path."
        ),
    )


@cyber_tool("Submit Report", args_schema=_SubmitReportArgs)
def submit_report_tool(report: DisclosureReport) -> SubmissionResult:
    """Submit a DisclosureReport to HackerOne."""
    # The wrapper signature is DisclosureReport so the agent-facing
    # args_schema is typed, but CrewAI's args_schema.model_validate(...)
    # .model_dump() pass leaves the runtime value as a dict by the time
    # this body runs. model_validate accepts both shapes - it returns
    # the same DisclosureReport when given an instance and constructs
    # one when given a dict - so this is the both-shapes adapter.
    report = DisclosureReport.model_validate(report)
    save_report(report)
    return h1.submit_report(report)


class _CheckDuplicateArgs(BaseModel):
    """Explicit args_schema for the Check H1 Duplicate tool."""

    title: str = Field(
        description=(
            "Draft report title to fuzzy-match against existing reports on"
            " this programme. The first 30 characters (case-insensitive)"
            " are used as the substring needle, so phrase the title so its"
            " leading 30 characters are distinctive (target host or"
            " vulnerability class up front)."
        ),
    )


@cyber_tool("Check H1 Duplicate", args_schema=_CheckDuplicateArgs)
def check_duplicate_tool(title: str) -> list[ProgrammeReportSummary]:
    """
    Last-chance duplicate check before submission. Lists recent reports on this
    programme whose titles resemble the given title. A match means another
    researcher may have already submitted this finding.
    """
    reports = h1.list_reports(runtime.programme_handle, page_size=25)
    title_lower = title.lower()
    return [
        ProgrammeReportSummary(
            report_id=r.get("id"),
            title=r.get("attributes", {}).get("title"),
            state=r.get("attributes", {}).get("state"),
        )
        for r in reports
        if title_lower[:30] in (r.get("attributes", {}).get("title") or "").lower()
    ]
