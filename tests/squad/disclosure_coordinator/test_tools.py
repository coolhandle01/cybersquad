"""
Behavioural tests for the Disclosure Coordinator's @tool wrappers.

The wrappers are thin: deserialise inputs, call into tools/* helpers,
return the result. Coverage here is regression coverage of the
wrapping itself; the underlying helpers are exercised in their own
dedicated test files. The args_schema contract for the same tools
lives in the sibling ``test_args_schemas.py``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestDisclosureCoordinatorTools:
    def test_submit_report_tool(self, disclosure_report) -> None:
        from models.h1 import SubmissionResult, SubmissionStatus
        from squad.disclosure_coordinator import submit_report_tool

        submission = SubmissionResult(report_id="h1-42", status=SubmissionStatus.SUBMITTED)

        with (
            patch("squad.disclosure_coordinator.tools.submission.save_report") as msave,
            patch(
                "squad.disclosure_coordinator.tools.submission.h1.submit_report",
                return_value=submission,
            ) as msub,
        ):
            # The wrapper takes a typed DisclosureReport; the body's
            # model_validate handles either a model instance or the dict
            # CrewAI hands it after args_schema validation.
            result = submit_report_tool.func(disclosure_report)

        assert result == submission
        msave.assert_called_once()
        msub.assert_called_once()

    def test_submit_report_tool_accepts_dict(self, disclosure_report) -> None:
        """CrewAI hands the wrapper a dict after args_schema validation; the
        both-shapes adapter must accept that too."""
        from models.h1 import SubmissionResult, SubmissionStatus
        from squad.disclosure_coordinator import submit_report_tool

        submission = SubmissionResult(report_id="h1-42", status=SubmissionStatus.SUBMITTED)

        with (
            patch("squad.disclosure_coordinator.tools.submission.save_report"),
            patch(
                "squad.disclosure_coordinator.tools.submission.h1.submit_report",
                return_value=submission,
            ),
        ):
            result = submit_report_tool.func(disclosure_report.model_dump())

        assert result == submission

    def test_check_duplicate_tool(self) -> None:
        from squad.disclosure_coordinator import check_duplicate_tool

        reports = [
            {
                "id": "1",
                "attributes": {"title": "SQL Injection in search", "state": "open"},
            },
        ]
        with (
            patch("runtime.programme_handle", "acme"),
            patch(
                "squad.disclosure_coordinator.tools.submission.h1.list_reports",
                return_value=reports,
            ),
        ):
            result = check_duplicate_tool.func("SQL Injection in search")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].title == "SQL Injection in search"
        assert result[0].report_id == "1"
