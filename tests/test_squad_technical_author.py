"""
tests/test_squad_technical_author.py - exercise the @tool wrappers on the
Technical Author.

The wrappers are thin: unmarshal JSON, call into tools/* helpers, serialise
the result. Coverage here is regression coverage of the wrapping itself; the
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.fixtures.findings import draft_report_kwargs
from tests.fixtures.programme import stage_models_json

pytestmark = pytest.mark.unit


class TestTechnicalAuthorTools:
    def test_draft_report_tool_writes_draft_and_returns_validation(
        self, verified_vuln, run_dir
    ) -> None:
        from squad.technical_author import draft_report_tool
        from tools.report_tools import ReportDraftResult

        stage_models_json(run_dir, "verified.json", verified_vuln)
        result = draft_report_tool.func(**draft_report_kwargs())

        assert isinstance(result, ReportDraftResult)
        assert result.validation.ok is True
        assert (run_dir / "drafts" / "000.json").exists()

    def test_draft_report_tool_surfaces_validation_issues(self, verified_vuln, run_dir) -> None:
        from squad.technical_author import draft_report_tool
        from tools.report_tools import ReportDraftResult

        stage_models_json(run_dir, "verified.json", verified_vuln)
        result = draft_report_tool.func(**draft_report_kwargs(title="bad title"))

        assert isinstance(result, ReportDraftResult)
        assert result.validation.ok is False
        sections = {i.section for i in result.validation.issues}
        assert "title" in sections

    def test_draft_report_tool_rejects_out_of_range_index(self, verified_vuln, run_dir) -> None:
        from squad.technical_author import draft_report_tool

        stage_models_json(run_dir, "verified.json", verified_vuln)
        with pytest.raises(ValueError, match="out of range"):
            draft_report_tool.func(**draft_report_kwargs(finding_index=5))

    def test_finalise_reports_tool_consolidates_drafts(self, verified_vuln, run_dir) -> None:
        from squad.technical_author import draft_report_tool, finalise_reports_tool

        stage_models_json(run_dir, "verified.json", verified_vuln)
        with patch("runtime.programme_handle", "acme"):
            draft_report_tool.func(**draft_report_kwargs())
            result = finalise_reports_tool.func("Session summary line.")

        assert result == "reports.json"
        assert (run_dir / "reports.json").exists()

    def test_finalise_reports_tool_raises_on_unresolved_errors(
        self, verified_vuln, run_dir
    ) -> None:
        from squad.technical_author import draft_report_tool, finalise_reports_tool

        stage_models_json(run_dir, "verified.json", verified_vuln)
        with patch("runtime.programme_handle", "acme"):
            draft_report_tool.func(**draft_report_kwargs(title="bad title"))
            with pytest.raises(ValueError, match="unresolved errors"):
                finalise_reports_tool.func("Summary.")

    def test_sanitise_evidence_tool_returns_redactions(self) -> None:
        from squad.technical_author import sanitise_evidence_tool
        from tools.report_tools import SanitisationReport

        result = sanitise_evidence_tool.func("Authorization: Bearer abc.def.ghi")
        assert isinstance(result, SanitisationReport)
        assert "Bearer abc.def.ghi" not in result.sanitised
        assert result.redactions

    def test_lookup_cwe_tool_finds_known_class(self) -> None:
        from models import CWE
        from squad.technical_author import lookup_cwe_tool

        result = lookup_cwe_tool.func(89)
        assert isinstance(result, list)
        assert result
        assert isinstance(result[0], CWE)
        assert result[0].cwe_id == 89
        assert "cwe.mitre.org" in result[0].url

    def test_lookup_cwe_tool_empty_for_unknown(self) -> None:
        from squad.technical_author import lookup_cwe_tool

        assert lookup_cwe_tool.func(999999) == []

    def test_lookup_owasp_tool_returns_cheatsheet(self) -> None:
        from squad.technical_author import lookup_owasp_tool
        from tools.owasp_data import OWASPEntry

        result = lookup_owasp_tool.func("sql injection")
        assert isinstance(result, list)
        assert result
        assert all(isinstance(r, OWASPEntry) for r in result)
        assert any("SQL_Injection_Prevention" in r.url for r in result)

    def test_calculate_cvss_tool(self) -> None:
        from squad.technical_author import calculate_cvss_tool

        with patch(
            "squad.technical_author.calculate_cvss_score",
            return_value=8.8,
        ) as m:
            result = calculate_cvss_tool.func("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        assert result == 8.8
        m.assert_called_once_with("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_list_programme_reports_tool(self) -> None:
        from models import ProgrammeReportSummary
        from squad.technical_author import list_programme_reports_tool

        h1_reports = [
            {
                "id": "1",
                "attributes": {
                    "title": "Existing report",
                    "severity_rating": "high",
                    "state": "triaged",
                },
            }
        ]
        with (
            patch("runtime.programme_handle", "acme"),
            patch("squad.technical_author.h1.list_reports", return_value=h1_reports) as mlist,
        ):
            result = list_programme_reports_tool.func(page_size=10)

        assert result == [
            ProgrammeReportSummary(
                report_id="1",
                title="Existing report",
                severity="high",
                state="triaged",
            )
        ]
        mlist.assert_called_once_with("acme", page_size=10)
