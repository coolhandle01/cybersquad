"""
tests/test_models.py — unit tests for models.py
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    DisclosureReport,
    Endpoint,
    Programme,
    RawFinding,
    ReconResult,
    ScopeItem,
    ScopeType,
    Severity,
    SubmissionResult,
    SubmissionStatus,
    VerifiedVulnerability,
)

pytestmark = pytest.mark.unit


class TestSeverityEnum:
    def test_all_values_present(self):
        levels = {s.value for s in Severity}
        assert levels == {"informational", "low", "medium", "high", "critical"}

    def test_severity_is_string_enum(self):
        assert isinstance(Severity.HIGH, str)
        assert Severity.HIGH == "high"


class TestScopeItem:
    def test_valid_url_scope_item(self, scope_item_url):
        assert scope_item_url.asset_type == ScopeType.URL
        assert scope_item_url.eligible_for_bounty is True

    def test_valid_wildcard_scope_item(self, scope_item_wildcard):
        assert scope_item_wildcard.asset_type == ScopeType.WILDCARD

    def test_instruction_defaults_to_none(self):
        item = ScopeItem(
            asset_identifier="https://example.com",
            asset_type=ScopeType.URL,
        )
        assert item.instruction is None

    def test_invalid_asset_type_raises(self):
        with pytest.raises(ValidationError):
            ScopeItem(
                asset_identifier="https://example.com",
                asset_type="not_a_real_type",
            )


class TestProgramme:
    def test_valid_programme(self, programme):
        assert programme.handle == "test-programme"
        assert programme.allows_automated_scanning is True
        assert Severity.HIGH in programme.bounty_table

    def test_priority_score_defaults_to_zero(self, programme):
        assert programme.priority_score == 0.0

    def test_selected_at_is_set(self, programme):
        assert programme.selected_at is not None

    def test_serialise_roundtrip(self, programme):
        data = programme.model_dump()
        restored = Programme.model_validate(data)
        assert restored.handle == programme.handle
        assert restored.bounty_table == programme.bounty_table


class TestEndpoint:
    def test_valid_endpoint(self, endpoint):
        assert endpoint.status_code == 200
        assert "nginx" in endpoint.technologies

    def test_optional_fields_default(self):
        ep = Endpoint(url="https://example.com")
        assert ep.status_code is None
        assert ep.technologies == []
        assert ep.parameters == []


class TestReconResult:
    def test_valid_recon_result(self, recon_result):
        assert len(recon_result.subdomains) == 2
        assert len(recon_result.endpoints) == 1

    def test_completed_at_is_set(self, recon_result):
        assert recon_result.completed_at is not None

    def test_serialise_roundtrip(self, recon_result):
        json_str = recon_result.model_dump_json()
        restored = ReconResult.model_validate_json(json_str)
        assert restored.programme.handle == recon_result.programme.handle
        assert len(restored.endpoints) == len(recon_result.endpoints)


class TestRawFinding:
    def test_valid_finding(self, raw_finding_high):
        assert raw_finding_high.vuln_class == "SQLi"
        assert raw_finding_high.severity_hint == Severity.HIGH

    def test_severity_defaults_to_medium(self):
        finding = RawFinding(
            title="Test",
            vuln_class="XSS",
            target="https://example.com",
            evidence="payload reflected",
            tool="nuclei",
        )
        assert finding.severity_hint == Severity.MEDIUM


class TestVerifiedVulnerability:
    def test_valid_verified_vuln(self, verified_vuln):
        assert verified_vuln.in_scope is True
        assert verified_vuln.cvss_score == 8.8
        assert len(verified_vuln.steps_to_reproduce) == 3

    def test_confirmed_at_is_set(self, verified_vuln):
        assert verified_vuln.confirmed_at is not None

    def test_serialise_roundtrip(self, verified_vuln):
        json_str = verified_vuln.model_dump_json()
        restored = VerifiedVulnerability.model_validate_json(json_str)
        assert restored.cvss_vector == verified_vuln.cvss_vector


class TestDisclosureReport:
    def test_valid_report(self, disclosure_report):
        assert disclosure_report.programme_handle == "test-programme"
        assert disclosure_report.weakness_id == 89

    def test_attachments_default_empty(self, disclosure_report):
        assert disclosure_report.attachments == []

    def test_serialise_roundtrip(self, disclosure_report):
        json_str = disclosure_report.model_dump_json()
        restored = DisclosureReport.model_validate_json(json_str)
        assert restored.title == disclosure_report.title


class TestSubmissionResult:
    def test_default_status_is_pending(self):
        result = SubmissionResult()
        assert result.status == SubmissionStatus.PENDING
        assert result.report_id is None

    def test_successful_submission(self):
        from datetime import datetime

        result = SubmissionResult(
            report_id="12345",
            status=SubmissionStatus.SUBMITTED,
            h1_url="https://hackerone.com/reports/12345",
            submitted_at=datetime.utcnow(),
        )
        assert result.report_id == "12345"
        assert result.submitted_at is not None
