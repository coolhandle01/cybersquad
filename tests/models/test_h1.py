"""tests/models/test_h1.py - unit tests for models/h1.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    Severity,
)
from models.h1 import (
    DisclosureReport,
    Programme,
    ScopeItem,
    ScopeType,
    SubmissionResult,
    SubmissionStatus,
)

pytestmark = pytest.mark.unit


class TestScopeItem:
    def test_valid_url_scope_item(self, scope_item_url):
        assert scope_item_url.asset_type == ScopeType.URL
        assert scope_item_url.eligible_for_bounty is True

    def test_valid_wildcard_scope_item(self, scope_item_wildcard):
        assert scope_item_wildcard.asset_type == ScopeType.WILDCARD

    def test_instruction_defaults_to_none(self, target_apex):
        item = ScopeItem(
            asset_identifier=f"https://{target_apex}",
            asset_type=ScopeType.URL,
        )
        assert item.instruction is None

    def test_invalid_asset_type_raises(self, target_apex):
        with pytest.raises(ValidationError):
            ScopeItem(
                asset_identifier=f"https://{target_apex}",
                asset_type="not_a_real_type",
            )


class TestProgramme:
    def test_valid_programme(self, programme):
        assert programme.handle == "test-programme"
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
        from datetime import UTC, datetime

        result = SubmissionResult(
            report_id="12345",
            status=SubmissionStatus.SUBMITTED,
            h1_url="https://hackerone.com/reports/12345",
            submitted_at=datetime.now(UTC),
        )
        assert result.report_id == "12345"
        assert result.submitted_at is not None
