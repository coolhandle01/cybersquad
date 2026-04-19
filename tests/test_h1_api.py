"""
tests/test_h1_api.py — unit tests for tools/h1_api.py

All HTTP calls are mocked — no real H1 API calls made.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from models import (
    ScopeType,
    Severity,
    SubmissionStatus,
)

pytestmark = pytest.mark.unit


@pytest.fixture()
def h1_client(monkeypatch):
    monkeypatch.setenv("H1_API_USERNAME", "testuser")
    monkeypatch.setenv("H1_API_TOKEN", "testtoken")
    import importlib

    import tools.h1_api as h1_module

    importlib.reload(h1_module)
    return h1_module.H1Client()


# ── parse_programme ───────────────────────────────────────────────────────────


class TestParseProgramme:
    def _raw_programme(self):
        return {
            "attributes": {
                "handle": "acme",
                "name": "Acme Corp",
                "policy": "We allow automated scanning with care.",
                "bounty_table": {
                    "data": [
                        {"attributes": {"label": "high", "maximum_amount": 2000}},
                        {"attributes": {"label": "critical", "maximum_amount": 5000}},
                    ]
                },
            }
        }

    def _raw_scope(self, eligible=True):
        return {
            "data": [
                {
                    "attributes": {
                        "asset_identifier": "*.acme.com",
                        "asset_type": "WILDCARD",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": eligible,
                        "instruction": None,
                    }
                }
            ]
        }

    def test_parses_handle_and_name(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.handle == "acme"
        assert prog.name == "Acme Corp"

    def test_parses_bounty_table(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.bounty_table[Severity.HIGH] == 2000
        assert prog.bounty_table[Severity.CRITICAL] == 5000

    def test_allows_automated_scanning_true(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.allows_automated_scanning is True

    def test_allows_automated_scanning_false_when_prohibited(self, h1_client):
        raw = self._raw_programme()
        raw["attributes"]["policy"] = "No automated scanning is permitted on this programme."
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.allows_automated_scanning is False

    def test_in_scope_items_parsed(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope(eligible=True))
        assert len(prog.in_scope) == 1
        assert prog.in_scope[0].asset_type == ScopeType.WILDCARD

    def test_out_of_scope_items_separated(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope(eligible=False))
        assert len(prog.in_scope) == 0
        assert len(prog.out_of_scope) == 1


# ── submit_report ─────────────────────────────────────────────────────────────


class TestSubmitReport:
    def test_successful_submission(self, h1_client, disclosure_report):
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"id": "999"}}
        mock_response.raise_for_status = MagicMock()

        with patch.object(h1_client._session, "post", return_value=mock_response):
            result = h1_client.submit_report(disclosure_report)

        assert result.report_id == "999"
        assert result.status == SubmissionStatus.SUBMITTED
        assert result.h1_url == "https://hackerone.com/reports/999"
        assert result.submitted_at is not None

    def test_submission_payload_uses_id_not_attributes(self, h1_client, disclosure_report):
        """Regression: payload previously used attributes:{handle:} → 422."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"id": "999"}}
        mock_response.raise_for_status = MagicMock()

        with patch.object(h1_client._session, "post", return_value=mock_response) as mock_post:
            h1_client.submit_report(disclosure_report)

        payload = mock_post.call_args.kwargs["json"]
        relationship = payload["data"]["relationships"]["program"]["data"]
        assert "id" in relationship
        assert "attributes" not in relationship
        assert relationship["id"] == disclosure_report.programme_handle

    def test_http_error_returns_pending(self, h1_client, disclosure_report):
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            response=MagicMock(text="Unauthorized")
        )

        with patch.object(h1_client._session, "post", return_value=mock_response):
            result = h1_client.submit_report(disclosure_report)

        assert result.status == SubmissionStatus.PENDING
        assert result.error is not None
        assert result.report_id is None

    def test_get_report_status_maps_states(self, h1_client):
        for h1_state, expected in [
            ("new", SubmissionStatus.SUBMITTED),
            ("triaged", SubmissionStatus.TRIAGED),
            ("resolved", SubmissionStatus.RESOLVED),
            ("duplicate", SubmissionStatus.DUPLICATE),
        ]:
            mock_response = MagicMock()
            mock_response.json.return_value = {"data": {"attributes": {"state": h1_state}}}
            mock_response.raise_for_status = MagicMock()

            with patch.object(h1_client._session, "get", return_value=mock_response):
                status = h1_client.get_report_status("12345")

            assert status == expected, f"State '{h1_state}' should map to {expected}"


class TestListProgrammes:
    def test_paginates_until_max(self, h1_client):
        page1 = {
            "data": [{"id": f"p{i}", "attributes": {"handle": f"h{i}"}} for i in range(5)],
            "links": {"next": "/programs?page=2"},
        }
        page2 = {
            "data": [{"id": f"p{i}", "attributes": {"handle": f"h{i}"}} for i in range(5, 10)],
            "links": {},
        }
        responses = [MagicMock(), MagicMock()]
        responses[0].json.return_value = page1
        responses[1].json.return_value = page2
        for r in responses:
            r.raise_for_status = MagicMock()

        with patch.object(h1_client._session, "get", side_effect=responses):
            result = h1_client.list_programmes(page_size=5)

        assert len(result) <= 10
        assert result[0]["id"] == "p0"

    def test_get_programme_policy_hits_endpoint(self, h1_client):
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"attributes": {"handle": "acme"}}}
        mock_response.raise_for_status = MagicMock()

        with patch.object(h1_client._session, "get", return_value=mock_response) as mock_get:
            result = h1_client.get_programme_policy("acme")

        assert result == {"data": {"attributes": {"handle": "acme"}}}
        assert "/programs/acme" in mock_get.call_args[0][0]

    def test_get_structured_scope_hits_endpoint(self, h1_client):
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(h1_client._session, "get", return_value=mock_response) as mock_get:
            result = h1_client.get_structured_scope("acme")

        assert result == {"data": []}
        assert "/programs/acme/structured_scopes" in mock_get.call_args[0][0]
