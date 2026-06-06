"""
tests/tools/test_h1_api.py - unit tests for tools/h1_api.py

All HTTP calls are mocked - no real H1 API calls made.

These tests cover the HACKER API (/hackers/* endpoints), not the customer API
(/programs). Endpoint path assertions explicitly require the /hackers/ prefix
so a regression back to customer endpoints will fail immediately.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from models import Severity
from models.h1 import ScopeType, SubmissionStatus

pytestmark = pytest.mark.unit


@pytest.fixture()
def h1_client(monkeypatch):
    monkeypatch.setenv("H1_API_USERNAME", "testuser")
    monkeypatch.setenv("H1_API_TOKEN", "testtoken")
    import importlib

    import tools.h1_api as h1_module

    importlib.reload(h1_module)
    return h1_module.H1Client()


# parse_programme
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

    def test_policy_text_preserved(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert "automated scanning" in prog.policy_text.lower()

    def test_no_automated_scanning_shortcut_field(self, h1_client):
        # The PM reads policy_text directly; the boolean shortcut was removed
        # because the keyword heuristic missed real prohibitions.
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert not hasattr(prog, "allows_automated_scanning")

    def test_in_scope_items_parsed(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope(eligible=True))
        assert len(prog.in_scope) == 1
        assert prog.in_scope[0].asset_type == ScopeType.WILDCARD

    def test_out_of_scope_items_separated(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope(eligible=False))
        assert len(prog.in_scope) == 0
        assert len(prog.out_of_scope) == 1

    def test_offers_bounties_false_when_vdp(self, h1_client):
        raw = self._raw_programme()
        raw["attributes"]["offers_bounties"] = False
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.offers_bounties is False

    def test_offers_bounties_defaults_true_when_missing(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.offers_bounties is True

    def test_accepts_new_reports_false_when_closed(self, h1_client):
        raw = self._raw_programme()
        raw["attributes"]["submission_state"] = "closed"
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.accepts_new_reports is False

    def test_accepts_new_reports_true_when_open(self, h1_client):
        raw = self._raw_programme()
        raw["attributes"]["submission_state"] = "open"
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.accepts_new_reports is True

    def test_accepts_new_reports_defaults_true_when_missing(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.accepts_new_reports is True

    def test_state_extracted_verbatim(self, h1_client):
        # The PM agent reads state directly to reason about access; the value
        # is surfaced raw so prompt updates do not have to chase a Python-side
        # enum of accepted values. "private_mode" matches the value already
        # asserted in TestGetProgrammeStats - the only non-public state value
        # grounded in code; other invite-only states await a captured response.
        raw = self._raw_programme()
        raw["attributes"]["state"] = "private_mode"
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.state == "private_mode"

    def test_state_none_when_missing(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.state is None

    def test_parses_response_efficiency_pct(self, h1_client):
        raw = self._raw_programme()
        raw["attributes"]["response_efficiency_percentage"] = 87.5
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.response_efficiency_pct == 87.5

    def test_parses_avg_time_to_bounty_days(self, h1_client):
        raw = self._raw_programme()
        # 2880 minutes = 2 days exactly
        raw["attributes"]["average_time_to_bounty_in_minutes"] = 2880
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.avg_time_to_bounty_days == 2.0

    def test_avg_time_to_bounty_days_none_when_missing(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.avg_time_to_bounty_days is None

    def test_parses_total_bounties_paid_usd(self, h1_client):
        raw = self._raw_programme()
        raw["attributes"]["total_bounties_paid_in_cents"] = 1_500_000
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.total_bounties_paid_usd == 15_000

    def test_total_bounties_paid_usd_none_when_missing(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.total_bounties_paid_usd is None

    def test_parses_scope_item_max_severity(self, h1_client):
        scope = {
            "data": [
                {
                    "attributes": {
                        "asset_identifier": "api.acme.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                        "instruction": None,
                        "max_severity": "medium",
                    }
                }
            ]
        }
        prog = h1_client.parse_programme(self._raw_programme(), scope)
        assert prog.in_scope[0].max_severity == Severity.MEDIUM

    def test_scope_item_max_severity_none_when_missing(self, h1_client):
        prog = h1_client.parse_programme(self._raw_programme(), self._raw_scope())
        assert prog.in_scope[0].max_severity is None

    def test_policy_text_stored_on_programme(self, h1_client):
        raw = self._raw_programme()
        raw["attributes"]["policy"] = "Automated scanning is permitted with rate limiting."
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert "Automated scanning is permitted" in prog.policy_text

    def test_policy_text_empty_string_when_missing(self, h1_client):
        raw = self._raw_programme()
        raw["attributes"].pop("policy", None)
        prog = h1_client.parse_programme(raw, self._raw_scope())
        assert prog.policy_text == ""


# submit_report
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
        """Regression: payload previously used attributes:{handle:} -> 422."""
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

        with patch.object(h1_client._session, "get", side_effect=responses) as mock_get:
            result = h1_client.list_programmes(page_size=5)

        assert len(result) <= 10
        assert result[0]["id"] == "p0"
        assert "/hackers/programs" in mock_get.call_args_list[0][0][0]

    def test_get_programme_policy_hits_endpoint(self, h1_client):
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"attributes": {"handle": "acme"}}}
        mock_response.raise_for_status = MagicMock()

        with patch.object(h1_client._session, "get", return_value=mock_response) as mock_get:
            result = h1_client.get_programme_policy("acme")

        assert result == {"data": {"attributes": {"handle": "acme"}}}
        assert "/hackers/programs/acme" in mock_get.call_args[0][0]

    def test_get_structured_scope_hits_endpoint(self, h1_client):
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(h1_client._session, "get", return_value=mock_response) as mock_get:
            result = h1_client.get_structured_scope("acme")

        assert result == {"data": []}
        assert "/hackers/programs/acme/structured_scopes" in mock_get.call_args[0][0]

    def test_get_programme_detail_uses_include_params(self, h1_client):
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {}, "included": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(h1_client._session, "get", return_value=mock_response) as mock_get:
            h1_client.get_programme_detail("acme")

        assert "/hackers/programs/acme" in mock_get.call_args[0][0]
        params = mock_get.call_args[1]["params"]
        assert params == {"include": "bounty_table,structured_scopes"}


class TestBrowseProgrammes:
    """browse_programmes returns lightweight previews from the list endpoint
    only - no per-programme detail fetch."""

    def _list_resp(self, programmes, next_link: str | None = None):
        return {
            "data": [
                {
                    "id": handle,
                    "attributes": attrs,
                }
                for handle, attrs in programmes
            ],
            "links": {"next": next_link} if next_link else {},
        }

    def test_returns_one_preview_per_programme_no_detail_fetch(self, h1_client):
        list_payload = self._list_resp(
            [
                ("acme", {"handle": "acme", "name": "Acme", "offers_bounties": True}),
                ("beta", {"handle": "beta", "name": "Beta", "offers_bounties": False}),
            ]
        )
        with patch.object(h1_client, "_get", side_effect=[list_payload]) as m:
            previews = h1_client.browse_programmes()
        assert [p.handle for p in previews] == ["acme", "beta"]
        assert previews[0].offers_bounties is True
        assert previews[1].offers_bounties is False
        # Critical: exactly one HTTP call - no detail hydration.
        assert m.call_count == 1

    def test_preserves_state_and_submission_state_attributes(self, h1_client):
        list_payload = self._list_resp(
            [
                (
                    "acme",
                    {
                        "handle": "acme",
                        "name": "Acme",
                        "state": "public_mode",
                        "submission_state": "open",
                        "bookmarked": True,
                    },
                ),
            ]
        )
        with patch.object(h1_client, "_get", return_value=list_payload):
            previews = h1_client.browse_programmes()
        assert previews[0].state == "public_mode"
        assert previews[0].submission_state == "open"
        assert previews[0].bookmarked is True

    def test_paginates_until_limit(self, h1_client):
        # Two pages of 3, limit 5 -> 5 results.
        page1 = self._list_resp(
            [(f"p{i}", {"handle": f"p{i}"}) for i in range(3)],
            next_link="/hackers/programs?page=2",
        )
        page2 = self._list_resp([(f"p{i}", {"handle": f"p{i}"}) for i in range(3, 6)])
        with patch.object(h1_client, "_get", side_effect=[page1, page2]):
            previews = h1_client.browse_programmes(limit=5)
        assert [p.handle for p in previews] == ["p0", "p1", "p2", "p3", "p4"]

    def test_stops_at_limit_within_first_page(self, h1_client):
        page1 = self._list_resp(
            [(f"p{i}", {"handle": f"p{i}"}) for i in range(10)],
            next_link="/hackers/programs?page=2",
        )
        # limit=3 means we trim the first page; no need to fetch page 2.
        with patch.object(h1_client, "_get", side_effect=[page1]) as m:
            previews = h1_client.browse_programmes(limit=3)
        assert [p.handle for p in previews] == ["p0", "p1", "p2"]
        assert m.call_count == 1

    def test_filter_kwargs_become_filter_bracket_params(self, h1_client):
        list_payload = self._list_resp([])
        with patch.object(h1_client, "_get", return_value=list_payload) as m:
            h1_client.browse_programmes(
                offers_bounties=True,
                bookmarked=False,
                submission_state="open",
                asset_type="URL",
                sort="-launched_at",
            )
        params = m.call_args[0][1]
        # H1 filter params follow JSON:API bracket notation.
        assert params["filter[offers_bounties]"] == "true"
        assert params["filter[bookmarked]"] == "false"
        assert params["filter[submission_state]"] == "open"
        assert params["filter[asset_type]"] == "URL"
        assert params["sort"] == "-launched_at"

    def test_omits_filter_param_when_arg_is_none(self, h1_client):
        list_payload = self._list_resp([])
        with patch.object(h1_client, "_get", return_value=list_payload) as m:
            h1_client.browse_programmes(offers_bounties=True)
        params = m.call_args[0][1]
        assert "filter[offers_bounties]" in params
        assert "filter[bookmarked]" not in params
        assert "filter[asset_type]" not in params
        assert "filter[submission_state]" not in params
        assert "sort" not in params

    def test_skips_records_with_missing_handle(self, h1_client):
        # H1 list shapes that have no handle attribute and no id field are
        # unusable as previews - the PM needs a handle to hydrate. Drop them.
        list_payload = {
            "data": [
                {"id": "acme", "attributes": {"handle": "acme"}},
                {"attributes": {}},  # no id, no handle
            ],
            "links": {},
        }
        with patch.object(h1_client, "_get", return_value=list_payload):
            previews = h1_client.browse_programmes()
        assert [p.handle for p in previews] == ["acme"]


class TestHydrateProgramme:
    """hydrate_programme fetches one full Programme from the detail endpoint."""

    def _detail_resp(self, handle, state: str | None = "public_mode"):
        attributes = {
            "handle": handle,
            "name": handle.upper(),
            "policy": "Automated scanning permitted.",
            "bounty_table": {
                "data": [{"attributes": {"label": "critical", "maximum_amount": 5000}}]
            },
        }
        if state is not None:
            attributes["state"] = state
        return {
            "data": {"attributes": attributes},
            "included": [
                {
                    "type": "structured-scope",
                    "attributes": {
                        "asset_identifier": f"*.{handle}.com",
                        "asset_type": "WILDCARD",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                    },
                }
            ],
        }

    def test_returns_typed_programme(self, h1_client):
        with patch.object(h1_client, "_get", return_value=self._detail_resp("acme")):
            prog = h1_client.hydrate_programme("acme")
        assert prog.handle == "acme"
        assert prog.name == "ACME"
        assert prog.bounty_table[Severity.CRITICAL] == 5000

    def test_hydrate_carries_state_through(self, h1_client):
        with patch.object(
            h1_client, "_get", return_value=self._detail_resp("acme", state="private_mode")
        ):
            prog = h1_client.hydrate_programme("acme")
        assert prog.state == "private_mode"

    def test_uses_detail_endpoint_with_include(self, h1_client):
        with patch.object(h1_client, "_get", return_value=self._detail_resp("acme")) as m:
            h1_client.hydrate_programme("acme")
        path = m.call_args[0][0]
        if "params" in m.call_args[1]:
            params = m.call_args[1]["params"]
        elif len(m.call_args[0]) > 1:
            params = m.call_args[0][1]
        else:
            params = {}
        assert "/hackers/programs/acme" in path
        assert params.get("include") == "bounty_table,structured_scopes"

    def test_includes_structured_scope_from_detail(self, h1_client):
        with patch.object(h1_client, "_get", return_value=self._detail_resp("acme")):
            prog = h1_client.hydrate_programme("acme")
        assert prog.in_scope[0].asset_identifier == "*.acme.com"
        assert prog.in_scope[0].asset_type == ScopeType.WILDCARD


class TestGetProgrammeStats:
    def test_returns_parsed_fields(self, h1_client):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "response_efficiency_percentage": 95,
                    "average_time_to_first_programme_response_in_minutes": 120,
                    "average_time_to_bounty_in_minutes": 14400,
                    "average_time_to_resolution_in_minutes": 43200,
                    "total_bounties_paid_in_cents": 500000,
                    "state": "public_mode",
                }
            }
        }

        with patch.object(h1_client._session, "get", return_value=mock_response):
            stats = h1_client.get_programme_stats("acme")

        assert stats["handle"] == "acme"
        assert stats["response_efficiency_pct"] == 95
        assert stats["avg_time_to_bounty_minutes"] == 14400
        assert stats["total_bounties_paid_cents"] == 500000

    def test_accepting_reports_true_when_public_mode(self, h1_client):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"data": {"attributes": {"state": "public_mode"}}}

        with patch.object(h1_client._session, "get", return_value=mock_response):
            stats = h1_client.get_programme_stats("acme")

        assert stats["accepting_reports"] is True

    def test_accepting_reports_false_when_not_public_mode(self, h1_client):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"data": {"attributes": {"state": "private_mode"}}}

        with patch.object(h1_client._session, "get", return_value=mock_response):
            stats = h1_client.get_programme_stats("acme")

        assert stats["accepting_reports"] is False


class TestListReports:
    def test_passes_programme_filter_param(self, h1_client):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"data": [{"id": "42"}]}

        with patch.object(h1_client._session, "get", return_value=mock_response) as mock_get:
            h1_client.list_reports("acme", page_size=10)

        call_kwargs = mock_get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert params.get("filter[program][]") == "acme"
        assert params.get("page[size]") == 10

    def test_returns_data_list(self, h1_client):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"data": [{"id": "1"}, {"id": "2"}]}

        with patch.object(h1_client._session, "get", return_value=mock_response):
            result = h1_client.list_reports("acme")

        assert result == [{"id": "1"}, {"id": "2"}]

    def test_empty_data_returns_empty_list(self, h1_client):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"data": []}

        with patch.object(h1_client._session, "get", return_value=mock_response):
            result = h1_client.list_reports("acme")

        assert result == []
