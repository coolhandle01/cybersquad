"""tests/tools/recon/test_cert_transparency.py - unit tests for
tools/recon/cert_transparency.py.

crt.sh certificate-transparency lookup: parse the JSON name_value field,
strip wildcard prefixes, keep only names on the queried domain, dedupe.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest
import requests

from tools.recon.cert_transparency import cert_transparency

pytestmark = pytest.mark.unit


class TestCertTransparency:
    def _crtsh_response(self):
        return [
            {"name_value": "api.example.com\nstage.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "other.notexample.com"},
        ]

    def test_returns_subdomains_ending_in_domain(self, make_response):
        mock_resp = make_response(json=self._crtsh_response())

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert "api.example.com" in result
        assert "stage.example.com" in result

    def test_strips_wildcard_prefix(self, make_response):
        mock_resp = make_response(json=[{"name_value": "*.example.com"}])

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert all(not n.startswith("*.") for n in result)

    def test_preserves_leading_non_wildcard_characters(self, make_response):
        """lstrip('*.') must remove only the wildcard prefix, not arbitrary
        leading letters - a host beginning with a non-wildcard char survives whole."""
        mock_resp = make_response(json=[{"name_value": "Xtest.example.com"}])
        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")
        assert result == ["Xtest.example.com"]

    def test_filters_off_domain_names(self, make_response):
        mock_resp = make_response(json=[{"name_value": "other.notexample.com"}])

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert result == []

    def test_deduplicates_results(self, make_response):
        mock_resp = make_response(
            json=[
                {"name_value": "api.example.com"},
                {"name_value": "api.example.com"},
            ]
        )

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert result.count("api.example.com") == 1

    def test_queries_crtsh_with_expected_url_params_and_timeout(self, make_response):
        """Pin the outbound crt.sh request: exact URL, the CT-log query params
        (``%.<domain>`` + ``output=json``), and the explicit 30s timeout. The
        request is the tool's entire contract with crt.sh; asserting only the
        parsed result leaves url/params/timeout free to drift silently."""
        mock_resp = make_response(json=[])

        with patch("requests.get", return_value=mock_resp) as mock_get:
            cert_transparency("example.com")

        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        # URL is the sole positional; timeout/params ride as keywords through
        # tools.http.get (which also injects the traceable User-Agent header).
        assert args == ("https://crt.sh/",)
        assert kwargs["params"] == {"q": "%.example.com", "output": "json"}
        assert kwargs["timeout"] == 30

    def test_query_tracks_the_requested_domain(self, make_response):
        """The ``q`` param must be built from the argument, not a constant -
        a different domain yields a different ``%.<domain>`` filter."""
        mock_resp = make_response(json=[])

        with patch("requests.get", return_value=mock_resp) as mock_get:
            cert_transparency("other.test")

        assert mock_get.call_args.kwargs["params"] == {
            "q": "%.other.test",
            "output": "json",
        }

    def test_error_status_propagates(self, make_response):
        """A >=400 response reaches ``resp.raise_for_status()`` and the error
        propagates - the tool does not swallow it into an empty result. A loud
        failure is the documented behaviour; a silent ``[]`` on an HTTP error
        would look identical to a domain with no certificates."""
        mock_resp = make_response(status=503)

        with (
            patch("requests.get", return_value=mock_resp),
            pytest.raises(requests.HTTPError),
        ):
            cert_transparency("example.com")

    def test_tolerates_entry_missing_name_value(self, make_response):
        """An entry without a ``name_value`` key degrades to no names for that
        entry rather than crashing - the empty-string default must survive.
        The good entry alongside it still comes through."""
        mock_resp = make_response(json=[{}, {"name_value": "api.example.com"}])

        with patch("requests.get", return_value=mock_resp):
            result = cert_transparency("example.com")

        assert result == ["api.example.com"]

    def test_logs_summary_count_for_domain(self, make_response, caplog):
        """The operator-facing summary line reports the exact count and the
        queried domain - the log is how a SOC operator ties names back to a
        run, so its format and both interpolated values are load-bearing."""
        mock_resp = make_response(json=[{"name_value": "api.example.com\nstage.example.com"}])

        with (
            caplog.at_level(logging.INFO, logger="tools.recon.cert_transparency"),
            patch("requests.get", return_value=mock_resp),
        ):
            result = cert_transparency("example.com")

        assert result == ["api.example.com", "stage.example.com"]
        messages = [
            r.getMessage() for r in caplog.records if r.name == "tools.recon.cert_transparency"
        ]
        assert messages == ["crt.sh found 2 names for example.com"]
