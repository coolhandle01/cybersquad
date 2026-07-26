"""tests/tools/recon/test_cert_transparency.py - unit tests for
tools/recon/cert_transparency.py.

crt.sh certificate-transparency lookup: parse the JSON name_value field,
strip wildcard prefixes, keep only names on the queried domain, dedupe.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

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
