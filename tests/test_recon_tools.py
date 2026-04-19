"""
tests/test_recon_tools.py — unit tests for tools/recon_tools.py

Focuses on the scope guard (security-critical) and domain extraction.
Subprocess calls are mocked so tests run without binaries installed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Programme
from tools.recon_tools import (
    enumerate_subdomains,
    extract_domain,
    filter_in_scope,
    port_scan,
    probe_endpoints,
)

pytestmark = pytest.mark.unit


# ── extract_domain ────────────────────────────────────────────────────────────


class TestExtractDomain:
    def test_plain_domain(self):
        assert extract_domain("example.com") == "example.com"

    def test_url_with_scheme(self):
        assert extract_domain("https://example.com") == "example.com"

    def test_url_with_path(self):
        assert extract_domain("https://api.example.com/v1/search") == "api.example.com"

    def test_subdomain(self):
        assert extract_domain("sub.example.com") == "sub.example.com"

    def test_url_with_port(self):
        assert extract_domain("https://example.com:8443") == "example.com"


# ── filter_in_scope ───────────────────────────────────────────────────────────


class TestFilterInScope:
    """
    The scope guard is security-critical — an out-of-scope false positive
    would cause us to test targets we're not authorised to touch.
    """

    def test_exact_domain_match(self, programme):
        assert filter_in_scope(["example.com"], programme) == ["example.com"]

    def test_genuine_subdomain_passes(self, programme):
        result = filter_in_scope(["api.example.com"], programme)
        assert "api.example.com" in result

    def test_deep_subdomain_passes(self, programme):
        result = filter_in_scope(["deep.api.example.com"], programme)
        assert "deep.api.example.com" in result

    def test_out_of_scope_domain_blocked(self, programme):
        result = filter_in_scope(["other.com"], programme)
        assert result == []

    def test_boundary_spoofing_blocked(self, programme):
        """evil.notexample.com must NOT pass as in-scope for example.com."""
        result = filter_in_scope(["evil.notexample.com"], programme)
        assert result == [], "Scope guard boundary bug: evil.notexample.com matched example.com"

    def test_suffix_spoofing_blocked(self, programme):
        """attackerexample.com must NOT match *.example.com."""
        result = filter_in_scope(["attackerexample.com"], programme)
        assert result == []

    def test_mixed_batch(self, programme):
        hosts = ["api.example.com", "evil.notexample.com", "admin.example.com", "other.io"]
        result = filter_in_scope(hosts, programme)
        assert "api.example.com" in result
        assert "admin.example.com" in result
        assert "evil.notexample.com" not in result
        assert "other.io" not in result

    def test_empty_input(self, programme):
        assert filter_in_scope([], programme) == []

    def test_no_scope_items(self):
        bare_programme = Programme(
            handle="bare",
            name="Bare",
            url="https://hackerone.com/bare",
            bounty_table={},
            in_scope=[],
            out_of_scope=[],
            allows_automated_scanning=True,
        )
        assert filter_in_scope(["example.com"], bare_programme) == []


# ── enumerate_subdomains ──────────────────────────────────────────────────────


class TestEnumerateSubdomains:
    def test_returns_parsed_subdomains(self):
        mock_result = MagicMock()
        mock_result.stdout = "api.example.com\nadmin.example.com\n"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = enumerate_subdomains("example.com")

        assert "api.example.com" in result
        assert "admin.example.com" in result

    def test_deduplicates_results(self):
        mock_result = MagicMock()
        mock_result.stdout = "api.example.com\napi.example.com\nadmin.example.com\n"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = enumerate_subdomains("example.com")

        assert result.count("api.example.com") == 1

    def test_raises_if_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="subfinder"):
                enumerate_subdomains("example.com")

    def test_empty_output(self):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = enumerate_subdomains("example.com")

        assert result == []


# ── probe_endpoints ───────────────────────────────────────────────────────────


class TestProbeEndpoints:
    def test_parses_httpx_json_output(self):
        import json

        mock_result = MagicMock()
        mock_result.stdout = "\n".join(
            [
                json.dumps(
                    {"url": "https://api.example.com", "status_code": 200, "tech": ["nginx"]}
                ),
                json.dumps({"url": "https://admin.example.com", "status_code": 403, "tech": []}),
            ]
        )
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/httpx"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = probe_endpoints(["api.example.com", "admin.example.com"])

        assert len(result) == 2
        assert result[0].url == "https://api.example.com"
        assert result[0].status_code == 200
        assert "nginx" in result[0].technologies

    def test_skips_malformed_json_lines(self):
        mock_result = MagicMock()
        mock_result.stdout = (
            'not json\n{"url": "https://api.example.com", "status_code": 200, "tech": []}'
        )
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/httpx"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = probe_endpoints(["api.example.com"])

        assert len(result) == 1

    def test_stdin_receives_host_list(self):
        """Regression: probe_endpoints previously discarded the host list entirely."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/httpx"),
            patch("subprocess.run", return_value=mock_result) as mock_run,
        ):
            probe_endpoints(["api.example.com", "admin.example.com"])

        call_kwargs = mock_run.call_args.kwargs
        assert "input" in call_kwargs, "host list must be passed via stdin (input=)"
        assert "api.example.com" in call_kwargs["input"]
        assert "admin.example.com" in call_kwargs["input"]

    def test_raises_if_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="httpx"):
                probe_endpoints(["example.com"])


# ── port_scan ─────────────────────────────────────────────────────────────────


class TestPortScan:
    def test_parses_open_ports(self):
        mock_result = MagicMock()
        mock_result.stdout = (
            "# Nmap scan\n"
            "Host: 93.184.216.34 (example.com)\tStatus: Up\n"
            "Host: 93.184.216.34 (example.com)\tPorts: 80/open/tcp, 443/open/tcp\n"
        )
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = port_scan(["example.com"])

        assert 80 in result["example.com"]
        assert 443 in result["example.com"]

    def test_empty_host_list(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            result = port_scan([])
        assert result == {}

    def test_raises_if_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="nmap"):
                port_scan(["example.com"])
