"""
tests/test_vuln_tools.py — unit tests for tools/vuln_tools.py
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity, VerifiedVulnerability
from tools.vuln_tools import (
    _lookup_cvss,
    check_cors_misconfiguration,
    is_in_scope,
    run_nuclei,
    triage_findings,
)

pytestmark = pytest.mark.unit


# ── _above_floor ──────────────────────────────────────────────────────────────


class TestAboveFloor:
    def test_medium_above_medium_floor(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "medium")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        assert vt._above_floor(Severity.MEDIUM) is True

    def test_low_below_medium_floor(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "medium")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        assert vt._above_floor(Severity.LOW) is False

    def test_critical_always_above(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "high")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        assert vt._above_floor(Severity.CRITICAL) is True

    def test_informational_below_low_floor(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "low")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        assert vt._above_floor(Severity.INFORMATIONAL) is False


# ── _lookup_cvss ──────────────────────────────────────────────────────────────


class TestLookupCvss:
    def test_sqli_critical(self):
        score, vector = _lookup_cvss("SQLi", Severity.CRITICAL)
        assert score == 9.8
        assert "CVSS:3.1" in vector

    def test_cors_high(self):
        score, vector = _lookup_cvss("CORS", Severity.HIGH)
        assert score == 7.4

    def test_unknown_class_falls_back_to_default(self):
        score, vector = _lookup_cvss("UnknownVulnType", Severity.HIGH)
        assert score == 7.5

    def test_returns_tuple(self):
        result = _lookup_cvss("XSS", Severity.MEDIUM)
        assert isinstance(result, tuple)
        assert len(result) == 2


# ── is_in_scope ───────────────────────────────────────────────────────────────


class TestIsInScope:
    def test_in_scope_finding(self, raw_finding_high, programme):
        assert is_in_scope(raw_finding_high, programme) is True

    def test_out_of_scope_finding(self, raw_finding_oos, programme):
        assert is_in_scope(raw_finding_oos, programme) is False


# ── triage_findings ───────────────────────────────────────────────────────────


class TestTriageFindings:
    def test_filters_out_of_scope(self, raw_finding_high, raw_finding_oos, programme):
        results = triage_findings([raw_finding_high, raw_finding_oos], programme)
        targets = [v.target for v in results]
        assert raw_finding_oos.target not in targets

    def test_filters_below_severity_floor(
        self, raw_finding_high, raw_finding_low, programme, monkeypatch
    ):
        monkeypatch.setenv("MIN_SEVERITY", "medium")
        import importlib

        import tools.vuln_tools as vt

        importlib.reload(vt)
        results = vt.triage_findings([raw_finding_high, raw_finding_low], programme)
        severities = [v.severity for v in results]
        assert Severity.LOW not in severities

    def test_assigns_cvss_score(self, raw_finding_high, programme):
        results = triage_findings([raw_finding_high], programme)
        assert len(results) == 1
        assert results[0].cvss_score > 0
        assert results[0].cvss_vector.startswith("CVSS:3.1")

    def test_returns_verified_vulnerability_objects(self, raw_finding_high, programme):
        results = triage_findings([raw_finding_high], programme)
        for r in results:
            assert isinstance(r, VerifiedVulnerability)

    def test_empty_input_returns_empty(self, programme):
        assert triage_findings([], programme) == []

    def test_all_filtered_returns_empty(self, raw_finding_oos, programme):
        assert triage_findings([raw_finding_oos], programme) == []

    def test_preserves_title_and_target(self, raw_finding_high, programme):
        results = triage_findings([raw_finding_high], programme)
        assert results[0].title == raw_finding_high.title
        assert results[0].target == raw_finding_high.target


# ── run_nuclei ────────────────────────────────────────────────────────────────


class TestRunNuclei:
    def test_parses_nuclei_json_output(self):
        import json

        mock_result = MagicMock()
        mock_result.stdout = json.dumps(
            {
                "info": {"name": "Test Finding", "severity": "high", "tags": ["xss"]},
                "matched-at": "https://api.example.com/search",
                "extracted-results": ["payload"],
            }
        )
        mock_result.returncode = 0

        endpoints = [Endpoint(url="https://api.example.com/search", status_code=200)]

        with (
            patch("shutil.which", return_value="/usr/bin/nuclei"),
            patch("subprocess.run", return_value=mock_result),
        ):
            results = run_nuclei(endpoints)

        assert len(results) == 1
        assert results[0].tool == "nuclei"
        assert results[0].severity_hint == Severity.HIGH

    def test_empty_endpoints_returns_empty(self):
        results = run_nuclei([])
        assert results == []

    def test_raises_if_binary_missing(self):
        endpoints = [Endpoint(url="https://example.com", status_code=200)]
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="nuclei"):
                run_nuclei(endpoints)


# ── check_cors_misconfiguration ───────────────────────────────────────────────


class TestCheckCorsMisconfiguration:
    def test_detects_wildcard_cors(self):
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "false",
        }

        endpoints = [Endpoint(url="https://api.example.com", status_code=200)]

        with patch("requests.get", return_value=mock_response):
            results = check_cors_misconfiguration(endpoints)

        assert len(results) == 1
        assert results[0].vuln_class == "CORS"

    def test_detects_reflected_origin_with_credentials(self):
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil.example.com",
            "Access-Control-Allow-Credentials": "true",
        }

        endpoints = [Endpoint(url="https://api.example.com", status_code=200)]

        with patch("requests.get", return_value=mock_response):
            results = check_cors_misconfiguration(endpoints)

        assert len(results) == 1
        assert results[0].severity_hint == Severity.HIGH

    def test_safe_cors_produces_no_finding(self):
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://example.com",
            "Access-Control-Allow-Credentials": "false",
        }

        endpoints = [Endpoint(url="https://api.example.com", status_code=200)]

        with patch("requests.get", return_value=mock_response):
            results = check_cors_misconfiguration(endpoints)

        assert results == []

    def test_request_exception_is_swallowed(self):
        endpoints = [Endpoint(url="https://api.example.com", status_code=200)]

        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_cors_misconfiguration(endpoints)

        assert results == []
