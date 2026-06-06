"""Unit tests for tools/pentest/nosqli.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.pentest.nosqli import run_nosqli

pytestmark = pytest.mark.unit


def _mock_result(stdout: str, returncode: int = 0) -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.returncode = returncode
    return m


class TestRunNosqli:
    def test_detects_injection_from_stdout(self, target_apex):
        output = (
            "Testing http://example.com/?id=1\nInjection found in parameter: id\n[payload details]"
        )
        endpoints = [Endpoint(url=f"https://{target_apex}/api", status_code=200, parameters=["id"])]

        with (
            patch("shutil.which", return_value="/usr/bin/nosqli"),
            patch("subprocess.run", return_value=_mock_result(output)),
        ):
            results = run_nosqli(endpoints)

        assert len(results) == 1
        assert results[0].vuln_class == "NoSQLi"
        assert results[0].tool == "nosqli"
        assert results[0].severity_hint == Severity.HIGH

    def test_no_finding_when_no_injection(self, target_apex):
        output = "Testing http://example.com/?id=1\nNo vulnerabilities detected."
        endpoints = [Endpoint(url=f"https://{target_apex}/api", status_code=200, parameters=["id"])]

        with (
            patch("shutil.which", return_value="/usr/bin/nosqli"),
            patch("subprocess.run", return_value=_mock_result(output)),
        ):
            results = run_nosqli(endpoints)

        assert results == []

    def test_empty_endpoints_returns_empty(self):
        with patch("shutil.which", return_value="/usr/bin/nosqli"):
            results = run_nosqli([])
        assert results == []

    def test_skips_endpoints_without_parameters(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/static", status_code=200)]

        with (
            patch("shutil.which", return_value="/usr/bin/nosqli"),
            patch("subprocess.run") as mock_run,
        ):
            results = run_nosqli(endpoints)

        mock_run.assert_not_called()
        assert results == []

    def test_raises_if_binary_missing(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}", status_code=200, parameters=["id"])]
        with patch("shutil.which", return_value=None):
            with pytest.raises(OSError, match="nosqli"):
                run_nosqli(endpoints)

    def test_evidence_truncated_to_last_2000_chars(self, target_apex):
        long_output = "Injection found\n" + "x" * 5000
        endpoints = [Endpoint(url=f"https://{target_apex}/api", status_code=200, parameters=["q"])]

        with (
            patch("shutil.which", return_value="/usr/bin/nosqli"),
            patch("subprocess.run", return_value=_mock_result(long_output)),
        ):
            results = run_nosqli(endpoints)

        assert len(results[0].evidence) <= 2000
