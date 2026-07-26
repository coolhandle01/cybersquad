"""tests/tools/recon/test_subfinder.py - unit tests for tools/recon/subfinder.py.

Covers the scan-mode-aware flag plumbing: ``-rl`` / ``-t`` / ``-active``
all derive from ``config.scan``, so the operator's stealth dial flows
through to subfinder the same way it does to httpx / dnsx / dirfuzz.
"""

from __future__ import annotations

from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from tools.recon.subfinder import enumerate_subdomains

pytestmark = pytest.mark.unit


def _completed(stdout: str = "") -> CompletedProcess:
    return CompletedProcess([], 0, stdout, "")


class TestEnumerateSubdomainsFlags:
    def _capture(self):
        captured: list[list[str]] = []

        def fake_run(cmd, timeout: int = 180, input: str | None = None) -> CompletedProcess:
            captured.append(cmd)
            return _completed("")

        return captured, fake_run

    def test_passes_rate_limit_and_threads_from_config(self, monkeypatch, target_apex: str):
        import tools.recon.subfinder as sf_mod

        monkeypatch.setattr(sf_mod.config.scan, "subfinder_rate_limit", 17)
        monkeypatch.setattr(sf_mod.config.scan, "subfinder_threads", 4)
        captured, fake_run = self._capture()

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("tools.recon.subfinder._run", side_effect=fake_run),
        ):
            enumerate_subdomains(target_apex)

        assert captured, "expected subfinder to be invoked"
        argv = captured[0]
        assert argv[argv.index("-rl") + 1] == "17"
        assert argv[argv.index("-t") + 1] == "4"

    def test_active_flag_present_when_enabled(self, monkeypatch, target_apex: str):
        """NORMAL / RAID flip ``subfinder_active`` on - the ``-active``
        flag joins the argv so subfinder live-resolves each candidate.
        """
        import tools.recon.subfinder as sf_mod

        monkeypatch.setattr(sf_mod.config.scan, "subfinder_active", True)
        captured, fake_run = self._capture()

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("tools.recon.subfinder._run", side_effect=fake_run),
        ):
            enumerate_subdomains(target_apex)

        assert "-active" in captured[0]

    def test_active_flag_absent_when_disabled(self, monkeypatch, target_apex: str):
        """STEALTH flips ``subfinder_active`` off - the lookup stays
        passive against the third-party sources, no live DNS resolution.
        """
        import tools.recon.subfinder as sf_mod

        monkeypatch.setattr(sf_mod.config.scan, "subfinder_active", False)
        captured, fake_run = self._capture()

        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("tools.recon.subfinder._run", side_effect=fake_run),
        ):
            enumerate_subdomains(target_apex)

        assert "-active" not in captured[0]


class TestEnumerateSubdomainsParsing:
    """Output handling: stdout lines become hostnames, duplicates collapse,
    a missing binary raises, and empty stdout yields an empty list. The
    flag plumbing lives in ``TestEnumerateSubdomainsFlags`` above."""

    def test_returns_parsed_subdomains(self):
        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch(
                "tools.recon.subfinder._run",
                return_value=_completed("api.example.com\nadmin.example.com\n"),
            ),
        ):
            result = enumerate_subdomains("example.com")

        assert "api.example.com" in result
        assert "admin.example.com" in result

    def test_deduplicates_results(self):
        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch(
                "tools.recon.subfinder._run",
                return_value=_completed("api.example.com\napi.example.com\nadmin.example.com\n"),
            ),
        ):
            result = enumerate_subdomains("example.com")

        assert result.count("api.example.com") == 1

    def test_raises_if_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="subfinder"):
                enumerate_subdomains("example.com")

    def test_empty_output(self):
        with (
            patch("shutil.which", return_value="/usr/bin/subfinder"),
            patch("tools.recon.subfinder._run", return_value=_completed("")),
        ):
            result = enumerate_subdomains("example.com")

        assert result == []
