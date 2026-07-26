"""tests/tools/recon/test_traceroute.py - unit tests for tools/recon/traceroute.py"""

from __future__ import annotations

from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from tools.recon.traceroute import _is_public, _parse_hops, run_traceroute

pytestmark = pytest.mark.unit


class TestIsPublic:
    def test_public_ip_is_true(self):
        assert _is_public("93.184.216.34") is True

    def test_rfc1918_10_is_false(self):
        assert _is_public("10.0.0.1") is False

    def test_rfc1918_192168_is_false(self):
        assert _is_public("192.168.1.1") is False

    def test_rfc1918_172_16_is_false(self):
        assert _is_public("172.16.0.1") is False

    def test_loopback_is_false(self):
        assert _is_public("127.0.0.1") is False

    def test_link_local_is_false(self):
        assert _is_public("169.254.0.1") is False


class TestParseHops:
    def test_extracts_public_ips_from_tracepath_output(self):
        output = """\
 1?: [LOCALHOST]                                         pmtu 1500
 1:  192.168.1.1                                           0.450ms
 2:  203.0.113.1                                           5.123ms
 3:  198.51.100.4                                          12.456ms
 4:  93.184.216.34                                         20.789ms
"""
        hops = _parse_hops(output)
        assert hops == ["203.0.113.1", "198.51.100.4", "93.184.216.34"]

    def test_extracts_public_ips_from_traceroute_output(self):
        output = """\
traceroute to example.com (93.184.216.34), 30 hops max
 1  10.0.0.1 (10.0.0.1)  0.123 ms
 2  203.0.113.1 (203.0.113.1)  5.678 ms
 3  93.184.216.34 (93.184.216.34)  22.345 ms
"""
        hops = _parse_hops(output)
        assert hops == ["203.0.113.1", "93.184.216.34"]

    def test_deduplicates_repeated_ips(self):
        output = "203.0.113.1 203.0.113.1 93.184.216.34\n"
        hops = _parse_hops(output)
        assert hops == ["203.0.113.1", "93.184.216.34"]

    def test_empty_output_returns_empty_list(self):
        assert _parse_hops("") == []

    def test_only_private_hops_returns_empty(self):
        output = "10.0.0.1\n192.168.1.1\n172.16.0.1\n"
        assert _parse_hops(output) == []


class TestRunTraceroute:
    def _fake_run(self, stdout: str):
        def _run(cmd, timeout=60):
            return CompletedProcess(cmd, 0, stdout, "")

        return _run

    def test_returns_hops_for_each_host(self):
        output = "203.0.113.1\n93.184.216.34\n"
        with patch("shutil.which", return_value="/usr/bin/tracepath"):
            with patch("tools.recon.traceroute._run", side_effect=self._fake_run(output)):
                result = run_traceroute(["example.com", "other.com"])
        assert set(result.keys()) == {"example.com", "other.com"}
        assert "203.0.113.1" in result["example.com"]

    def test_returns_empty_dict_when_binary_missing(self):
        with patch("shutil.which", return_value=None):
            result = run_traceroute(["example.com"])
        assert result == {}

    def test_empty_hostname_list_returns_empty_dict(self):
        with patch("shutil.which", return_value="/usr/bin/tracepath"):
            result = run_traceroute([])
        assert result == {}

    def test_exception_per_host_returns_empty_list(self):
        with patch("shutil.which", return_value="/usr/bin/tracepath"):
            with patch("tools.recon.traceroute._run", side_effect=Exception("timeout")):
                result = run_traceroute(["example.com"])
        assert result == {"example.com": []}

    def test_skips_when_traceroute_disabled(self, monkeypatch):
        """STEALTH posture flips ``config.scan.traceroute_enabled`` False.

        Gate fires before binary detection - no shutil.which / subprocess
        call ever lands. The OA's loudest tool (ICMP from the operator IP)
        respects the stealth dial.
        """
        import tools.recon.traceroute as trace_mod

        monkeypatch.setattr(trace_mod.config.scan, "traceroute_enabled", False)
        with patch("shutil.which") as which:
            with patch("tools.recon.traceroute._run") as run:
                result = run_traceroute(["example.com"])
        assert result == {}
        which.assert_not_called()
        run.assert_not_called()

    def test_uses_traceroute_when_tracepath_absent(self):
        calls = []

        def fake_which(name):
            if name == "tracepath":
                return None
            if name == "traceroute":
                return "/usr/bin/traceroute"
            return None

        def fake_run(cmd, timeout=60):
            calls.append(cmd)
            return CompletedProcess(cmd, 0, "", "")

        with patch("shutil.which", side_effect=fake_which):
            with patch("tools.recon.traceroute._run", side_effect=fake_run):
                run_traceroute(["example.com"])

        assert any("traceroute" in str(c) for c in calls)
        assert not any("tracepath" in str(c) for c in calls)
