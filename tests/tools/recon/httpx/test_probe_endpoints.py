"""tests/tools/recon/httpx/test_probe_endpoints.py - unit tests for the
``probe_endpoints`` entry point in tools/recon/httpx.

``probe_endpoints`` is the slim ``list[Endpoint]`` shim the recon
orchestrator calls - ``httpx_scan`` in TECH_DETECT mode without the rich
result. The scanner internals (flag assembly, NDJSON parsing helpers,
evidence paths) are covered in ``test_scanner.py`` / ``test_flags.py`` /
``test_parser.py``; this file pins the shim's own behaviour: mode
selection plus output handling.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from tools.recon.httpx import probe_endpoints

pytestmark = pytest.mark.unit


def _ndjson_line(**kwargs) -> str:
    """Build one httpx NDJSON output line from the kwargs as fields."""
    return json.dumps(kwargs)


class TestProbeEndpoints:
    """Covers the mode/flag behaviour plus output handling: NDJSON
    parsing, malformed-line tolerance, the host list reaching the binary
    via stdin, and the missing-binary raise."""

    def test_runs_tech_detect_mode(self, target_url):
        # probe_endpoints == httpx_scan with mode=TECH_DETECT, returning
        # ``list[Endpoint]`` not the rich HttpxScanResult.
        mock_result = MagicMock(
            stdout=_ndjson_line(url=target_url, status_code=200, tech=["Django:4.2"]),
            returncode=0,
            stderr="",
        )
        with (
            patch("tools.recon.httpx.scanner._require_binary", return_value="/usr/bin/httpx"),
            patch("tools.recon.httpx.scanner._run", return_value=mock_result) as mock_run,
        ):
            endpoints = probe_endpoints([target_url])

        assert isinstance(endpoints, list)
        assert len(endpoints) == 1
        assert endpoints[0].technologies == ["Django:4.2"]
        # The flags include -tech-detect (i.e. TECH_DETECT mode, not LIVE).
        cmd = mock_run.call_args.args[0]
        assert "-tech-detect" in cmd

    def test_parses_httpx_json_output(self, target_apex):
        mock_result = MagicMock()
        mock_result.stdout = "\n".join(
            [
                json.dumps(
                    {"url": f"https://api.{target_apex}", "status_code": 200, "tech": ["nginx"]}
                ),
                json.dumps({"url": f"https://admin.{target_apex}", "status_code": 403, "tech": []}),
            ]
        )
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/httpx"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = probe_endpoints([f"api.{target_apex}", f"admin.{target_apex}"])

        assert len(result) == 2
        assert result[0].url == f"https://api.{target_apex}"
        assert result[0].status_code == 200
        assert "nginx" in result[0].technologies

    def test_skips_malformed_json_lines(self, target_apex):
        mock_result = MagicMock()
        mock_result.stdout = (
            f'not json\n{{"url": "https://api.{target_apex}", "status_code": 200, "tech": []}}'
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
