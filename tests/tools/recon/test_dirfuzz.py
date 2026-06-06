"""tests/tools/recon/test_dirfuzz.py - unit tests for tools/recon/dirfuzz.py.

Content discovery via ``ffuf``: feed known endpoints, parse the JSON
results file the binary writes, dedupe against URLs already known, honour
each hit's status code, and skip 5xx seeds. Subprocess is mocked so the
tests run without ffuf installed.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint
from tools.recon.dirfuzz import discover_paths

pytestmark = pytest.mark.unit


class TestDiscoverPaths:
    def _ffuf_side_effect(self, results):
        """Return a subprocess.run side effect that writes ffuf JSON to the -o path."""

        def fake_run(cmd, *args, **kwargs):
            out_path = cmd[cmd.index("-o") + 1]
            with open(out_path, "w") as fh:
                json.dump({"results": results}, fh)
            return MagicMock(returncode=0, stdout="", stderr="")

        return fake_run

    def test_returns_discovered_endpoints(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        hits = [
            {"url": f"https://{target_apex}/admin", "status": 200},
            {"url": f"https://{target_apex}/api", "status": 200},
        ]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=self._ffuf_side_effect(hits)),
        ):
            result = discover_paths(endpoints)

        urls = [ep.url for ep in result]
        assert f"https://{target_apex}/admin" in urls
        assert f"https://{target_apex}/api" in urls

    def test_deduplicates_known_urls(self, target_apex):
        endpoints = [
            Endpoint(url=f"https://{target_apex}/", status_code=200),
            Endpoint(url=f"https://{target_apex}/admin", status_code=200),
        ]
        hits = [
            {"url": f"https://{target_apex}/admin", "status": 200},
            {"url": f"https://{target_apex}/new-path", "status": 200},
        ]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=self._ffuf_side_effect(hits)),
        ):
            result = discover_paths(endpoints)

        urls = [ep.url for ep in result]
        assert f"https://{target_apex}/admin" not in urls
        assert f"https://{target_apex}/new-path" in urls

    def test_empty_endpoints_returns_empty(self):
        assert discover_paths([]) == []

    def test_skips_endpoints_with_500_status(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=500)]
        with patch("shutil.which", return_value="/usr/bin/ffuf"):
            result = discover_paths(endpoints)
        assert result == []

    def test_missing_binary_raises_oserror(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        with patch("shutil.which", return_value=None):
            with pytest.raises(OSError, match="ffuf"):
                discover_paths(endpoints)

    def test_ffuf_exception_is_swallowed(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=Exception("connection refused")),
        ):
            result = discover_paths(endpoints)
        assert result == []

    def test_respects_status_codes_from_results(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        hits = [{"url": f"https://{target_apex}/protected", "status": 403}]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=self._ffuf_side_effect(hits)),
        ):
            result = discover_paths(endpoints)

        assert len(result) == 1
        assert result[0].status_code == 403

    def test_empty_ffuf_results_returns_empty(self, target_apex):
        endpoints = [Endpoint(url=f"https://{target_apex}/", status_code=200)]
        with (
            patch("shutil.which", return_value="/usr/bin/ffuf"),
            patch("subprocess.run", side_effect=self._ffuf_side_effect([])),
        ):
            result = discover_paths(endpoints)
        assert result == []
