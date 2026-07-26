"""tests/tools/recon/test_waybackurls.py - unit tests for
tools/recon/waybackurls.py.

Historical-URL discovery via the ``waybackurls`` binary: parse stdout
into a URL list, raise when the binary is missing, tolerate empty output.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.recon.waybackurls import historical_urls

pytestmark = pytest.mark.unit


class TestHistoricalUrls:
    def test_returns_urls_from_binary_output(self, target_apex):
        mock_proc = MagicMock()
        mock_proc.stdout = f"https://{target_apex}/old-path\nhttps://example.com/another\n"
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/waybackurls"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = historical_urls("example.com")

        assert f"https://{target_apex}/old-path" in result
        assert f"https://{target_apex}/another" in result

    def test_missing_binary_raises(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(OSError, match="waybackurls"):
                historical_urls("example.com")

    def test_empty_output_returns_empty_list(self):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/waybackurls"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = historical_urls("example.com")

        assert result == []
