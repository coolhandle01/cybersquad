"""
tests/test_scan_mode.py - unit tests for SCAN_MODE config and adaptive_sleep.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


class TestScanMode:
    def test_invalid_mode_raises(self):
        from config import ScanMode

        with pytest.raises(ValueError):
            ScanMode("turbo")

    # Per-mode env vars that the recon-side tunings honour. Listed once
    # here and threaded into every mode-set test so a new field gets
    # picked up across all three modes in lockstep.
    _RECON_MODE_ENV_VARS = (
        "SCAN_DELAY",
        "NUCLEI_RATE_LIMIT",
        "DIRFUZZ_RATE_LIMIT",
        "DIRFUZZ_THREADS",
        "SQLMAP_LEVEL",
        "SQLMAP_RISK",
        "HTTPX_RATE_LIMIT",
        "HTTPX_RETRIES",
        "HTTPX_THREADS",
        "DNSX_RATE_LIMIT",
        "DNSX_THREADS",
        "SUBFINDER_RATE_LIMIT",
        "SUBFINDER_THREADS",
        "SUBFINDER_ACTIVE",
        "TRACEROUTE_ENABLED",
        "TLS_ENABLED",
    )

    def test_stealth_sets_conservative_defaults(self, monkeypatch):
        monkeypatch.setenv("SCAN_MODE", "stealth")
        for var in self._RECON_MODE_ENV_VARS:
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.request_delay == 2.0
        assert c.nuclei_rate_limit == 2
        assert c.dirfuzz_rate_limit == 5
        assert c.dirfuzz_threads == 5
        assert c.sqlmap_level == 1
        assert c.sqlmap_risk == 1
        assert c.httpx_rate_limit == 20
        assert c.httpx_retries == 1
        assert c.httpx_threads == 10
        assert c.dnsx_rate_limit == 50
        assert c.dnsx_threads == 10
        assert c.subfinder_rate_limit == 10
        assert c.subfinder_threads == 5
        assert c.subfinder_active is False
        assert c.traceroute_enabled is False
        assert c.tls_enabled is False

    def test_normal_preserves_existing_defaults(self, monkeypatch):
        monkeypatch.setenv("SCAN_MODE", "normal")
        for var in self._RECON_MODE_ENV_VARS:
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.request_delay == 0.5
        assert c.nuclei_rate_limit == 10
        assert c.dirfuzz_rate_limit == 20
        assert c.dirfuzz_threads == 40
        assert c.sqlmap_level == 2
        assert c.httpx_rate_limit == 150
        assert c.httpx_retries == 2
        assert c.httpx_threads == 50
        assert c.dnsx_rate_limit == 500
        assert c.dnsx_threads == 50
        assert c.subfinder_rate_limit == 50
        assert c.subfinder_threads == 10
        assert c.subfinder_active is True
        assert c.traceroute_enabled is True
        assert c.tls_enabled is True

    def test_raid_sets_aggressive_defaults(self, monkeypatch):
        monkeypatch.setenv("SCAN_MODE", "raid")
        for var in self._RECON_MODE_ENV_VARS:
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.request_delay == 0.05
        assert c.nuclei_rate_limit == 100
        assert c.dirfuzz_rate_limit == 150
        assert c.dirfuzz_threads == 80
        assert c.sqlmap_level == 3
        assert c.sqlmap_risk == 2
        assert c.httpx_rate_limit == 500
        assert c.httpx_retries == 3
        assert c.httpx_threads == 100
        assert c.dnsx_rate_limit == 2000
        assert c.dnsx_threads == 100
        assert c.subfinder_rate_limit == 200
        assert c.subfinder_threads == 20
        assert c.subfinder_active is True
        assert c.traceroute_enabled is True
        assert c.tls_enabled is True

    def test_explicit_httpx_rate_overrides_mode(self, monkeypatch):
        """Explicit env override wins over mode for a recon-side field too."""
        monkeypatch.setenv("SCAN_MODE", "stealth")
        monkeypatch.setenv("HTTPX_RATE_LIMIT", "777")
        for var in self._RECON_MODE_ENV_VARS:
            if var == "HTTPX_RATE_LIMIT":
                continue
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.httpx_rate_limit == 777
        # The other STEALTH defaults still apply.
        assert c.httpx_retries == 1
        assert c.traceroute_enabled is False

    def test_explicit_traceroute_enabled_overrides_stealth(self, monkeypatch):
        """The bool gates honour the explicit env override the same way ints do."""
        monkeypatch.setenv("SCAN_MODE", "stealth")
        monkeypatch.setenv("TRACEROUTE_ENABLED", "true")
        for var in self._RECON_MODE_ENV_VARS:
            if var == "TRACEROUTE_ENABLED":
                continue
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.traceroute_enabled is True
        # tls_enabled stayed off (the other STEALTH default).
        assert c.tls_enabled is False

    def test_explicit_env_var_wins_over_mode(self, monkeypatch):
        monkeypatch.setenv("SCAN_MODE", "stealth")
        monkeypatch.setenv("NUCLEI_RATE_LIMIT", "50")
        monkeypatch.delenv("SCAN_DELAY", raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.nuclei_rate_limit == 50  # explicit wins
        assert c.request_delay == 2.0  # mode default applies

    def test_default_mode_is_normal(self, monkeypatch):
        monkeypatch.delenv("SCAN_MODE", raising=False)
        for var in ("SCAN_DELAY", "NUCLEI_RATE_LIMIT"):
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.scan_mode == "normal"
        assert c.request_delay == 0.5


class TestAdaptiveSleep:
    def test_sleeps_for_given_delay(self, monkeypatch, reload_module):
        import config as cfg_module

        reload_module(cfg_module)
        from tools._helpers import adaptive_sleep

        with patch("time.sleep") as mock_sleep:
            adaptive_sleep(1.0, 200)
        mock_sleep.assert_called_once_with(1.0)

    def test_429_doubles_delay(self, monkeypatch):
        monkeypatch.delenv("SCAN_MODE", raising=False)
        monkeypatch.delenv("SCAN_DELAY", raising=False)
        from tools._helpers import adaptive_sleep

        with patch("time.sleep"):
            new_delay = adaptive_sleep(1.0, 429)
        assert new_delay == 2.0

    def test_429_caps_at_60_seconds(self, monkeypatch):
        from tools._helpers import adaptive_sleep

        with patch("time.sleep"):
            new_delay = adaptive_sleep(50.0, 429)
        assert new_delay == 60.0

    def test_200_recovers_elevated_delay(self, monkeypatch, reload_module):
        monkeypatch.delenv("SCAN_MODE", raising=False)
        monkeypatch.setenv("SCAN_DELAY", "0.5")
        import config as cfg_module

        reload_module(cfg_module)
        from tools._helpers import adaptive_sleep

        with patch("time.sleep"):
            new_delay = adaptive_sleep(10.0, 200)
        # should recover towards base (0.5) by 10%
        assert new_delay == pytest.approx(9.0, rel=0.01)

    def test_200_at_base_delay_stays_constant(self, monkeypatch, reload_module):
        monkeypatch.setenv("SCAN_DELAY", "0.5")
        import config as cfg_module

        reload_module(cfg_module)
        from tools._helpers import adaptive_sleep

        with patch("time.sleep"):
            new_delay = adaptive_sleep(0.5, 200)
        assert new_delay == 0.5

    def test_recovery_does_not_go_below_base(self, monkeypatch, reload_module):
        monkeypatch.setenv("SCAN_DELAY", "0.5")
        import config as cfg_module

        reload_module(cfg_module)
        from tools._helpers import adaptive_sleep

        # elevated by only a hair above base
        with patch("time.sleep"):
            new_delay = adaptive_sleep(0.51, 200)
        assert new_delay >= 0.5
