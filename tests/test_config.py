"""
tests/test_config.py — unit tests for config.py
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


class TestH1Config:
    def test_reads_api_credentials_from_env(self, monkeypatch):
        monkeypatch.setenv("H1_API_USERNAME", "testuser")
        monkeypatch.setenv("H1_API_TOKEN", "testtoken")
        import importlib

        import config as cfg_module

        importlib.reload(cfg_module)
        c = cfg_module.H1Config()
        assert c.api_username == "testuser"
        assert c.api_token == "testtoken"

    def test_custom_min_bounty(self, monkeypatch):
        monkeypatch.setenv("H1_MIN_BOUNTY", "1000")
        from config import H1Config

        c = H1Config()
        assert c.min_bounty_threshold == 1000

    def test_missing_credentials_raises(self, monkeypatch):
        monkeypatch.delenv("H1_API_USERNAME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)
        with pytest.raises(KeyError):
            from config import H1Config

            H1Config()


class TestLLMConfig:
    def test_defaults(self, monkeypatch):
        monkeypatch.delenv("CREWAI_MODEL", raising=False)
        monkeypatch.delenv("CREWAI_TEMPERATURE", raising=False)
        monkeypatch.delenv("CREWAI_MAX_TOKENS", raising=False)
        from config import LLMConfig

        c = LLMConfig()
        assert "claude" in c.model
        assert c.temperature == 0.2
        assert c.max_tokens == 4096

    def test_custom_temperature(self, monkeypatch):
        monkeypatch.setenv("CREWAI_TEMPERATURE", "0.7")
        from config import LLMConfig

        c = LLMConfig()
        assert c.temperature == 0.7


class TestScanConfig:
    def test_defaults(self, monkeypatch):
        for var in [
            "MIN_SEVERITY",
            "SCAN_DELAY",
            "NUCLEI_RATE_LIMIT",
            "SQLMAP_LEVEL",
            "SQLMAP_RISK",
            "SQLMAP_OUTPUT_DIR",
        ]:
            monkeypatch.delenv(var, raising=False)
        from config import ScanConfig

        c = ScanConfig()
        assert c.min_severity == "medium"
        assert c.sqlmap_level == 2
        assert c.sqlmap_risk == 1
        assert c.nuclei_rate_limit == 10
        assert c.request_delay == 0.5

    def test_custom_severity(self, monkeypatch):
        monkeypatch.setenv("MIN_SEVERITY", "high")
        from config import ScanConfig

        c = ScanConfig()
        assert c.min_severity == "high"

    def test_sqlmap_output_dir_configurable(self, monkeypatch):
        monkeypatch.setenv("SQLMAP_OUTPUT_DIR", "/var/tmp/sqlmap")
        from config import ScanConfig

        c = ScanConfig()
        assert c.sqlmap_output_dir == "/var/tmp/sqlmap"


class TestAppConfig:
    def test_reports_dir_configurable(self, monkeypatch):
        monkeypatch.setenv("REPORTS_DIR", "/var/reports")
        from config import AppConfig

        c = AppConfig()
        assert c.reports_dir == "/var/reports"

    def test_verbose_defaults_false(self, monkeypatch):
        monkeypatch.delenv("VERBOSE", raising=False)
        from config import AppConfig

        c = AppConfig()
        assert c.verbose is False
