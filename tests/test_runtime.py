"""tests/test_runtime.py - unit tests for runtime.py"""

from __future__ import annotations

import pytest

import runtime

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def reset_runtime():
    """Restore module globals after each test."""
    yield
    runtime.run_id = ""
    runtime.programme_handle = ""


class TestRunDir:
    def test_returns_correct_path(self, monkeypatch, tmp_path):
        monkeypatch.setattr("config.config.reports_dir", str(tmp_path))
        runtime.programme_handle = "acme"
        runtime.run_id = "20260517-120000-abc123"

        result = runtime.run_dir()

        assert result == tmp_path / "programs" / "acme" / "20260517-120000-abc123"

    def test_raises_when_handle_unset(self, monkeypatch, tmp_path):
        monkeypatch.setattr("config.config.reports_dir", str(tmp_path))
        runtime.run_id = "20260517-120000-abc123"

        with pytest.raises(RuntimeError, match="programme_handle"):
            runtime.run_dir()

    def test_raises_when_run_id_unset(self, monkeypatch, tmp_path):
        monkeypatch.setattr("config.config.reports_dir", str(tmp_path))
        runtime.programme_handle = "acme"

        with pytest.raises(RuntimeError, match="run_id"):
            runtime.run_dir()

    def test_raises_when_both_unset(self, monkeypatch, tmp_path):
        monkeypatch.setattr("config.config.reports_dir", str(tmp_path))

        with pytest.raises(RuntimeError):
            runtime.run_dir()


class TestBindRunId:
    def test_binds_when_unset(self):
        runtime.bind_run_id("20260517-120000-abc123")
        assert runtime.run_id == "20260517-120000-abc123"

    def test_same_value_rebind_is_noop(self):
        runtime.bind_run_id("20260517-120000-abc123")
        runtime.bind_run_id("20260517-120000-abc123")
        assert runtime.run_id == "20260517-120000-abc123"

    def test_conflicting_rebind_raises(self):
        runtime.bind_run_id("20260517-120000-abc123")
        with pytest.raises(RuntimeError, match="#128"):
            runtime.bind_run_id("20260517-120000-deadbe")
        assert runtime.run_id == "20260517-120000-abc123"


class TestBindProgramme:
    def test_binds_when_unset(self):
        runtime.bind_programme("acme")
        assert runtime.programme_handle == "acme"

    def test_same_value_rebind_is_noop(self):
        runtime.bind_programme("acme")
        runtime.bind_programme("acme")
        assert runtime.programme_handle == "acme"

    def test_conflicting_rebind_raises(self):
        runtime.bind_programme("acme")
        with pytest.raises(RuntimeError, match="#128"):
            runtime.bind_programme("globex")
        assert runtime.programme_handle == "acme"


class TestProgrammeCachePath:
    def test_returns_correct_path(self, monkeypatch, tmp_path):
        monkeypatch.setattr("config.config.reports_dir", str(tmp_path))

        result = runtime.programme_cache_path("acme")

        assert result == tmp_path / "programs" / "acme" / "programme.json"

    def test_uses_provided_handle_not_global(self, monkeypatch, tmp_path):
        monkeypatch.setattr("config.config.reports_dir", str(tmp_path))
        runtime.programme_handle = "other"

        result = runtime.programme_cache_path("acme")

        assert "acme" in str(result)
        assert "other" not in str(result)
