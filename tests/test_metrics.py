"""tests/test_metrics.py — unit tests for tools/metrics.py."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tools.metrics import build_run_metrics, estimate_cost, print_metrics, save_metrics

pytestmark = pytest.mark.unit


class TestEstimateCost:
    def test_sonnet_pricing(self) -> None:
        cost = estimate_cost("claude-sonnet-4-20250514", 1_000_000, 1_000_000)
        assert cost == pytest.approx(18.00)

    def test_opus_pricing(self) -> None:
        cost = estimate_cost("claude-opus-4-20250514", 1_000_000, 1_000_000)
        assert cost == pytest.approx(90.00)

    def test_haiku_pricing(self) -> None:
        cost = estimate_cost("claude-haiku-4-5-20251001", 1_000_000, 1_000_000)
        assert cost == pytest.approx(4.80)

    def test_zero_tokens(self) -> None:
        assert estimate_cost("claude-sonnet-4-20250514", 0, 0) == 0.0

    def test_unknown_model_returns_zero(self) -> None:
        assert estimate_cost("gpt-4o", 1_000_000, 1_000_000) == 0.0

    def test_input_output_weighted_separately(self) -> None:
        # Only output tokens: sonnet output = $15/1M
        cost = estimate_cost("claude-sonnet-4-20250514", 0, 1_000_000)
        assert cost == pytest.approx(15.00)


class TestBuildRunMetrics:
    def _started(self) -> datetime:
        return datetime.utcnow() - timedelta(seconds=10)

    def test_duration_is_positive(self) -> None:
        m = build_run_metrics("r1", self._started(), "claude-sonnet-4-20250514", 100, 50)
        assert m.duration_seconds > 0

    def test_total_tokens_summed(self) -> None:
        m = build_run_metrics("r1", self._started(), "claude-sonnet-4-20250514", 300, 200)
        assert m.total_tokens == 500

    def test_cost_populated(self) -> None:
        m = build_run_metrics("r1", self._started(), "claude-sonnet-4-20250514", 1_000_000, 0)
        assert m.estimated_cost_usd == pytest.approx(3.00)

    def test_optional_fields_default(self) -> None:
        m = build_run_metrics("r1", self._started(), "claude-sonnet-4-20250514", 0, 0)
        assert m.programme_handle is None
        assert m.submitted is False
        assert m.findings_raw == 0


class TestSaveMetrics:
    def test_writes_valid_json(self, tmp_path: Path) -> None:
        started = datetime.utcnow() - timedelta(seconds=5)
        m = build_run_metrics("test-run", started, "claude-sonnet-4-20250514", 100, 50)
        out = save_metrics(m, str(tmp_path))
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["run_id"] == "test-run"
        assert data["total_tokens"] == 150

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        started = datetime.utcnow() - timedelta(seconds=1)
        m = build_run_metrics("nested-run", started, "claude-haiku-4-5-20251001", 0, 0)
        out = save_metrics(m, str(tmp_path / "new" / "dir"))
        assert out.exists()


class TestPrintMetrics:
    def test_prints_without_error(self, capsys: pytest.CaptureFixture) -> None:
        started = datetime.utcnow() - timedelta(seconds=3)
        m = build_run_metrics(
            "print-test",
            started,
            "claude-sonnet-4-20250514",
            500,
            250,
            programme_handle="acme",
            submitted=True,
        )
        print_metrics(m)
        out = capsys.readouterr().out
        assert "print-test" in out
        assert "acme" in out
        assert "750" in out  # total tokens
