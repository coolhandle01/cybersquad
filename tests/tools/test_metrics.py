"""tests/tools/test_metrics.py - unit tests for tools/metrics.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tools.metrics import build_run_metrics, estimate_cost, parse_llm, print_metrics, save_metrics

pytestmark = pytest.mark.unit


class TestParseLlm:
    def test_with_provider(self) -> None:
        assert parse_llm("anthropic/claude-sonnet-4") == ("anthropic", "claude-sonnet-4")

    def test_without_provider(self) -> None:
        assert parse_llm("claude-sonnet-4") == ("", "claude-sonnet-4")

    def test_multiple_slashes_uses_last(self) -> None:
        assert parse_llm("org/team/claude-sonnet-4") == ("org/team", "claude-sonnet-4")


class TestEstimateCost:
    def test_sonnet_pricing(self) -> None:
        cost = estimate_cost("claude-sonnet-4-20250514", 1_000_000, 1_000_000)
        assert cost == pytest.approx(18.00)

    def test_legacy_opus_pricing(self) -> None:
        # Opus 4 (base, deprecated): $15 in + $75 out per 1M.
        cost = estimate_cost("claude-opus-4-20250514", 1_000_000, 1_000_000)
        assert cost == pytest.approx(90.00)

    def test_current_opus_pricing_does_not_collide_with_legacy(self) -> None:
        # Opus 4.5+ is $5 in + $25 out; the longest-prefix match must beat the
        # shorter legacy "claude-opus-4" key rather than billing $90.
        cost = estimate_cost("claude-opus-4-5", 1_000_000, 1_000_000)
        assert cost == pytest.approx(30.00)

    def test_longest_prefix_wins_independent_of_pricing_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The real _PRICING happens to list every specific key before its
        # shorter legacy prefix, so a first-match loop would coincidentally pass
        # the case above. Pin the actual max(..., key=len) tie-break with an
        # adversarial table: the *shorter* prefix is inserted FIRST, so a naive
        # first-match iteration bills the wrong ($9) rate. Assert both orderings
        # resolve to the longer key, so the resolution is order-independent.
        from tools import metrics

        short_first = {"brand-x": (9.0, 0.0), "brand-x-pro": (1.0, 0.0)}
        monkeypatch.setattr(metrics, "_PRICING", short_first)
        assert metrics.estimate_cost("brand-x-pro-mini", 1_000_000, 0) == pytest.approx(1.0)

        long_first = {"brand-x-pro": (1.0, 0.0), "brand-x": (9.0, 0.0)}
        monkeypatch.setattr(metrics, "_PRICING", long_first)
        assert metrics.estimate_cost("brand-x-pro-mini", 1_000_000, 0) == pytest.approx(1.0)

    def test_haiku_pricing(self) -> None:
        # Haiku 4.5: $1 in + $5 out per 1M (not the legacy 3.5 rate).
        cost = estimate_cost("claude-haiku-4-5-20251001", 1_000_000, 1_000_000)
        assert cost == pytest.approx(6.00)

    def test_zero_tokens(self) -> None:
        assert estimate_cost("claude-sonnet-4-20250514", 0, 0) == 0.0

    def test_provider_prefix_stripped(self) -> None:
        cost_bare = estimate_cost("claude-sonnet-4-6", 1_000_000, 1_000_000)
        cost_prefixed = estimate_cost("anthropic/claude-sonnet-4-6", 1_000_000, 1_000_000)
        assert cost_prefixed == pytest.approx(cost_bare)
        assert cost_prefixed > 0

    def test_unknown_model_returns_zero(self) -> None:
        assert estimate_cost("gpt-4o", 1_000_000, 1_000_000) == 0.0

    def test_input_output_weighted_separately(self) -> None:
        # Only output tokens: sonnet output = $15/1M
        cost = estimate_cost("claude-sonnet-4-20250514", 0, 1_000_000)
        assert cost == pytest.approx(15.00)


class TestBuildRunMetrics:
    def _started(self) -> datetime:
        return datetime.now(UTC) - timedelta(seconds=10)

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
        started = datetime.now(UTC) - timedelta(seconds=5)
        m = build_run_metrics("test-run", started, "claude-sonnet-4-20250514", 100, 50)
        out = save_metrics(m, tmp_path)
        # metrics.json lands directly in the run dir it is handed - alongside
        # programme.json - not in a nested reports/<run_id>/ folder.
        assert out == tmp_path / "metrics.json"
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["run_id"] == "test-run"
        assert data["total_tokens"] == 150

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        started = datetime.now(UTC) - timedelta(seconds=1)
        m = build_run_metrics("nested-run", started, "claude-haiku-4-5-20251001", 0, 0)
        out = save_metrics(m, tmp_path / "new" / "dir")
        assert out.exists()


class TestPrintMetrics:
    def test_prints_without_error(self, capsys: pytest.CaptureFixture) -> None:
        started = datetime.now(UTC) - timedelta(seconds=3)
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
