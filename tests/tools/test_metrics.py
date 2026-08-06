"""tests/tools/test_metrics.py - unit tests for tools/metrics.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from models import RunMetrics
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

    def test_exact_quotient_no_denominator_drift(self) -> None:
        # 1M in + 1M out at sonnet (3.00 + 15.00) is exactly 18.0 - the
        # quotient is representable, so an exact `==` pins the per-1M divisor.
        # A perturbed denominator (e.g. /1000001) yields 17.999982 and reddens.
        assert estimate_cost("claude-sonnet-4-20250514", 1_000_000, 1_000_000) == 18.0

    def test_opus_pricing(self) -> None:
        cost = estimate_cost("claude-opus-4-20250514", 1_000_000, 1_000_000)
        assert cost == pytest.approx(90.00)

    def test_haiku_pricing(self) -> None:
        cost = estimate_cost("claude-haiku-4-5-20251001", 1_000_000, 1_000_000)
        assert cost == pytest.approx(4.80)

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
        assert m.findings_verified == 0

    def test_all_fields_wired_through(self) -> None:
        # Every argument must reach the matching RunMetrics field. Distinct
        # values (input != output, findings_raw != findings_verified) so a
        # dropped or transposed kwarg reddens rather than coinciding.
        m = build_run_metrics(
            "r-wire",
            self._started(),
            "claude-sonnet-4-20250514",
            input_tokens=1500,
            output_tokens=900,
            programme_handle="acme",
            findings_raw=7,
            findings_verified=3,
            submitted=True,
        )
        assert m.run_id == "r-wire"
        assert m.input_tokens == 1500
        assert m.output_tokens == 900
        assert m.programme_handle == "acme"
        assert m.findings_raw == 7
        assert m.findings_verified == 3
        assert m.submitted is True


class TestSaveMetrics:
    def test_writes_valid_json(self, tmp_path: Path) -> None:
        started = datetime.now(UTC) - timedelta(seconds=5)
        m = build_run_metrics("test-run", started, "claude-sonnet-4-20250514", 100, 50)
        out = save_metrics(m, str(tmp_path))
        assert out.exists()
        assert out.name == "metrics.json"
        text = out.read_text()
        # Pretty-printed with indent=2: file opens with a brace, newline, and a
        # two-space indent before the first key. Pins the on-disk format so a
        # dropped/changed indent (compact JSON, or a different width) reddens.
        assert text.startswith('{\n  "')
        data = json.loads(text)
        assert data["run_id"] == "test-run"
        assert data["total_tokens"] == 150

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        started = datetime.now(UTC) - timedelta(seconds=1)
        m = build_run_metrics("nested-run", started, "claude-haiku-4-5-20251001", 0, 0)
        out = save_metrics(m, str(tmp_path / "new" / "dir"))
        assert out.exists()

    def test_resave_same_run_overwrites(self, tmp_path: Path) -> None:
        # Second save reuses the already-created <run_id> directory, so the
        # mkdir must tolerate an existing parent (exist_ok=True). A dropped or
        # falsified exist_ok raises FileExistsError on the second call.
        started = datetime.now(UTC) - timedelta(seconds=5)
        m = build_run_metrics("dup-run", started, "claude-sonnet-4-20250514", 100, 50)
        first = save_metrics(m, str(tmp_path))
        second = save_metrics(m, str(tmp_path))
        assert second == first
        assert second.exists()


class TestPrintMetrics:
    # A fixed instant so duration/rows are fully deterministic - print_metrics
    # renders stored fields, it does not compute time, so both timestamps can
    # be the same frozen value.
    _INSTANT = datetime(2026, 1, 1, tzinfo=UTC)
    _SEP = "-" * 50

    def _metrics(self, **overrides: object) -> RunMetrics:
        base: dict[str, object] = {
            "run_id": "print-test",
            "started_at": self._INSTANT,
            "completed_at": self._INSTANT,
            "duration_seconds": 3.5,
            "llm_model": "claude-sonnet-4-20250514",
            "programme_handle": "acme",
            "input_tokens": 1500,
            "output_tokens": 900,
            "total_tokens": 2400,
            "estimated_cost_usd": 0.0186,
            "findings_raw": 7,
            "findings_verified": 3,
            "submitted": True,
        }
        base.update(overrides)
        return RunMetrics(**base)  # type: ignore[arg-type]

    def test_prints_without_error(self, capsys: pytest.CaptureFixture) -> None:
        # Preserve the build_run_metrics -> print_metrics smoke path (real,
        # clock-derived duration); the exact-render pins below carry the
        # observation.
        started = datetime.now(UTC) - timedelta(seconds=3)
        m = build_run_metrics(
            "print-test", started, "claude-sonnet-4-20250514", 500, 250, submitted=True
        )
        print_metrics(m)
        assert "print-test" in capsys.readouterr().out

    def test_full_render(self, capsys: pytest.CaptureFixture) -> None:
        # Pin the entire rendered block. Every label, row and value is asserted
        # exhaustively, so a mislabelled row, a swapped input/output line
        # (1,500 vs 900 differ), a wrong cost format, or a changed separator
        # all redden. `submitted=True` renders the "yes" branch.
        print_metrics(self._metrics())
        out = capsys.readouterr().out
        expected = (
            "\n" + self._SEP + "\n"
            "  SQUAD METRICS\n" + self._SEP + "\n"
            "  Run ID       : print-test\n"
            "  Programme    : acme\n"
            "  Duration     : 3.5s\n"
            "  Model        : claude-sonnet-4-20250514\n"
            "  Input tokens : 1,500\n"
            "  Output tokens: 900\n"
            "  Total tokens : 2,400\n"
            "  Est. cost    : $0.0186\n"
            "  Raw findings : 7\n"
            "  Verified     : 3\n"
            "  Submitted    : yes\n" + self._SEP + "\n\n"
        )
        assert out == expected

    def test_render_missing_programme_and_not_submitted(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        # The two branches the happy-path render cannot reach: a None programme
        # falls back to "-", and submitted=False renders the "no" branch.
        print_metrics(
            self._metrics(
                run_id="r0",
                duration_seconds=0.0,
                llm_model="claude-haiku-4",
                programme_handle=None,
                input_tokens=0,
                output_tokens=0,
                total_tokens=0,
                estimated_cost_usd=0.0,
                findings_raw=0,
                findings_verified=0,
                submitted=False,
            )
        )
        out = capsys.readouterr().out
        expected = (
            "\n" + self._SEP + "\n"
            "  SQUAD METRICS\n" + self._SEP + "\n"
            "  Run ID       : r0\n"
            "  Programme    : -\n"
            "  Duration     : 0.0s\n"
            "  Model        : claude-haiku-4\n"
            "  Input tokens : 0\n"
            "  Output tokens: 0\n"
            "  Total tokens : 0\n"
            "  Est. cost    : $0.0000\n"
            "  Raw findings : 0\n"
            "  Verified     : 0\n"
            "  Submitted    : no\n" + self._SEP + "\n\n"
        )
        assert out == expected
