"""
tools/metrics.py - Token-usage accounting and cost estimation.

Anthropic publishes no pricing API (the Models API returns capabilities, not
rates), so per-1M-token rates live in the hand-maintained ``_PRICING`` table
below and nowhere else. The cost figure is therefore an *estimate* against a
dated snapshot - keep the "Last updated" stamp current when rates change.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from models import RunMetrics

logger = logging.getLogger(__name__)

# (input_usd_per_1m, output_usd_per_1m), keyed by model-name prefix.
# The LONGEST matching prefix wins (see estimate_cost), so legacy Opus 4 and
# current Opus 4.5+ resolve to their own rates instead of colliding.
#
# Last updated: 2026-06-06
# Source: https://platform.claude.com/docs/en/about-claude/pricing
_PRICING: dict[str, tuple[float, float]] = {
    # Opus 4.5 and later.
    "claude-opus-4-5": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    # Legacy Opus 4 / 4.1 (deprecated).
    "claude-opus-4": (15.00, 75.00),
    # Sonnet 4 / 4.5 / 4.6 share a rate.
    "claude-sonnet-4": (3.00, 15.00),
    # Haiku 4.5, then legacy Haiku 3.5.
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-haiku-3-5": (0.80, 4.00),
}


def parse_llm(llm: str) -> tuple[str, str]:
    """Split a litellm-format model string into (provider, model).

    "anthropic/claude-sonnet-4" -> ("anthropic", "claude-sonnet-4")
    "claude-sonnet-4"           -> ("", "claude-sonnet-4")
    """
    provider, _, model = llm.rpartition("/")
    return provider, model


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Return estimated USD cost for the given token counts and model.

    Resolves the rate by longest-matching ``_PRICING`` prefix, so a specific
    key (``claude-opus-4-5``) wins over a shorter legacy one (``claude-opus-4``)
    when both match. Unknown models warn and cost $0.00.
    """
    _, model_key = parse_llm(model)
    match = max(
        (prefix for prefix in _PRICING if model_key.startswith(prefix)),
        key=len,
        default=None,
    )
    if match is None:
        logger.warning("No pricing entry for model %r - cost will show as $0.00", model)
        return 0.0
    in_price, out_price = _PRICING[match]
    return (input_tokens * in_price + output_tokens * out_price) / 1_000_000


def build_run_metrics(
    run_id: str,
    started_at: datetime,
    llm_model: str,
    input_tokens: int,
    output_tokens: int,
    programme_handle: str | None = None,
    findings_raw: int = 0,
    findings_verified: int = 0,
    submitted: bool = False,
) -> RunMetrics:
    completed_at = datetime.now(UTC)
    return RunMetrics(
        run_id=run_id,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=(completed_at - started_at).total_seconds(),
        llm_model=llm_model,
        programme_handle=programme_handle,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
        estimated_cost_usd=estimate_cost(llm_model, input_tokens, output_tokens),
        findings_raw=findings_raw,
        findings_verified=findings_verified,
        submitted=submitted,
    )


def print_metrics(metrics: RunMetrics) -> None:
    """Print a human-readable run summary to stdout."""
    print("\n" + "-" * 50)
    print("  SQUAD METRICS")
    print("-" * 50)
    print(f"  Run ID       : {metrics.run_id}")
    print(f"  Programme    : {metrics.programme_handle or '-'}")
    print(f"  Duration     : {metrics.duration_seconds:.1f}s")
    print(f"  Model        : {metrics.llm_model}")
    print(f"  Input tokens : {metrics.input_tokens:,}")
    print(f"  Output tokens: {metrics.output_tokens:,}")
    print(f"  Total tokens : {metrics.total_tokens:,}")
    print(f"  Est. cost    : ${metrics.estimated_cost_usd:.4f}")
    print(f"  Raw findings : {metrics.findings_raw}")
    print(f"  Verified     : {metrics.findings_verified}")
    print(f"  Submitted    : {'yes' if metrics.submitted else 'no'}")
    print("-" * 50 + "\n")


def save_metrics(metrics: RunMetrics, reports_dir: str) -> Path:
    """Write metrics JSON to <reports_dir>/<run_id>/metrics.json."""
    out = Path(reports_dir) / metrics.run_id / "metrics.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(metrics.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    logger.info("Metrics saved to %s", out)
    return out
