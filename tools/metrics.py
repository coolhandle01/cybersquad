"""
tools/metrics.py — Token-usage accounting and cost estimation.

Anthropic pricing is expressed per 1 M tokens; the table below reflects
rates as of 2026-04. Update the table when pricing changes — do not
hardcode rates elsewhere.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from models import RunMetrics

logger = logging.getLogger(__name__)

# (input_usd_per_1m, output_usd_per_1m)
_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4": (15.00, 75.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-haiku-4": (0.80, 4.00),
}


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Return estimated USD cost for the given token counts and model."""
    for prefix, (in_price, out_price) in _PRICING.items():
        if model.startswith(prefix):
            return (input_tokens * in_price + output_tokens * out_price) / 1_000_000
    logger.warning("No pricing entry for model %r — cost will show as $0.00", model)
    return 0.0


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
    completed_at = datetime.utcnow()
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
    print("\n" + "━" * 50)
    print("  SQUAD METRICS")
    print("━" * 50)
    print(f"  Run ID       : {metrics.run_id}")
    print(f"  Programme    : {metrics.programme_handle or '—'}")
    print(f"  Duration     : {metrics.duration_seconds:.1f}s")
    print(f"  Model        : {metrics.llm_model}")
    print(f"  Input tokens : {metrics.input_tokens:,}")
    print(f"  Output tokens: {metrics.output_tokens:,}")
    print(f"  Total tokens : {metrics.total_tokens:,}")
    print(f"  Est. cost    : ${metrics.estimated_cost_usd:.4f}")
    print(f"  Raw findings : {metrics.findings_raw}")
    print(f"  Verified     : {metrics.findings_verified}")
    print(f"  Submitted    : {'yes' if metrics.submitted else 'no'}")
    print("━" * 50 + "\n")


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
