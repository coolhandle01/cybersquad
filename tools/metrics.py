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

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
    # Strip litellm provider prefix (e.g. "anthropic/claude-sonnet-4-…" → "claude-sonnet-4-…")
    bare = model.split("/", 1)[-1]
    for prefix, (in_price, out_price) in _PRICING.items():
        if bare.startswith(prefix):
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
    h1_report_id: str | None = None,
    h1_report_url: str | None = None,
    bounty_awarded_usd: float | None = None,
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
        h1_report_id=h1_report_id,
        h1_report_url=h1_report_url,
        bounty_awarded_usd=bounty_awarded_usd,
    )


def print_metrics(metrics: RunMetrics) -> None:
    """Render a rich run-report panel to stdout."""
    console = Console()

    tbl = Table(box=None, show_header=False, padding=(0, 2))
    tbl.add_column(style="dim", min_width=16)
    tbl.add_column()

    tbl.add_row("Run ID", metrics.run_id)
    tbl.add_row("Programme", metrics.programme_handle or "—")
    tbl.add_row("Model", metrics.llm_model)
    tbl.add_row("Duration", f"{metrics.duration_seconds:.1f}s")
    tbl.add_row(
        "Findings",
        f"{metrics.findings_raw} raw  ·  {metrics.findings_verified} verified",
    )
    submitted_cell = "[green]yes[/green]" if metrics.submitted else "[dim]no[/dim]"
    tbl.add_row("Submitted", submitted_cell)
    if metrics.h1_report_id:
        tbl.add_row("Report ID", metrics.h1_report_id)
    if metrics.h1_report_url:
        tbl.add_row("Report URL", metrics.h1_report_url)

    tbl.add_section()
    tbl.add_row("Input tokens", f"{metrics.input_tokens:,}")
    tbl.add_row("Output tokens", f"{metrics.output_tokens:,}")
    tbl.add_row("Total tokens", f"[bold]{metrics.total_tokens:,}[/bold]")
    tbl.add_row("Est. cost", f"[red]-${metrics.estimated_cost_usd:.4f}[/red]")

    tbl.add_section()
    if metrics.bounty_awarded_usd is not None:
        tbl.add_row("Bounty earned", f"[green]+${metrics.bounty_awarded_usd:.2f}[/green]")
        net = metrics.bounty_awarded_usd - metrics.estimated_cost_usd
        net_fmt = (
            f"[bold green]+${net:.2f}[/bold green]"
            if net >= 0
            else f"[bold red]-${abs(net):.2f}[/bold red]"
        )
        tbl.add_row("Net", net_fmt)
    else:
        tbl.add_row("Bounty earned", "[dim]awaiting triage[/dim]")

    console.print(
        Panel(
            tbl,
            title="[bold green]  Bounty Squad — Run Report  [/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )


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
