"""
tui.py - Cybersquad Textual TUI.

Binds the generic crewui.CrewAIPipelineTUI to cybersquad: the crew, the
role -> phase mapping, and the two app-specific callbacks crewui injects -
recording the run id in ``runtime`` and computing/persisting run metrics for
the sidebar. Launch with: python main.py (default) or python main.py
--headless to skip the TUI.
"""

from __future__ import annotations

from datetime import datetime

from crewui import CrewAIPipelineTUI, format_metrics_block

from mcp_servers import ProvisionedMCPTools


def _bind_run_id(run_id: str) -> None:
    """crewui ``on_run_start``: record the run id the TUI generated.

    Routed through ``runtime.bind_run_id`` so the single-pipeline-at-a-time
    invariant (see runtime.py / #128) applies to TUI runs too.
    """
    import runtime

    runtime.bind_run_id(run_id)


def _save_and_format_metrics(result: object, run_id: str, started_at: datetime) -> str | None:
    """crewui ``on_run_complete``: persist run metrics and format the sidebar
    block, or ``None`` when there is nothing to show.

    Returns ``None`` when the crew produced no token usage, or when writing
    metrics.json fails - in either case the sidebar metrics widget is left
    untouched.
    """
    from config import config
    from tools.metrics import build_run_metrics, save_metrics

    usage = getattr(result, "token_usage", None)
    if usage is None:
        return None

    metrics = build_run_metrics(
        run_id=run_id,
        started_at=started_at,
        llm_model=config.llm.model,
        input_tokens=getattr(usage, "prompt_tokens", 0),
        output_tokens=getattr(usage, "completion_tokens", 0),
    )
    try:
        save_metrics(metrics, config.reports_dir)
    except OSError:
        return None
    return format_metrics_block(
        total_tokens=metrics.total_tokens,
        estimated_cost_usd=metrics.estimated_cost_usd,
        run_id=run_id,
    )


class CybersquadTUI(CrewAIPipelineTUI):
    CSS_PATH = "tui.tcss"

    def __init__(
        self,
        verbose: bool = False,
        dry_run: bool = False,
        mcp_tools: ProvisionedMCPTools | None = None,
    ) -> None:
        from crew import build_crew, crew_phases

        super().__init__(
            crew=build_crew(verbose=verbose, mcp_tools=mcp_tools),
            phases=crew_phases(),
            record_prefix="cybersquad",
            verbose=verbose,
            dry_run=dry_run,
            on_run_start=_bind_run_id,
            on_run_complete=_save_and_format_metrics,
        )
