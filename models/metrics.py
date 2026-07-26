"""
models.metrics - per-run operational metrics emitted after every pipeline
run.

Token usage, cost, and finding-funnel summary. Lives apart from the data
models so the metrics shape can evolve without touching the artefact
graph.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class RunMetrics(BaseModel):
    """Token usage, cost, and effectiveness summary for one pipeline run."""

    run_id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    llm_model: str
    programme_handle: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    findings_raw: int = 0
    findings_verified: int = 0
    submitted: bool = False
