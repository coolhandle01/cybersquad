"""
proposals/rich_demo.py — Mock-up of rich terminal output for Bounty Squad.

Run with:
    .venv/bin/python proposals/rich_demo.py

Shows three candidate UI patterns with simulated timing so you can
feel the pacing. No real API calls are made.
"""

from __future__ import annotations

import time

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.progress import Progress as RichProgress
from rich.rule import Rule
from rich.table import Table

console = Console()

AGENTS = [
    ("Programme Manager", "Selecting programmes", 1.2, 8_412, 1_203),
    ("OSINT Analyst", "Enumerating attack surface", 2.1, 14_890, 2_441),
    ("Penetration Tester", "Running nuclei / sqlmap", 3.4, 22_310, 3_890),
    ("Vulnerability Researcher", "Triaging findings", 1.8, 11_750, 2_105),
    ("Technical Author", "Writing disclosure report", 2.0, 18_640, 4_312),
    ("Disclosure Coordinator", "Submitting to HackerOne", 0.9, 6_210, 980),
]

MODEL = "anthropic/claude-sonnet-4-20250514"
IN_PRICE, OUT_PRICE = 3.00, 15.00  # USD per 1M tokens


def cost(inp: int, out: int) -> float:
    return (inp * IN_PRICE + out * OUT_PRICE) / 1_000_000


# ── DEMO 1 ────────────────────────────────────────────────────────────────────
# Live pipeline table — updates in place as each agent finishes.


def demo_live_pipeline() -> None:
    console.print(Rule("[bold cyan]DEMO 1 — Live pipeline progress[/bold cyan]"))
    console.print()

    STATUS_ICONS = {
        "waiting": "[dim]○[/dim]",
        "running": "[yellow]◉[/yellow]",
        "review": "[bold yellow]▶ awaiting your feedback[/bold yellow]",
        "done": "[green]✓[/green]",
    }

    rows: list[dict] = [
        {"name": name, "phase": phase, "status": "waiting", "in": 0, "out": 0, "dur": 0.0}
        for name, phase, *_ in AGENTS
    ]

    def build_table() -> Table:
        t = Table(box=None, padding=(0, 2), show_header=True, header_style="bold")
        t.add_column("", width=3)
        t.add_column("Agent", style="cyan", min_width=24)
        t.add_column("Phase", style="dim", min_width=28)
        t.add_column("In", justify="right", style="dim")
        t.add_column("Out", justify="right", style="dim")
        t.add_column("Cost", justify="right")
        t.add_column("Time", justify="right", style="dim")
        for r in rows:
            icon = STATUS_ICONS[r["status"]]
            c = f"[green]${cost(r['in'], r['out']):.4f}[/green]" if r["in"] else ""
            dur = f"{r['dur']:.1f}s" if r["dur"] else ""
            inp = f"{r['in']:,}" if r["in"] else ""
            out = f"{r['out']:,}" if r["out"] else ""
            t.add_row(icon, r["name"], r["phase"], inp, out, c, dur)
        return t

    with Live(build_table(), console=console, refresh_per_second=10) as live:
        for i, (name, _phase, duration, inp, out) in enumerate(AGENTS):
            rows[i]["status"] = "running"
            live.update(build_table())
            time.sleep(duration * 0.4)  # simulate work

            rows[i]["in"] = inp
            rows[i]["out"] = out
            rows[i]["dur"] = duration

            # Gates after Programme Manager and Technical Author
            if name in ("Programme Manager", "Technical Author"):
                rows[i]["status"] = "review"
                live.update(build_table())
                time.sleep(1.2)  # simulate operator reading

            rows[i]["status"] = "done"
            live.update(build_table())

    console.print()
    total_in = sum(r["in"] for r in rows)
    total_out = sum(r["out"] for r in rows)
    total_dur = sum(r["dur"] for r in rows)
    console.print(
        Panel(
            f"[bold]Total tokens[/bold]  {total_in + total_out:,}  "
            f"([dim]{total_in:,} in · {total_out:,} out[/dim])\n"
            f"[bold]Estimated cost[/bold]  [green]${cost(total_in, total_out):.4f}[/green]\n"
            f"[bold]Wall time[/bold]  {total_dur:.1f}s",
            title="[bold green]  Run complete  [/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )
    console.print()


# ── DEMO 2 ────────────────────────────────────────────────────────────────────
# Progress bar variant — better if you want a compact single-line feel.


def demo_progress_bar() -> None:
    console.print(Rule("[bold cyan]DEMO 2 — Progress bar variant[/bold cyan]"))
    console.print()

    with RichProgress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=32),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        overall = progress.add_task("Pipeline", total=len(AGENTS))
        for name, _phase, duration, _inp, _out in AGENTS:
            step = progress.add_task(f"  {name}", total=100)
            for _ in range(10):
                time.sleep(duration * 0.04)
                progress.advance(step, 10)
            progress.update(step, description=f"  [green]✓[/green] {name}")
            progress.advance(overall, 1)

    console.print()


# ── DEMO 3 ────────────────────────────────────────────────────────────────────
# Final run report — uses the real print_metrics() from tools/metrics.py.
# Shown twice: once immediately after submission (bounty pending),
# once after H1 pays out (so you can see the cost-vs-earned view).


def demo_cost_report() -> None:
    import sys
    from datetime import datetime

    sys.path.insert(0, str(__file__).rsplit("/proposals", 1)[0])
    from tools.metrics import build_run_metrics, print_metrics

    started = datetime(2026, 4, 20, 14, 22, 33)  # naive, matches datetime.utcnow()
    total_in = sum(inp for *_, inp, _out in AGENTS)
    total_out = sum(out for *_, out in AGENTS)

    console.print(Rule("[bold cyan]DEMO 3a — After submission (bounty pending)[/bold cyan]"))
    console.print()
    metrics_pending = build_run_metrics(
        run_id="20260420-142233-a3f9c1",
        started_at=started,
        llm_model=MODEL,
        input_tokens=total_in,
        output_tokens=total_out,
        programme_handle="acme-corp",
        findings_raw=7,
        findings_verified=3,
        submitted=True,
        h1_report_id="2847391",
        h1_report_url="https://hackerone.com/reports/2847391",
        bounty_awarded_usd=None,
    )
    print_metrics(metrics_pending)

    time.sleep(0.5)

    console.print(Rule("[bold cyan]DEMO 3b — Same report after H1 awards the bounty[/bold cyan]"))
    console.print()
    metrics_paid = metrics_pending.model_copy(update={"bounty_awarded_usd": 750.00})
    print_metrics(metrics_paid)


if __name__ == "__main__":
    demo_live_pipeline()
    time.sleep(0.5)
    demo_progress_bar()
    time.sleep(0.5)
    demo_cost_report()
