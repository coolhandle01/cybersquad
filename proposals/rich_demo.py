"""
proposals/rich_demo.py — Mock-up of rich terminal output for Bounty Squad.

Run with:
    .venv/bin/python proposals/rich_demo.py

Shows three candidate UI patterns with simulated timing so you can
feel the pacing. No real API calls are made.
"""

from __future__ import annotations

import time

from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.progress import Progress as RichProgress
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()

AGENTS = [
    ("Programme Manager",       "Selecting programmes",         1.2,  8_412,  1_203),
    ("OSINT Analyst",           "Enumerating attack surface",   2.1, 14_890,  2_441),
    ("Penetration Tester",      "Running nuclei / sqlmap",      3.4, 22_310,  3_890),
    ("Vulnerability Researcher","Triaging findings",            1.8, 11_750,  2_105),
    ("Technical Author",        "Writing disclosure report",    2.0, 18_640,  4_312),
    ("Disclosure Coordinator",  "Submitting to HackerOne",      0.9,  6_210,    980),
]

MODEL = "anthropic/claude-sonnet-4-20250514"
IN_PRICE, OUT_PRICE = 3.00, 15.00   # USD per 1M tokens


def cost(inp: int, out: int) -> float:
    return (inp * IN_PRICE + out * OUT_PRICE) / 1_000_000


# ── DEMO 1 ────────────────────────────────────────────────────────────────────
# Live pipeline table — updates in place as each agent finishes.

def demo_live_pipeline() -> None:
    console.print(Rule("[bold cyan]DEMO 1 — Live pipeline progress[/bold cyan]"))
    console.print()

    STATUS_ICONS = {
        "waiting":  "[dim]○[/dim]",
        "running":  "[yellow]◉[/yellow]",
        "review":   "[bold yellow]▶ awaiting your feedback[/bold yellow]",
        "done":     "[green]✓[/green]",
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
        for i, (name, phase, duration, inp, out) in enumerate(AGENTS):
            rows[i]["status"] = "running"
            live.update(build_table())
            time.sleep(duration * 0.4)          # simulate work

            rows[i]["in"]  = inp
            rows[i]["out"] = out
            rows[i]["dur"] = duration

            # Gates after Programme Manager and Technical Author
            if name in ("Programme Manager", "Technical Author"):
                rows[i]["status"] = "review"
                live.update(build_table())
                time.sleep(1.2)                 # simulate operator reading

            rows[i]["status"] = "done"
            live.update(build_table())

    console.print()
    total_in  = sum(r["in"]  for r in rows)
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
        for name, phase, duration, inp, out in AGENTS:
            step = progress.add_task(f"  {name}", total=100)
            for _ in range(10):
                time.sleep(duration * 0.04)
                progress.advance(step, 10)
            progress.update(step, description=f"  [green]✓[/green] {name}")
            progress.advance(overall, 1)

    console.print()


# ── DEMO 3 ────────────────────────────────────────────────────────────────────
# Final cost report — what print_metrics() could become.

def demo_cost_report() -> None:
    console.print(Rule("[bold cyan]DEMO 3 — Per-agent cost report[/bold cyan]"))
    console.print()

    tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tbl.add_column("Agent", style="cyan")
    tbl.add_column("In tokens", justify="right")
    tbl.add_column("Out tokens", justify="right")
    tbl.add_column("Est. cost", justify="right")
    tbl.add_column("Time", justify="right", style="dim")

    total_in = total_out = total_dur = 0
    for name, _phase, duration, inp, out in AGENTS:
        tbl.add_row(
            name,
            f"{inp:,}",
            f"{out:,}",
            f"[green]${cost(inp, out):.4f}[/green]",
            f"{duration:.1f}s",
        )
        total_in  += inp
        total_out += out
        total_dur += duration

    tbl.add_section()
    tbl.add_row(
        "[bold]Total[/bold]",
        f"[bold]{total_in:,}[/bold]",
        f"[bold]{total_out:,}[/bold]",
        f"[bold green]${cost(total_in, total_out):.4f}[/bold green]",
        f"[bold]{total_dur:.1f}s[/bold]",
    )

    summary_left = Text()
    summary_left.append("Run ID\n",  style="dim")
    summary_left.append("Programme\n", style="dim")
    summary_left.append("Model\n",   style="dim")
    summary_left.append("Findings\n", style="dim")
    summary_left.append("Submitted\n", style="dim")

    summary_right = Text()
    summary_right.append("20260420-142233-a3f9c1\n")
    summary_right.append("acme-corp\n")
    summary_right.append(f"{MODEL}\n", style="dim")
    summary_right.append("7 raw  ·  3 verified\n")
    summary_right.append("[green]yes[/green]\n")

    console.print(
        Panel(
            Columns([summary_left, summary_right, tbl], equal=False, expand=False),
            title="[bold green]  Bounty Squad — Run Report  [/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )
    console.print()


if __name__ == "__main__":
    demo_live_pipeline()
    time.sleep(0.5)
    demo_progress_bar()
    time.sleep(0.5)
    demo_cost_report()
