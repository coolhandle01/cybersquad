"""
tui.py - Cybersquad Textual TUI.

Thin cybersquad binding of the generic CrewAIPipelineTUI: it fixes the record
prefix and takes an already-built crew (main.py builds it inside the
provisioned-MCP scope and hands it in), so the TUI stays free of crew
construction and MCP provisioning. The base ships the default theme; override
CSS_PATH here if cybersquad ever needs its own.
Launch with: python main.py  (default) or python main.py --headless to skip the TUI.
"""

from __future__ import annotations

from crewai import Crew

from tools.tui import CrewAIPipelineTUI


class CybersquadTUI(CrewAIPipelineTUI):
    def __init__(self, crew: Crew, verbose: bool = False, dry_run: bool = False) -> None:
        super().__init__(
            crew=crew,
            record_prefix="cybersquad",
            verbose=verbose,
            dry_run=dry_run,
        )
