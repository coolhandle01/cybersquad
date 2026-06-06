"""
tui.py - Cybersquad Textual TUI.

Wraps the generic CrewAIPipelineTUI with the cybersquad crew. The sidebar
reads each task's display name and agent role off the crew, so there is no
separate task map to wire here.
Launch with: python main.py  (default) or python main.py --headless to skip the TUI.
"""

from __future__ import annotations

from mcp_servers import ProvisionedMCPTools
from tools.tui import CrewAIPipelineTUI


class CybersquadTUI(CrewAIPipelineTUI):
    CSS_PATH = "tui.tcss"

    def __init__(
        self,
        verbose: bool = False,
        dry_run: bool = False,
        mcp_tools: ProvisionedMCPTools | None = None,
    ) -> None:
        from crew import build_crew

        super().__init__(
            crew=build_crew(verbose=verbose, mcp_tools=mcp_tools),
            record_prefix="cybersquad",
            verbose=verbose,
            dry_run=dry_run,
        )
