"""tools/tui - cybersquad's binding to the crewui TUI library.

The generic Textual TUI (sidebar task tracker, agent/pipeline logs, the
human-review gate, the break-glass Ctrl+Q teardown, the thread-aware log
handler) lives in the ``crewui`` package now; cybersquad keeps only this thin
subclass. ``main.py`` builds the crew inside the provisioned-MCP scope and hands
it in, exactly as before - the constructor signature is unchanged.

While crewui's break-glass and review-gate work is validated from cybersquad
(the integration harness), the crewui dependency is pinned by commit to a branch
in ``pyproject.toml``; it moves to a released pin once that work lands upstream.
"""

from __future__ import annotations

from crewui import CrewAIPipelineTUI


class CybersquadTUI(CrewAIPipelineTUI):
    """cybersquad's pipeline TUI - crewui's ``CrewAIPipelineTUI`` unchanged.

    Kept as a named subclass so the construction site (``main.py``) and the
    tests have a stable cybersquad symbol, and so cybersquad-specific theming or
    behaviour has a home the day it is needed (a derived class ships its own
    look by setting its own ``CSS_PATH``). For now it inherits crewui's theme.
    """
