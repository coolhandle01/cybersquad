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

from pathlib import Path
from typing import ClassVar

from crewui import CrewAIPipelineTUI
from textual.app import CSSPathType


class CybersquadTUI(CrewAIPipelineTUI):
    """cybersquad's pipeline TUI - crewui's ``CrewAIPipelineTUI`` with a thin
    cybersquad theme layered on top.

    Kept as a named subclass so the construction site (``main.py``) and the
    tests have a stable cybersquad symbol, and so cybersquad-specific theming or
    behaviour has a home. Textual reads ``CSS_PATH`` from the concrete class
    only (no MRO merge), so a subclass that sets it *replaces* crewui's default;
    we therefore list crewui's base first, then ``cybersquad.tcss``, so both
    load and cybersquad's preferences win on ties. Structural CSS stays in
    crewui; this layer carries only look-and-feel (see ``cybersquad.tcss``).
    """

    # crewui narrows the inherited base type to ``str``; we re-widen to the
    # canonical Textual union so a list of paths is accepted.
    CSS_PATH: ClassVar[CSSPathType] = [  # type: ignore[assignment]
        CrewAIPipelineTUI.CSS_PATH,
        str(Path(__file__).parent / "cybersquad.tcss"),
    ]
