"""tests/test_tui.py - cybersquad's thin TUI wrapper over the crewui library.

The generic TUI moved to crewui; cybersquad keeps only ``CybersquadTUI``, a
subclass of ``crewui.CrewAIPipelineTUI``. These tests pin the two things
``main.py`` relies on: the wrapper is that subclass, and it accepts the
host-injected construction contract unchanged.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

if TYPE_CHECKING:
    from crewai import Crew

pytestmark = pytest.mark.unit


def test_cybersquad_tui_subclasses_the_crewui_base() -> None:
    from crewui import CrewAIPipelineTUI

    from tools.tui import CybersquadTUI

    assert issubclass(CybersquadTUI, CrewAIPipelineTUI)


def test_constructor_accepts_the_host_contract() -> None:
    from tools.tui import CybersquadTUI

    crew = cast("Crew", SimpleNamespace(tasks=[], step_callback=None))
    app = CybersquadTUI(
        crew=crew,
        record_prefix="cybersquad",
        pipeline_name="Bug Bounty #test",
        dry_run=True,
        on_start=lambda: None,
        on_complete=lambda _result: None,
        get_token_cost=lambda _in, _out: 0.0,
    )
    assert app._record_prefix == "cybersquad"


def test_css_layer_lists_crewui_base_then_cybersquad_override() -> None:
    """The layer must load crewui's structural CSS *and* cybersquad's, with
    cybersquad's last so its look-and-feel wins on equal-specificity ties."""
    from crewui import CrewAIPipelineTUI

    from tools.tui import CybersquadTUI

    paths = CybersquadTUI.CSS_PATH
    assert isinstance(paths, list)
    assert paths[0] == CrewAIPipelineTUI.CSS_PATH
    assert str(paths[-1]).endswith("cybersquad.tcss")


def test_theme_layer_thins_scrollbars_and_insets_the_agent_session() -> None:
    """Measured, not asserted from source: mount the app headless and read the
    computed styles, so this fails if the layer stops loading or Textual's
    defaults shift under us. crewui's default leaves scrollbars at Textual's
    width of 2 and the agent session flush against the bar; the cybersquad
    layer halves the bar and insets the content by one cell."""
    import asyncio

    from tools.tui import CybersquadTUI

    async def _measure() -> tuple[int, int, int]:
        crew = cast("Crew", SimpleNamespace(tasks=[], step_callback=None))
        app = CybersquadTUI(
            crew=crew,
            record_prefix="cybersquad",
            pipeline_name="Bug Bounty #test",
            dry_run=True,
            on_start=lambda: None,
            on_complete=lambda _result: None,
            get_token_cost=lambda _in, _out: 0.0,
        )
        async with app.run_test():
            session = app.query_one("#agent-session")
            log = app.query_one("#crew-log")
            return (
                session.styles.scrollbar_size_vertical,
                log.styles.scrollbar_size_vertical,
                session.styles.padding.right,
            )

    session_bar, log_bar, session_pad_right = asyncio.run(_measure())
    assert session_bar == 1  # half Textual's default of 2
    assert log_bar == 1
    assert session_pad_right == 1  # gap between the turn boxes and the scrollbar
