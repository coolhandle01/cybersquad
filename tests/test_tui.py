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


def test_theme_layer_thins_and_aligns_scrollbars_with_a_box_gap() -> None:
    """Measured, not asserted from source: mount the app headless, overflow the
    agent session so its scrollbar renders, and read the geometry the user sees
    - the two panes' scrollbars in one column, the bars at half Textual's width,
    and a gap between a turn box and the bar.

    This guards against the padding-on-the-container regression: padding-right
    on the scrollable dragged the bar inward *with* the content, so the bar
    misaligned from the log pane's and no gap appeared. The gap must live on the
    box (margin), which shrinks the box alone and leaves the bar at the edge."""
    import asyncio

    from textual.widgets import Static

    from tools.tui import CybersquadTUI

    async def _measure() -> tuple[int, int, int, int]:
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
        async with app.run_test(size=(100, 40)) as pilot:
            session = app.query_one("#agent-session")
            log = app.query_one("#crew-log")
            box = Static("a turn box", classes="agent-turn")
            session.mount(box)
            # Overflow the pane so the vertical scrollbar actually draws.
            for i in range(60):
                session.mount(Static(f"line {i} " + "x" * 40))
            await pilot.pause(0.2)
            return (
                session.styles.scrollbar_size_vertical,
                session.vertical_scrollbar.region.x,
                log.vertical_scrollbar.region.x,
                box.region.right,
            )

    bar_size, session_bar_x, log_bar_x, box_right = asyncio.run(_measure())
    assert bar_size == 1  # half Textual's default of 2
    assert session_bar_x == log_bar_x  # both scrollbars share one column
    assert box_right < session_bar_x  # a gap between the turn box and the bar


def test_human_input_right_edge_aligns_with_the_chat_boxes() -> None:
    """Measured: the human-input box must end in the same column as the agent
    turn boxes above it, and doing so must not disturb the scrollbar alignment.

    crewui wraps the input so the inset margin is local to the box; a margin on
    the bare input would shrink the pane and drag the scrollbar off the log
    pane's - this asserts both the alignment and the absence of that reskew."""
    import asyncio

    from textual.widgets import Static

    from tools.tui import CybersquadTUI

    async def _measure() -> tuple[int, int, int, int]:
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
        async with app.run_test(size=(100, 40)) as pilot:
            session = app.query_one("#agent-session")
            log = app.query_one("#crew-log")
            box = Static("a turn box", classes="agent-turn")
            session.mount(box)
            for i in range(60):
                session.mount(Static(f"line {i} " + "x" * 40))
            await pilot.pause(0.2)
            return (
                box.region.right,
                app.query_one("#human-input").region.right,
                session.vertical_scrollbar.region.x,
                log.vertical_scrollbar.region.x,
            )

    box_right, input_right, session_bar_x, log_bar_x = asyncio.run(_measure())
    assert input_right == box_right  # input lines up with the chat boxes
    assert session_bar_x == log_bar_x  # and the scrollbars stay aligned


def test_focused_tool_collapsible_is_not_filled_blue() -> None:
    """Measured: a focused/clicked tool-call collapsible title must not fill
    with the theme's blue block-cursor slab (which reads as selected text). The
    cybersquad layer clears that focus fill to transparent."""
    import asyncio

    from textual.widgets import Collapsible, Static
    from textual.widgets._collapsible import CollapsibleTitle

    from tools.tui import CybersquadTUI

    async def _measure() -> float:
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
        async with app.run_test() as pilot:
            session = app.query_one("#agent-session")
            collapsible = Collapsible(Static("body"), title="a tool", classes="tool-call")
            session.mount(collapsible)
            await pilot.pause(0.1)
            title = collapsible.query_one(CollapsibleTitle)
            title.focus()
            await pilot.pause(0.1)
            return title.styles.background.a

    # Alpha 0 == transparent: the blue block-cursor fill is gone.
    assert asyncio.run(_measure()) == 0
