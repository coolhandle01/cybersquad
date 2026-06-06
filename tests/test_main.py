"""
tests/test_main.py - covers ``main.main()``'s single run-scope dispatch.

``main()`` opens ``build_pipeline`` (the MCP scope lives there - see
test_crew.py) and hands the crew to ``_present``, which routes to one of three
renderers: dry-run preview, headless run, or the Textual TUI. The crew is
already built by the time a renderer sees it, so these tests stub the leaf
calls and assert the routing and the run-metrics handling.
"""

from __future__ import annotations

from argparse import Namespace
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _args(*, dry_run: bool, headless: bool, verbose: bool = False) -> Namespace:
    return Namespace(verbose=verbose, dry_run=dry_run, headless=headless)


class TestPresent:
    """``_present`` routes a built crew to exactly one renderer per flag combo."""

    def test_dry_run_routes_to_dry_run_renderer(self, monkeypatch) -> None:
        import main

        render = MagicMock()
        monkeypatch.setattr(main, "_render_dry_run", render)
        monkeypatch.setattr(main, "_run_headless", MagicMock())

        crew = MagicMock(name="crew")
        main._present(crew, _args(dry_run=True, headless=True))

        render.assert_called_once_with(crew, headless=True)

    def test_headless_routes_to_headless_runner(self, monkeypatch) -> None:
        import main

        run = MagicMock()
        monkeypatch.setattr(main, "_run_headless", run)
        monkeypatch.setattr(main, "_render_dry_run", MagicMock())

        crew = MagicMock(name="crew")
        main._present(crew, _args(dry_run=False, headless=True, verbose=True))

        run.assert_called_once_with(crew, verbose=True)

    def test_default_routes_to_tui(self, monkeypatch) -> None:
        import main

        app = MagicMock()
        tui_cls = MagicMock(return_value=app)
        monkeypatch.setattr("tui.CybersquadTUI", tui_cls)

        crew = MagicMock(name="crew")
        main._present(crew, _args(dry_run=False, headless=False, verbose=True))

        tui_cls.assert_called_once_with(crew=crew, verbose=True)
        app.run.assert_called_once()


class TestRenderDryRun:
    """``_render_dry_run`` previews the layout without kicking off."""

    def test_headless_uses_rich_tables(self, monkeypatch) -> None:
        import main

        summary = MagicMock()
        monkeypatch.setattr(main, "dry_run_summary", summary)
        tui_cls = MagicMock()
        monkeypatch.setattr("tui.CybersquadTUI", tui_cls)

        crew = MagicMock(name="crew")
        main._render_dry_run(crew, headless=True)

        summary.assert_called_once_with(crew)
        tui_cls.assert_not_called()

    def test_tui_renders_app_in_dry_run_mode(self, monkeypatch) -> None:
        import main

        app = MagicMock()
        tui_cls = MagicMock(return_value=app)
        monkeypatch.setattr("tui.CybersquadTUI", tui_cls)
        monkeypatch.setattr(main, "dry_run_summary", MagicMock())

        crew = MagicMock(name="crew")
        main._render_dry_run(crew, headless=False)

        tui_cls.assert_called_once_with(crew=crew, dry_run=True)
        app.run.assert_called_once()


def _stub_headless_metrics(monkeypatch) -> dict[str, MagicMock]:
    """Stub the metrics + run-id side effects of ``_run_headless``.

    Returns the metrics mocks so tests assert on the captured ``MagicMock``
    objects rather than the module attributes (whose declared types have no
    mock-assertion methods).
    """
    import runtime
    import tools.metrics as metrics_mod

    monkeypatch.setattr(runtime, "bind_run_id", lambda _run_id: None)
    mocks = {
        "build": MagicMock(return_value=MagicMock(name="metrics")),
        "print": MagicMock(),
        "save": MagicMock(),
    }
    monkeypatch.setattr(metrics_mod, "build_run_metrics", mocks["build"])
    monkeypatch.setattr(metrics_mod, "print_metrics", mocks["print"])
    monkeypatch.setattr(metrics_mod, "save_metrics", mocks["save"])
    return mocks


class TestRunHeadless:
    def test_kickoff_without_usage_skips_metrics(self, monkeypatch) -> None:
        import main

        mocks = _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.return_value = MagicMock(token_usage=None)

        main._run_headless(crew, verbose=False)

        crew.kickoff.assert_called_once()
        mocks["build"].assert_not_called()

    def test_kickoff_with_usage_builds_and_saves_metrics(self, monkeypatch) -> None:
        import main

        mocks = _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.return_value = MagicMock(
            token_usage=MagicMock(prompt_tokens=10, completion_tokens=20)
        )

        main._run_headless(crew, verbose=False)

        mocks["build"].assert_called_once()
        mocks["save"].assert_called_once()

    def test_keyboard_interrupt_exits_zero(self, monkeypatch) -> None:
        import main

        _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit) as exc:
            main._run_headless(crew, verbose=False)
        assert exc.value.code == 0

    def test_unexpected_exception_exits_one(self, monkeypatch) -> None:
        import main

        _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.side_effect = RuntimeError("boom")

        with pytest.raises(SystemExit) as exc:
            main._run_headless(crew, verbose=False)
        assert exc.value.code == 1


class TestMain:
    def test_builds_pipeline_then_presents(self, monkeypatch) -> None:
        """main() opens build_pipeline with the parsed flags and hands the
        yielded crew to _present - one run-scope, one exit."""
        import crew as crew_mod
        import main

        captured: dict[str, object] = {}
        fake_crew = MagicMock(name="crew")

        @contextmanager
        def fake_build_pipeline(verbose, dry_run):
            captured["verbose"] = verbose
            captured["dry_run"] = dry_run
            yield fake_crew

        present = MagicMock()
        args = _args(dry_run=False, headless=True, verbose=True)
        monkeypatch.setattr(main, "parse_args", lambda: args)
        monkeypatch.setattr(main, "check_env", lambda: None)
        monkeypatch.setattr(crew_mod, "build_pipeline", fake_build_pipeline)
        monkeypatch.setattr(main, "_present", present)

        main.main()

        assert captured == {"verbose": True, "dry_run": False}
        present.assert_called_once_with(fake_crew, args)


class TestParseArgs:
    def test_headless_flag_defaults_false_and_parses(self, monkeypatch) -> None:
        """The ``--headless`` flag is off by default (TUI is the default) and
        flips on when passed.
        """
        import main

        monkeypatch.setattr("sys.argv", ["main.py"])
        assert main.parse_args().headless is False

        monkeypatch.setattr("sys.argv", ["main.py", "--headless"])
        assert main.parse_args().headless is True
