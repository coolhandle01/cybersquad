"""
tests/test_main.py - covers ``main.main()``'s single run-scope dispatch.

``main()`` opens ``build_crew`` (the MCP scope lives there - see test_crew.py)
and hands the crew to ``_present``, which forwards it - with the dry-run flag -
to one of two surfaces: the headless CLI or the Textual TUI. Each surface holds
its own dry-run mode. The crew is already built by the time a surface sees it,
so these tests stub the leaf calls and assert the routing and the run-metrics
handling.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Callable
from contextlib import contextmanager
from typing import cast
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _args(*, dry_run: bool, headless: bool, verbose: bool = False) -> Namespace:
    return Namespace(verbose=verbose, dry_run=dry_run, headless=headless)


class TestPresent:
    """``_present`` forwards the crew to one surface, carrying the dry-run flag."""

    def test_headless_routes_to_headless_with_dry_run_flag(self, monkeypatch) -> None:
        import main

        run = MagicMock()
        monkeypatch.setattr(main, "_run_headless", run)
        monkeypatch.setattr(main, "_run_tui", MagicMock())

        crew = MagicMock(name="crew")
        main._present(crew, _args(dry_run=True, headless=True, verbose=True))

        run.assert_called_once_with(crew, verbose=True, dry_run=True)

    def test_tui_routes_to_run_tui_with_dry_run_flag(self, monkeypatch) -> None:
        import main

        run_tui = MagicMock()
        monkeypatch.setattr(main, "_run_tui", run_tui)
        monkeypatch.setattr(main, "_run_headless", MagicMock())

        crew = MagicMock(name="crew")
        main._present(crew, _args(dry_run=True, headless=False))

        run_tui.assert_called_once_with(crew, dry_run=True)


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
    def test_dry_run_prints_pipeline_and_skips_kickoff(self, monkeypatch) -> None:
        import main

        crew = MagicMock()
        named = MagicMock(human_input=True)
        named.name = "Reconnaissance"
        named.agent.role = "osint_analyst"
        unnamed = MagicMock(human_input=False)
        unnamed.name = None
        unnamed.agent.role = "programme_manager"
        crew.tasks = [named, unnamed]

        main._run_headless(crew, verbose=False, dry_run=True)

        crew.kickoff.assert_not_called()

    def test_kickoff_without_usage_skips_metrics(self, monkeypatch) -> None:
        import main

        mocks = _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.return_value = MagicMock(token_usage=None)

        main._run_headless(crew, verbose=False, dry_run=False)

        crew.kickoff.assert_called_once()
        mocks["build"].assert_not_called()

    def test_kickoff_with_usage_builds_and_saves_metrics(self, monkeypatch) -> None:
        import main

        mocks = _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.return_value = MagicMock(
            token_usage=MagicMock(prompt_tokens=10, completion_tokens=20)
        )

        main._run_headless(crew, verbose=False, dry_run=False)

        mocks["build"].assert_called_once()
        mocks["save"].assert_called_once()

    def test_keyboard_interrupt_exits_zero(self, monkeypatch) -> None:
        import main

        _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit) as exc:
            main._run_headless(crew, verbose=False, dry_run=False)
        assert exc.value.code == 0

    def test_unexpected_exception_exits_one(self, monkeypatch) -> None:
        import main

        _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.side_effect = RuntimeError("boom")

        with pytest.raises(SystemExit) as exc:
            main._run_headless(crew, verbose=False, dry_run=False)
        assert exc.value.code == 1


class TestRunTui:
    """``_run_tui`` injects cybersquad's run lifecycle into the CrewAI/Textual
    TUI as callbacks - the TUI package itself never imports runtime/config/
    metrics. These tests pin the wiring and the callback behaviour.
    """

    def _patch_tui(self, monkeypatch, captured: dict[str, object]):
        app = MagicMock()

        def fake_tui(**kwargs):
            captured.update(kwargs)
            return app

        monkeypatch.setattr("tools.tui.CybersquadTUI", fake_tui)
        return app

    def test_binds_run_id_and_wires_callbacks(self, monkeypatch) -> None:
        import main
        import runtime

        monkeypatch.setattr(runtime, "run_id", "")
        monkeypatch.setattr(runtime, "bind_run_id", lambda rid: setattr(runtime, "run_id", rid))

        captured: dict[str, object] = {}
        app = self._patch_tui(monkeypatch, captured)

        crew = MagicMock(name="crew")
        main._run_tui(crew, dry_run=False)

        # A run id was generated and bound; it surfaces only inside the
        # human-readable pipeline_name title, never as a run_id the TUI knows.
        assert runtime.run_id
        assert captured["pipeline_name"] == f"Bug Bounty #{runtime.run_id}"
        assert "run_id" not in captured
        assert captured["crew"] is crew
        assert captured["record_prefix"] == "cybersquad"
        assert captured["dry_run"] is False
        assert callable(captured["on_start"])
        assert callable(captured["on_complete"])
        assert callable(captured["get_token_cost"])
        app.run.assert_called_once()

    def test_dry_run_skips_run_id_and_uses_plain_name(self, monkeypatch) -> None:
        import main
        import runtime

        bound: list[str] = []
        monkeypatch.setattr(runtime, "bind_run_id", lambda rid: bound.append(rid))

        captured: dict[str, object] = {}
        self._patch_tui(monkeypatch, captured)

        main._run_tui(MagicMock(name="crew"), dry_run=True)

        # No run to identify: no run id bound, plain title, dry_run flag through.
        assert bound == []
        assert captured["pipeline_name"] == "Bug Bounty"
        assert captured["dry_run"] is True

    def test_callbacks_persist_metrics_and_estimate_cost(self, monkeypatch) -> None:
        import main
        import runtime
        from config import config

        monkeypatch.setattr(runtime, "run_id", "rid-xyz")
        monkeypatch.setattr(runtime, "bind_run_id", lambda _rid: None)
        monkeypatch.setattr(config.llm, "model", "anthropic/claude-sonnet-4-6")

        build = MagicMock(return_value=MagicMock())
        save = MagicMock()
        monkeypatch.setattr("tools.metrics.build_run_metrics", build)
        monkeypatch.setattr("tools.metrics.save_metrics", save)
        monkeypatch.setattr("tools.metrics.estimate_cost", lambda _model, _i, _o: 1.23)

        captured: dict[str, object] = {}
        self._patch_tui(monkeypatch, captured)
        main._run_tui(MagicMock(name="crew"), dry_run=False)

        on_start = cast(Callable[[], None], captured["on_start"])
        on_complete = cast(Callable[[object], None], captured["on_complete"])
        get_token_cost = cast(Callable[[int, int], float], captured["get_token_cost"])

        on_start()  # stamps started_at

        result = MagicMock()
        result.token_usage = MagicMock(prompt_tokens=10, completion_tokens=20)
        on_complete(result)
        build.assert_called_once()
        save.assert_called_once()

        # No token usage -> nothing persisted.
        build.reset_mock()
        save.reset_mock()
        no_usage = MagicMock()
        no_usage.token_usage = None
        on_complete(no_usage)
        build.assert_not_called()
        save.assert_not_called()

        assert get_token_cost(10, 20) == 1.23


class TestMain:
    def test_builds_crew_then_presents(self, monkeypatch) -> None:
        """main() opens build_crew with the parsed flags and hands the yielded
        crew to _present - one run-scope, one exit."""
        import crew as crew_mod
        import main

        captured: dict[str, object] = {}
        fake_crew = MagicMock(name="crew")

        @contextmanager
        def fake_build_crew(verbose):
            captured["verbose"] = verbose
            yield fake_crew

        present = MagicMock()
        args = _args(dry_run=False, headless=True, verbose=True)
        monkeypatch.setattr(main, "parse_args", lambda: args)
        monkeypatch.setattr(main, "check_env", lambda: None)
        monkeypatch.setattr(crew_mod, "build_crew", fake_build_crew)
        monkeypatch.setattr(main, "_present", present)

        main.main()

        assert captured == {"verbose": True}
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
