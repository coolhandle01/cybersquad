"""
tests/test_main.py - covers ``main.main()``'s single run-scope dispatch.

``main()`` opens ``build_crew`` (the MCP scope lives there - see test_crew.py)
and, inside that block, forwards the crew - with the dry-run flag - to one of two
surfaces: the headless CLI or the Textual TUI. Each surface holds its own dry-run
mode. The crew is already built by the time a surface sees it, so these tests
stub the leaf calls and assert the routing and the run-metrics handling.
"""

from __future__ import annotations

import logging
from argparse import Namespace
from collections.abc import Callable
from contextlib import contextmanager
from typing import cast
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _args(*, dry_run: bool, headless: bool, verbose: bool = False) -> Namespace:
    return Namespace(verbose=verbose, dry_run=dry_run, headless=headless)


def _stub_headless_metrics(monkeypatch) -> dict[str, MagicMock]:
    """Stub the metrics + run-id side effects of ``_run_headless``.

    Returns the metrics mocks so tests assert on the captured ``MagicMock``
    objects rather than the module attributes (whose declared types have no
    mock-assertion methods).
    """
    import runtime
    import tools.metrics as metrics_mod

    monkeypatch.setattr(runtime, "bind_run_id", lambda _run_id: None)
    # _run_headless resolves runtime.run_dir() for the metrics location; the run
    # is mocked so nothing binds programme_handle - stub run_dir so it does not
    # raise. save_metrics is mocked too, so its argument is never used for I/O.
    monkeypatch.setattr(runtime, "run_dir", lambda: MagicMock(name="run_dir"))
    mocks = {
        "build": MagicMock(return_value=MagicMock(name="metrics")),
        "print": MagicMock(),
        "save": MagicMock(),
    }
    monkeypatch.setattr(metrics_mod, "build_run_metrics", mocks["build"])
    monkeypatch.setattr(metrics_mod, "print_metrics", mocks["print"])
    monkeypatch.setattr(metrics_mod, "save_metrics", mocks["save"])
    return mocks


class TestDryRunSummary:
    """``dry_run_summary`` renders the crew layout as rich tables, exercising the
    tools / no-tools and human-review branches."""

    def test_renders_agents_and_tasks(self, capsys) -> None:
        import main

        tool = MagicMock()
        tool.name = "run_recon"
        with_tools = MagicMock(role="osint_analyst", tools=[tool])
        without_tools = MagicMock(role="programme_manager", tools=[])

        named = MagicMock(human_input=True)
        named.name = "Reconnaissance"
        named.agent.role = "osint_analyst"
        unnamed = MagicMock(human_input=False)
        unnamed.name = None
        unnamed.agent.role = "programme_manager"

        crew = MagicMock(agents=[with_tools, without_tools], tasks=[named, unnamed])
        main.dry_run_summary(crew)

        out = capsys.readouterr().out
        assert "DRY RUN" in out
        # The agent rows render: a role, its tool, and the "(none)" no-tools cell.
        assert "osint_analyst" in out
        assert "run_recon" in out
        assert "(none)" in out
        # The task rows render: the named task's heading and the human-review
        # marker on the task that pauses (the unnamed task falls back to its
        # agent role, exercised by "programme_manager" appearing at all).
        assert "Reconnaissance" in out
        assert "programme_manager" in out
        assert "pauses for feedback" in out


class TestRunHeadless:
    def test_dry_run_calls_summary_and_skips_kickoff(self, monkeypatch) -> None:
        import main

        summary = MagicMock()
        monkeypatch.setattr(main, "dry_run_summary", summary)
        crew = MagicMock()

        main._run_headless(crew, dry_run=True)

        summary.assert_called_once_with(crew)
        crew.kickoff.assert_not_called()

    def test_kickoff_without_usage_skips_metrics(self, monkeypatch) -> None:
        import main

        mocks = _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.return_value = MagicMock(token_usage=None)

        main._run_headless(crew, dry_run=False)

        crew.kickoff.assert_called_once()
        mocks["build"].assert_not_called()

    def test_kickoff_with_usage_builds_and_saves_metrics(self, monkeypatch) -> None:
        import main

        mocks = _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.return_value = MagicMock(
            token_usage=MagicMock(prompt_tokens=10, completion_tokens=20)
        )

        main._run_headless(crew, dry_run=False)

        mocks["build"].assert_called_once()
        mocks["save"].assert_called_once()

    def test_keyboard_interrupt_exits_zero(self, monkeypatch) -> None:
        import main

        _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit) as exc:
            main._run_headless(crew, dry_run=False)
        assert exc.value.code == 0

    def test_unexpected_exception_exits_one(self, monkeypatch) -> None:
        import main

        _stub_headless_metrics(monkeypatch)
        crew = MagicMock()
        crew.kickoff.side_effect = RuntimeError("boom")

        with pytest.raises(SystemExit) as exc:
            main._run_headless(crew, dry_run=False)
        assert exc.value.code == 1

    def test_metrics_without_a_bound_programme_warns_and_does_not_fail(
        self, monkeypatch, caplog
    ) -> None:
        # A completed run that produced token usage but where the PM selected no
        # programme has no run_dir to persist into (run_dir() raises). The
        # metrics were already printed; that must not turn a completed run into a
        # traceback + exit 1 - warn and finish cleanly, and never reach save.
        import main
        import runtime

        mocks = _stub_headless_metrics(monkeypatch)

        def _no_programme() -> None:
            raise RuntimeError("runtime.programme_handle and run_id must be bound")

        monkeypatch.setattr(runtime, "run_dir", _no_programme)

        crew = MagicMock()
        crew.kickoff.return_value = MagicMock(
            token_usage=MagicMock(prompt_tokens=10, completion_tokens=20)
        )

        with caplog.at_level(logging.WARNING, logger="bounty_squad"):
            main._run_headless(crew, dry_run=False)  # must not raise SystemExit

        mocks["build"].assert_called_once()
        mocks["print"].assert_called_once()  # metrics still shown to the operator
        mocks["save"].assert_not_called()  # run_dir() raised before save
        assert "not persisted" in caplog.text

    def test_metrics_save_io_error_still_exits_one(self, monkeypatch) -> None:
        # The no-programme warning is narrow: a genuine I/O failure during save
        # (disk full, permission) is a real error and must still exit 1, not be
        # swallowed by the missing-programme guard.
        import main

        mocks = _stub_headless_metrics(monkeypatch)
        mocks["save"].side_effect = OSError("disk full")

        crew = MagicMock()
        crew.kickoff.return_value = MagicMock(
            token_usage=MagicMock(prompt_tokens=10, completion_tokens=20)
        )

        with pytest.raises(SystemExit) as exc:
            main._run_headless(crew, dry_run=False)
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

    def test_callbacks_persist_metrics_and_estimate_cost(self, monkeypatch) -> None:
        import main
        import runtime
        from config import config

        monkeypatch.setattr(runtime, "run_id", "rid-xyz")
        monkeypatch.setattr(runtime, "bind_run_id", lambda _rid: None)
        # on_complete resolves runtime.run_dir() for the metrics location; the
        # run is mocked so nothing binds programme_handle - stub it so it does
        # not raise (save_metrics is mocked, so the argument is never used).
        monkeypatch.setattr(runtime, "run_dir", lambda: MagicMock(name="run_dir"))
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

    def test_callbacks_warn_when_no_programme_bound(self, monkeypatch, caplog) -> None:
        # The TUI is the DEFAULT surface, so its no-programme handling must match
        # headless: a completed run with usage but no bound programme has no
        # run_dir to persist into (run_dir raises RuntimeError). on_complete must
        # warn and return cleanly - not raise an internal invariant string up
        # into crewui's callback handler (where it would show a developer-facing
        # message instead of the actionable one).
        import main
        import runtime
        from config import config

        monkeypatch.setattr(runtime, "run_id", "rid-xyz")
        monkeypatch.setattr(runtime, "bind_run_id", lambda _rid: None)

        def _no_programme() -> None:
            raise RuntimeError("runtime.programme_handle and run_id must be bound")

        monkeypatch.setattr(runtime, "run_dir", _no_programme)
        monkeypatch.setattr(config.llm, "model", "anthropic/claude-sonnet-4-6")

        build = MagicMock(return_value=MagicMock())
        save = MagicMock()
        monkeypatch.setattr("tools.metrics.build_run_metrics", build)
        monkeypatch.setattr("tools.metrics.save_metrics", save)

        captured: dict[str, object] = {}
        self._patch_tui(monkeypatch, captured)
        main._run_tui(MagicMock(name="crew"), dry_run=False)
        on_start = cast(Callable[[], None], captured["on_start"])
        on_complete = cast(Callable[[object], None], captured["on_complete"])
        on_start()

        result = MagicMock()
        result.token_usage = MagicMock(prompt_tokens=10, completion_tokens=20)
        with caplog.at_level(logging.WARNING, logger="bounty_squad"):
            on_complete(result)  # must not raise

        build.assert_called_once()
        save.assert_not_called()  # run_dir() raised before save
        assert "not persisted" in caplog.text

    def test_callbacks_metrics_save_io_error_propagates(self, monkeypatch) -> None:
        # Symmetry with headless: a genuine write failure is NOT the no-programme
        # case. An OSError during save must propagate out of on_complete (crewui
        # surfaces it as a real error), not be swallowed by the no-programme
        # guard. This is the guarantee that keeps the two failure modes distinct.
        import main
        import runtime
        from config import config

        monkeypatch.setattr(runtime, "run_id", "rid-xyz")
        monkeypatch.setattr(runtime, "bind_run_id", lambda _rid: None)
        monkeypatch.setattr(runtime, "run_dir", lambda: MagicMock(name="run_dir"))
        monkeypatch.setattr(config.llm, "model", "anthropic/claude-sonnet-4-6")

        monkeypatch.setattr("tools.metrics.build_run_metrics", MagicMock(return_value=MagicMock()))
        monkeypatch.setattr(
            "tools.metrics.save_metrics", MagicMock(side_effect=OSError("disk full"))
        )

        captured: dict[str, object] = {}
        self._patch_tui(monkeypatch, captured)
        main._run_tui(MagicMock(name="crew"), dry_run=False)
        on_start = cast(Callable[[], None], captured["on_start"])
        on_complete = cast(Callable[[object], None], captured["on_complete"])
        on_start()

        result = MagicMock()
        result.token_usage = MagicMock(prompt_tokens=10, completion_tokens=20)
        with pytest.raises(OSError, match="disk full"):
            on_complete(result)


class TestMain:
    """main() opens build_crew with the parsed flags and, inside that block,
    dispatches the crew to the headless or TUI surface - one run-scope, one exit.
    """

    def _wire(self, monkeypatch, args, captured: dict[str, object]) -> MagicMock:
        import crew as crew_mod
        import main

        fake_crew = MagicMock(name="crew")

        @contextmanager
        def fake_build_crew(verbose):
            captured["verbose"] = verbose
            yield fake_crew

        monkeypatch.setattr(main, "parse_args", lambda: args)
        monkeypatch.setattr(main, "check_env", lambda: None)
        monkeypatch.setattr(crew_mod, "build_crew", fake_build_crew)
        return fake_crew

    def test_headless_dispatches_to_run_headless(self, monkeypatch) -> None:
        import main

        captured: dict[str, object] = {}
        args = _args(dry_run=True, headless=True, verbose=True)
        fake_crew = self._wire(monkeypatch, args, captured)
        run = MagicMock()
        monkeypatch.setattr(main, "_run_headless", run)
        monkeypatch.setattr(main, "_run_tui", MagicMock())

        main.main()

        assert captured == {"verbose": True}
        run.assert_called_once_with(fake_crew, dry_run=True)

    def test_default_dispatches_to_run_tui(self, monkeypatch) -> None:
        import main

        captured: dict[str, object] = {}
        args = _args(dry_run=False, headless=False)
        fake_crew = self._wire(monkeypatch, args, captured)
        run_tui = MagicMock()
        monkeypatch.setattr(main, "_run_tui", run_tui)
        monkeypatch.setattr(main, "_run_headless", MagicMock())
        # An interactive terminal is present, so the TUI path is allowed.
        monkeypatch.setattr(main, "_interactive_tty", lambda: True)

        main.main()

        run_tui.assert_called_once_with(fake_crew, dry_run=False)

    def test_non_tty_without_headless_exits_with_a_headless_hint(self, monkeypatch, caplog) -> None:
        # The TUI needs an interactive terminal. Piped or run under CI, the
        # default path must refuse with a clear pointer to --headless rather
        # than crashing inside Textual - and it must not build the crew or
        # fire the pipeline first (cybersquad acts on live targets).
        import main

        args = _args(dry_run=False, headless=False)
        run_tui = MagicMock()
        run_headless = MagicMock()
        monkeypatch.setattr(main, "parse_args", lambda: args)
        monkeypatch.setattr(main, "check_env", lambda: None)
        monkeypatch.setattr(main, "warn_if_telemetry_enabled", lambda: None)
        monkeypatch.setattr(main, "_run_tui", run_tui)
        monkeypatch.setattr(main, "_run_headless", run_headless)
        monkeypatch.setattr(main, "_interactive_tty", lambda: False)
        # build_crew must never be reached: fail before opening the MCP scope.
        import crew as crew_mod

        def exploding_build_crew(verbose):  # pragma: no cover - must not run
            raise AssertionError("build_crew reached before the TTY guard")

        monkeypatch.setattr(crew_mod, "build_crew", exploding_build_crew)

        with (
            caplog.at_level(logging.ERROR, logger="bounty_squad"),
            pytest.raises(SystemExit) as exc,
        ):
            main.main()

        assert exc.value.code == 1
        run_tui.assert_not_called()
        run_headless.assert_not_called()
        assert "--headless" in caplog.text

    def test_non_tty_dry_run_without_headless_is_also_refused(self, monkeypatch, caplog) -> None:
        # A dry run still constructs the Textual app, so a non-TTY dry run is
        # refused too - the operator is pointed at --headless --dry-run, which
        # prints the pipeline without a terminal.
        import main

        args = _args(dry_run=True, headless=False)
        run_tui = MagicMock()
        monkeypatch.setattr(main, "parse_args", lambda: args)
        monkeypatch.setattr(main, "check_env", lambda: None)
        monkeypatch.setattr(main, "warn_if_telemetry_enabled", lambda: None)
        monkeypatch.setattr(main, "_run_tui", run_tui)
        monkeypatch.setattr(main, "_interactive_tty", lambda: False)

        with (
            caplog.at_level(logging.ERROR, logger="bounty_squad"),
            pytest.raises(SystemExit) as exc,
        ):
            main.main()

        assert exc.value.code == 1
        run_tui.assert_not_called()
        assert "--headless" in caplog.text

    def test_run_tui_without_crewui_exits_with_a_headless_hint(self, monkeypatch, caplog) -> None:
        # tools.tui does a hard top-level `from crewui import ...`; a partial
        # install (crewui absent) must surface a clear pointer to --headless,
        # not a raw ImportError traceback. Modelled by a tools.tui module that
        # lacks the symbol, so `from tools.tui import CybersquadTUI` raises.
        import sys
        import types

        import main

        monkeypatch.setitem(sys.modules, "tools.tui", types.ModuleType("tools.tui"))

        with (
            caplog.at_level(logging.ERROR, logger="bounty_squad"),
            pytest.raises(SystemExit) as exc,
        ):
            main._run_tui(MagicMock(name="crew"), dry_run=False)

        assert exc.value.code == 1
        assert "--headless" in caplog.text

    def test_non_tty_with_headless_still_runs(self, monkeypatch) -> None:
        # The guard only blocks the TUI path; --headless needs no terminal, so a
        # non-interactive headless run dispatches normally.
        import main

        captured: dict[str, object] = {}
        args = _args(dry_run=False, headless=True)
        fake_crew = self._wire(monkeypatch, args, captured)
        run_headless = MagicMock()
        monkeypatch.setattr(main, "_run_headless", run_headless)
        monkeypatch.setattr(main, "_run_tui", MagicMock())
        monkeypatch.setattr(main, "_interactive_tty", lambda: False)

        main.main()

        run_headless.assert_called_once_with(fake_crew, dry_run=False)


class TestInteractiveTty:
    """``_interactive_tty`` is True only when *both* streams are a terminal -
    a redirected stdin or stdout (a pipe, a CI runner) reads as non-interactive.
    """

    def test_true_when_both_streams_are_a_terminal(self, monkeypatch) -> None:
        import main

        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert main._interactive_tty() is True

    def test_false_when_stdin_is_not_a_terminal(self, monkeypatch) -> None:
        import main

        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert main._interactive_tty() is False

    def test_false_when_stdout_is_not_a_terminal(self, monkeypatch) -> None:
        import main

        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("sys.stdout.isatty", lambda: False)
        assert main._interactive_tty() is False


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


class TestWarnIfTelemetryEnabled:
    """The startup telemetry warning fires only when CrewAI telemetry is left
    on - i.e. none of CrewAI's opt-out env vars disable it. Mirrors CrewAI's own
    ``_is_telemetry_disabled`` check so the warning matches reality.
    """

    _OPT_OUTS = ("OTEL_SDK_DISABLED", "CREWAI_DISABLE_TELEMETRY", "CREWAI_DISABLE_TRACKING")

    def test_warns_when_no_opt_out_set(self, monkeypatch, caplog) -> None:
        import main

        for var in self._OPT_OUTS:
            monkeypatch.delenv(var, raising=False)
        with caplog.at_level(logging.WARNING, logger="bounty_squad"):
            main.warn_if_telemetry_enabled()
        # Assert on a distinctive phrase, not the bare domain: a domain literal
        # in an `in` check trips CodeQL's incomplete-url-substring-sanitization
        # rule (a false positive on a log assertion, but easy to sidestep).
        assert "CrewAI telemetry is enabled" in caplog.text

    @pytest.mark.parametrize("var", _OPT_OUTS)
    def test_silent_when_opt_out_set(self, monkeypatch, caplog, var) -> None:
        import main

        for other in self._OPT_OUTS:
            monkeypatch.delenv(other, raising=False)
        monkeypatch.setenv(var, "true")
        with caplog.at_level(logging.WARNING, logger="bounty_squad"):
            main.warn_if_telemetry_enabled()
        assert "CrewAI telemetry is enabled" not in caplog.text
