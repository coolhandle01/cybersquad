"""
Behavioural tests for the Programme Manager's @tool wrappers.

The wrappers are thin: deserialise inputs, call into tools/* helpers,
return the result. Coverage here is regression coverage of the
wrapping itself; the underlying helpers are exercised in their own
dedicated test files. The args_schema contract for the same tools
lives in the sibling ``test_args_schemas.py``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

import runtime

pytestmark = pytest.mark.unit


class TestBrowseProgrammesTool:
    def test_returns_preview_dicts_no_cache(self, tmp_path) -> None:
        from models.h1 import ProgrammePreview
        from squad.programme_manager import browse_programmes_tool

        previews = [
            ProgrammePreview(handle="acme", name="Acme", offers_bounties=True),
            ProgrammePreview(handle="beta", name="Beta", offers_bounties=True),
        ]
        with patch(
            "squad.programme_manager.tools.selection.h1.browse_programmes",
            return_value=previews,
        ) as mbrowse:
            result = browse_programmes_tool.func(offers_bounties=True)

        assert result == previews
        # No filter args defaulted, only the one we passed in flight.
        mbrowse.assert_called_once_with(
            bookmarked=None,
            offers_bounties=True,
            submission_state=None,
            limit=None,
        )

    def test_forwards_all_filter_args(self, tmp_path) -> None:
        from models.h1 import SubmissionState
        from squad.programme_manager import browse_programmes_tool

        with patch(
            "squad.programme_manager.tools.selection.h1.browse_programmes",
            return_value=[],
        ) as mbrowse:
            browse_programmes_tool.func(
                bookmarked=True,
                offers_bounties=True,
                submission_state=SubmissionState.OPEN,
                limit=50,
            )

        # submission_state passes through as its lowercase StrEnum value.
        mbrowse.assert_called_once_with(
            bookmarked=True,
            offers_bounties=True,
            submission_state="open",
            limit=50,
        )


class TestHydrateProgrammeTool:
    def test_holds_hydrated_programme_in_memory_not_on_disk(
        self, programme, tmp_path, monkeypatch
    ) -> None:
        from squad.programme_manager import hydrate_programme_tool
        from squad.programme_manager.tools import selection

        monkeypatch.setattr(selection, "_hydrated_this_run", {})

        with patch(
            "squad.programme_manager.tools.selection.h1.hydrate_programme",
            return_value=programme,
        ) as mhydrate:
            result = hydrate_programme_tool.func(programme.handle)

        assert result == programme
        mhydrate.assert_called_once_with(programme.handle)
        # Held in memory for save - NOT written to disk. Hydrating N candidates
        # must not leave N programme.json files; the run gets exactly one (save's).
        assert selection._hydrated_this_run[programme.handle] == programme
        assert not list(tmp_path.rglob("programme.json"))


class TestProgrammeManagerTools:
    def test_save_writes_single_selection_from_memory(
        self, programme, tmp_path, monkeypatch
    ) -> None:
        from squad.programme_manager import save_programme_tool
        from squad.programme_manager.tools import selection

        run_dir = tmp_path / "run"
        # The handle was hydrated this run, so it is in the in-memory set.
        monkeypatch.setattr(selection, "_hydrated_this_run", {programme.handle: programme})

        with patch("runtime.run_dir", return_value=run_dir):
            result = save_programme_tool.func(programme.handle)

        assert runtime.programme_handle == programme.handle
        assert result == str(run_dir)
        # Exactly one programme.json on disk - the selection.
        assert (run_dir / "programme.json").exists()
        assert len(list(run_dir.rglob("programme.json"))) == 1

    def test_save_programme_tool_raises_when_not_hydrated(
        self, programme, tmp_path, monkeypatch
    ) -> None:
        # A handle absent from the in-memory hydrated set means hydrate never ran
        # (or failed) for it, so there is nothing to persist. save must fail loud
        # - NOT silently create an empty run directory with no programme.json,
        # which is what let the select task "succeed" with no artefact and then
        # fail the downstream guardrail with no clear cause.
        from squad.programme_manager import save_programme_tool
        from squad.programme_manager.tools import selection

        run_dir = tmp_path / "run"
        monkeypatch.setattr(selection, "_hydrated_this_run", {})

        with (
            patch("runtime.run_dir", return_value=run_dir),
            pytest.raises(ValueError, match="No hydrated programme for handle"),
        ):
            save_programme_tool.func(programme.handle)

        # Failed loud before binding or writing anything: no empty run dir.
        assert not (run_dir / "programme.json").exists()
