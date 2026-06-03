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
            asset_type=None,
            bookmarked=None,
            offers_bounties=True,
            submission_state=None,
            sort=None,
            limit=None,
        )

    def test_forwards_all_filter_args(self, tmp_path) -> None:
        from models.h1 import ScopeType, SubmissionState
        from squad.programme_manager import browse_programmes_tool

        with patch(
            "squad.programme_manager.tools.selection.h1.browse_programmes",
            return_value=[],
        ) as mbrowse:
            browse_programmes_tool.func(
                asset_type=ScopeType.WILDCARD,
                bookmarked=True,
                offers_bounties=True,
                submission_state=SubmissionState.OPEN,
                sort="-launched_at",
                limit=50,
            )

        # The wrapper uppercases the asset_type StrEnum value to match
        # H1's filter[asset_type] wire format; submission_state passes
        # through as its lowercase StrEnum value.
        mbrowse.assert_called_once_with(
            asset_type="WILDCARD",
            bookmarked=True,
            offers_bounties=True,
            submission_state="open",
            sort="-launched_at",
            limit=50,
        )


class TestHydrateProgrammeTool:
    def test_caches_hydrated_programme(self, programme, tmp_path) -> None:
        from squad.programme_manager import hydrate_programme_tool

        cache_path = tmp_path / programme.handle / "programme.json"

        with (
            patch(
                "squad.programme_manager.tools.selection.h1.hydrate_programme",
                return_value=programme,
            ) as mhydrate,
            patch(
                "runtime.programme_cache_path",
                return_value=cache_path,
            ),
        ):
            result = hydrate_programme_tool.func(programme.handle)

        assert result == programme
        mhydrate.assert_called_once_with(programme.handle)
        assert cache_path.exists()


class TestProgrammeManagerTools:
    def test_save_programme_tool_sets_handle_and_copies(self, programme, tmp_path) -> None:
        from squad.programme_manager import save_programme_tool

        cache = tmp_path / "cache" / "programme.json"
        cache.parent.mkdir(parents=True)
        cache.write_text(programme.model_dump_json(), encoding="utf-8")
        run_dir = tmp_path / "run"

        with (
            patch("runtime.run_dir", return_value=run_dir),
            patch("runtime.programme_cache_path", return_value=cache),
        ):
            result = save_programme_tool.func(programme.handle)

        assert runtime.programme_handle == programme.handle
        assert result == str(run_dir)
        assert (run_dir / "programme.json").exists()

    def test_save_programme_tool_skips_copy_when_cache_missing(self, programme, tmp_path) -> None:
        from squad.programme_manager import save_programme_tool

        run_dir = tmp_path / "run"
        absent_cache = tmp_path / "cache" / "programme.json"

        with (
            patch("runtime.run_dir", return_value=run_dir),
            patch("runtime.programme_cache_path", return_value=absent_cache),
        ):
            result = save_programme_tool.func(programme.handle)

        assert runtime.programme_handle == programme.handle
        assert result == str(run_dir)
        assert run_dir.exists()
        assert not (run_dir / "programme.json").exists()
