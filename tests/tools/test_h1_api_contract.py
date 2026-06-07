"""
tests/tools/test_h1_api_contract.py - contract/slice tests for the H1 client.

These mock at the HTTP boundary (``Session.get``), NOT at ``_get``, and the
fake server mimics HackerOne's *real* hacker-API contract
(api.hackerone.com/hacker-resources):

  - the programme DETAIL endpoint returns only ``data.attributes`` - it does
    NOT inline structured scopes (no ``included`` array);
  - structured scopes come only from the dedicated
    ``/hackers/programs/{handle}/structured_scopes`` sub-resource;
  - list pagination is an *absolute* ``links.next`` URL.

The pre-existing unit tests in ``test_h1_api.py`` faked an ``included`` scope
array on the detail response - a shape H1 never returns - which is why they
stayed green while every hydrated programme came back scope-less (#115) and
pagination doubled the base URL. These tests would have caught both. They are
network-free (the session is mocked) so they run in the ``-m unit`` gate.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import runtime
from config import config
from models.h1 import ScopeType
from squad.guardrails import validate_select_output
from squad.programme_manager import (
    browse_programmes_tool,
    hydrate_programme_tool,
    save_programme_tool,
)
from squad.programme_manager.tools import selection
from tests.fixtures import h1 as h1f

pytestmark = pytest.mark.unit

_BASE = config.h1.base_url


def _list_page1() -> dict:
    # links.next is ABSOLUTE, exactly as H1 returns it - the shape that used
    # to be concatenated onto the base and 404.
    return h1f.programmes_list(
        items=[h1f.programme_resource("acme", name="Acme")],
        next_link=f"{_BASE}/hackers/programs?page[number]=2&page[size]=25",
    )


def _list_page2() -> dict:
    return h1f.programmes_list(items=[h1f.programme_resource("beta", name="Beta")])


def _detail() -> dict:
    # Mirrors the documented detail shape: no `included`, no bounty_table - the
    # hacker API inlines no scopes on detail and exposes no bounty data at all.
    return h1f.programme_detail("acme", name="Acme", policy="Automated testing permitted.")


def _scopes() -> dict:
    return h1f.structured_scopes([h1f.structured_scope("*.acme.com", "WILDCARD", instruction=None)])


def _exclusions() -> dict:
    return h1f.scope_exclusions([h1f.scope_exclusion("Denial of Service")])


class _FakeH1Server:
    """Routes Session.get calls to the faithful H1 response for each path,
    recording every requested URL so tests can assert no base-doubling."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def get(self, url: str, params: dict | None = None, timeout: int | None = None):
        self.urls.append(url)
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "/structured_scopes" in url:
            resp.json.return_value = _scopes()
        elif "/scope_exclusions" in url:
            resp.json.return_value = _exclusions()
        elif "/hackers/programs/" in url:  # detail (handle path) - after sub-resource checks
            resp.json.return_value = _detail()
        elif "page[number]=2" in url:
            resp.json.return_value = _list_page2()
        else:
            resp.json.return_value = _list_page1()
        return resp


@pytest.fixture()
def fake_h1(monkeypatch):
    # Patch the session on the SAME singleton the tool wrappers call. selection
    # binds `from tools.h1_api import h1` at import, so it keeps the original
    # instance even after test_h1_api.py's fixture reloads tools.h1_api - patch
    # selection.h1, not tools.h1_api.h1, or the wrappers hit the real network.
    server = _FakeH1Server()
    monkeypatch.setattr(selection.h1._session, "get", server.get)
    return server


class TestBrowsePaginationContract:
    def test_paginates_via_absolute_next_without_doubling_base(self, fake_h1):
        previews = browse_programmes_tool.func(limit=5)

        assert [p.handle for p in previews] == ["acme", "beta"]
        # The page-2 fetch used the absolute links.next as-is, base intact.
        assert f"{_BASE}/hackers/programs?page[number]=2&page[size]=25" in fake_h1.urls
        # The regression signature: base concatenated onto an absolute URL.
        assert all("v1https://" not in u for u in fake_h1.urls), fake_h1.urls


class TestHydrateScopeContract:
    def test_scope_populated_from_dedicated_endpoint(self, fake_h1):
        prog = hydrate_programme_tool.func("acme")

        # The #115 regression catcher: scopes come from /structured_scopes, not
        # from a (never-present) `included` array on detail. If hydrate read
        # detail["included"], in_scope would be empty here.
        assert prog.handle == "acme"
        assert prog.in_scope, "hydrated programme has no in-scope assets"
        assert prog.in_scope[0].asset_identifier == "*.acme.com"
        assert prog.in_scope[0].asset_type == ScopeType.WILDCARD
        # Both endpoints were hit: detail then structured_scopes.
        assert f"{_BASE}/hackers/programs/acme" in fake_h1.urls
        assert f"{_BASE}/hackers/programs/acme/structured_scopes" in fake_h1.urls
        # And /scope_exclusions: its entries fold into out_of_scope so the
        # PenTester sees the do-not-touch set, not only the ineligible scopes.
        assert f"{_BASE}/hackers/programs/acme/scope_exclusions" in fake_h1.urls
        assert any(s.asset_identifier == "Denial of Service" for s in prog.out_of_scope)


class TestFullSelectionSlice:
    def test_browse_hydrate_save_passes_guardrail(self, fake_h1, tmp_path, monkeypatch):
        run_dir = tmp_path / "run"
        monkeypatch.setattr(runtime, "programme_handle", None)
        monkeypatch.setattr("runtime.run_dir", lambda: run_dir)

        # 1. survey -> 2. hydrate the pick (held in memory) -> 3. persist the
        #    single selection to the run dir.
        previews = browse_programmes_tool.func(limit=5)
        assert previews
        hydrate_programme_tool.func("acme")
        save_programme_tool.func("acme")

        # The selection artefact the whole pipeline reads is on disk and real.
        saved = run_dir / "programme.json"
        assert saved.exists()

        # 4. the select-task guardrail accepts it - so an empty-feedback Enter
        # actually finishes the task instead of looping on a failed guardrail.
        ok, _payload = validate_select_output(MagicMock(raw="selected acme"))
        assert ok is True
