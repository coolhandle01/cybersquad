"""Programme / scope / run-directory fixtures.

``programme`` is the canonical in-scope ``Programme`` (``*.example.com``
wildcard + ``https://example.com`` URL). ``programme_in_workspace``
stages it into the test rundir as ``programme.json`` so
``current_programme()`` resolves end-to-end - tests that exercise any
``@cyber_tool`` with a ``Target*`` typed-target field take this fixture
so the args_schema scope-validator has a programme to consult.

``dvwa_*`` mirrors the same shape pointing at Damn Vulnerable Web
Application on localhost; reserved for the DVWA-sandbox e2e work in
#121 Phase 3.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from models import Severity
from models.h1 import Programme, ScopeItem, ScopeType


@pytest.fixture()
def run_dir(tmp_path, monkeypatch):
    """Point ``runtime.run_dir()`` at this test's ``tmp_path``.

    Every tool that reads / writes workspace artefacts resolves the
    rundir through ``runtime.run_dir()``. Tests that exercise those
    tools take this fixture to get a per-test rundir without patching
    the function at every consumer's import alias
    (``tools.workspace.runtime.run_dir`` / ``tools.triage_tools.runtime.run_dir``
    / etc) - every consumer ``import runtime`` so a single setattr on
    ``runtime.run_dir`` propagates to all of them.

    Returns the ``Path`` so tests can read / write fixture files
    against it directly.
    """
    monkeypatch.setattr("runtime.run_dir", lambda: tmp_path)
    return tmp_path


def stage_models_json(run_dir: Path, name: str, models: BaseModel | list[BaseModel]) -> Path:
    """Stage a model (or list of models) as a JSON **array** at ``<run_dir>/<name>``.

    For the list-shaped workspace artefacts (``findings.json`` / ``verified.json``);
    writes ``[model_dump(mode="json"), ...]`` so a tool can read it back. Accepts a
    single model (wrapped in a one-element array) or a list. For artefacts that hold
    a single object (``recon.json`` / ``attack_graph.json``) use ``stage_model_json``.
    Returns the written ``Path``. A helper, not a fixture - ``run_dir`` is already in
    scope at the call site."""
    items = models if isinstance(models, list) else [models]
    path = run_dir / name
    path.write_text(json.dumps([m.model_dump(mode="json") for m in items]), encoding="utf-8")
    return path


def stage_model_json(run_dir: Path, name: str, model: BaseModel) -> Path:
    """Stage a single model as a JSON **object** at ``<run_dir>/<name>``.

    For the object-shaped workspace artefacts (``recon.json`` / ``attack_graph.json``,
    which hold one ``AttackGraph``); writes ``model.model_dump_json()``. The singular
    counterpart to ``stage_models_json`` (which writes an array). Returns the Path."""
    path = run_dir / name
    path.write_text(model.model_dump_json(), encoding="utf-8")
    return path


@pytest.fixture()
def scope_item_url(target_apex: str) -> ScopeItem:
    return ScopeItem(
        asset_identifier=f"https://{target_apex}",
        asset_type=ScopeType.URL,
        eligible_for_bounty=True,
    )


@pytest.fixture()
def scope_item_wildcard(target_apex: str) -> ScopeItem:
    return ScopeItem(
        asset_identifier=f"*.{target_apex}",
        asset_type=ScopeType.WILDCARD,
        eligible_for_bounty=True,
    )


@pytest.fixture()
def programme(scope_item_url, scope_item_wildcard) -> Programme:
    return Programme(
        handle="test-programme",
        name="Test Programme",
        url="https://hackerone.com/test-programme",
        bounty_table={
            Severity.LOW: 100,
            Severity.MEDIUM: 500,
            Severity.HIGH: 2000,
            Severity.CRITICAL: 5000,
        },
        in_scope=[scope_item_url, scope_item_wildcard],
        out_of_scope=[],
    )


@pytest.fixture()
def programme_in_workspace(programme: Programme, run_dir, monkeypatch) -> Programme:
    """Stage ``programme.json`` into the run directory and point runtime at it.

    Reproduces what the PM's ``Save Selected Programme`` does at run
    start: writes ``<run_dir>/programme.json`` and sets ``runtime`` so
    every downstream consumer (``current_programme()``, the args_schema
    ``Target*`` validators, every tool that reads
    ``runtime.programme_handle`` for HTTP attribution) sees the
    in-flight programme without any per-test stubbing of the loader.

    The artefact *is* the fixture: tests assert against the same shape
    the next agent would actually consume.
    """
    (run_dir / "programme.json").write_text(programme.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr("runtime.programme_handle", programme.handle)
    return programme


@pytest.fixture()
def dvwa_programme() -> Programme:
    """A Programme shaped like Damn Vulnerable Web Application on localhost.

    DVWA (https://github.com/digininja/DVWA) is the canonical
    deliberately-vulnerable PHP/MySQL training target; the usual
    deployment is a local Docker container exposed on
    ``http://localhost``. A Programme-shaped fixture pointing at that
    lets BDD scenarios and DVWA-targeted integration work read 'the
    squad targets DVWA' against a fixture that maps to a real,
    runnable target rather than a synthetic ``example.com``.

    Bounty table mirrors the in-scope ``programme`` fixture's token
    values so downstream consumers do not need to special-case a
    zero-bounty programme; the comment is the documentation that DVWA
    is not actually a paying programme.

    FIXME(#121 Phase 3): piton for the DVWA sandboxed e2e work.
    Currently unused - landed alongside ``programme_in_workspace`` in
    #159 as scaffolding the BDD scenarios in Phase 3 will pick up. If
    #121 Phase 3 is descoped, delete this fixture and ``dvwa_in_workspace``.
    """
    return Programme(
        handle="dvwa-localhost",
        name="Damn Vulnerable Web Application (localhost)",
        url="https://hackerone.com/dvwa-localhost",
        bounty_table={
            Severity.LOW: 100,
            Severity.MEDIUM: 500,
            Severity.HIGH: 2000,
            Severity.CRITICAL: 5000,
        },
        in_scope=[
            ScopeItem(
                asset_identifier="http://localhost",
                asset_type=ScopeType.URL,
                eligible_for_bounty=False,
            ),
            ScopeItem(
                asset_identifier="http://127.0.0.1",
                asset_type=ScopeType.URL,
                eligible_for_bounty=False,
            ),
        ],
        out_of_scope=[],
    )


@pytest.fixture()
def dvwa_in_workspace(dvwa_programme: Programme, run_dir, monkeypatch) -> Programme:
    """DVWA staged into the run dir - same shape as ``programme_in_workspace``
    but the in-flight programme is DVWA, so BDD scenarios that point the
    squad at DVWA exercise the artefact the runtime actually consumes.

    FIXME(#121 Phase 3): see ``dvwa_programme`` above - this is the
    workspace-staged counterpart waiting on the DVWA e2e scenarios."""
    (run_dir / "programme.json").write_text(dvwa_programme.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr("runtime.programme_handle", dvwa_programme.handle)
    return dvwa_programme
