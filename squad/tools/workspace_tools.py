"""squad/tools/workspace_tools.py - shared run-workspace surface.

Two halves:

- ``@cyber_tool`` wrappers around the workspace artefact IO (``List
  Run Files``, ``Read Run File``, ``Read Attack Plan``).
- ``current_programme()`` - the shared programme-loader used by every
  agent (and by ``@cyber_tool``'s auto-detected scope filter) that
  needs the parsed ``Programme`` to reason against. Reads from
  ``<run_dir>/programme.json`` - the snapshot the Programme Manager's
  ``Save Selected Programme`` tool writes at the top of every run.
  No H1 API call: the workspace is the authoritative source once a
  programme has been selected.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

import runtime
from models import RunFile, RunFileContent
from models.attack import AttackForest
from models.h1 import Programme
from squad import cyber_tool
from tools import workspace
from tools.research_tools import attack_forest_path, load_attack_forest


def current_programme() -> Programme:
    """Return the Programme selected for the current run.

    Reads ``<run_dir>/programme.json`` - written by the Programme
    Manager's ``Save Selected Programme`` tool at run start
    (``squad/programme_manager/__init__.py``). Every downstream agent
    and every ``@cyber_tool``-wrapped tool that takes a typed-target
    field (``FQDN`` / ``Endpoint``) sources its Programme through
    this function rather than hitting the H1 API again: the workspace
    snapshot is the contract.

    Raises ``FileNotFoundError`` if the file is missing - that means
    the PM has not run yet, and any caller reaching this code path is
    out of pipeline order.
    """
    path = runtime.run_dir() / "programme.json"
    return Programme.model_validate_json(path.read_text(encoding="utf-8"))


class _ListRunFilesArgs(BaseModel):
    """Explicit args_schema for the List Run Files tool.

    The tool takes no parameters - the run directory is resolved from
    ``runtime.run_dir()`` at call time. The empty schema is still
    declared so the closed-world contract test in each consuming
    agent's ``test_args_schemas.py`` accounts for the tool, and so
    every shared workspace wrapper goes through ``@cyber_tool``.
    """


@cyber_tool("List Run Files", args_schema=_ListRunFilesArgs)
def read_run_filelist_tool() -> list[RunFile]:
    """List the artefacts written to the current run directory by the squad
    so far, each with its name and byte size. Use this to discover what an
    upstream teammate has produced before deciding which file to sample with
    Read Run File."""
    return [RunFile(**entry) for entry in workspace.list_run_files()]


class _ReadRunFileArgs(BaseModel):
    """Explicit args_schema for the Read Run File tool."""

    relative_path: str = Field(
        description=(
            "Path of the artefact to read, relative to the current run"
            " directory (e.g. ``recon.json``, ``findings.json``,"
            " ``attack_forest.json``). Absolute paths and any segment"
            " containing ``..`` are rejected by the workspace layer; the"
            " agent should pass the bare filename a finalise tool returned"
            " (or one List Run Files surfaced). A wrong ``relative_path``"
            " here loads the wrong artefact and the agent reasons over the"
            " wrong inputs - prefer the typed slicers (``Recon Endpoints``"
            " / ``Read Attack Plan`` / ``List Raw Findings``) when one"
            " exists for the artefact you want."
        ),
    )


@cyber_tool("Read Run File", args_schema=_ReadRunFileArgs)
def read_run_file_tool(relative_path: str) -> RunFileContent:
    """Read a file from the current run directory and return its full contents.
    ``relative_path`` is a path relative to the run directory (e.g.
    "recon.json") - the only kind of path this tool accepts."""
    return RunFileContent(**workspace.read_run_file(relative_path))


class _ReadAttackForestArgs(BaseModel):
    """Explicit args_schema for the Read Attack Plan tool.

    The tool takes no parameters - the attack plan path is resolved
    from ``runtime.run_dir()`` via ``attack_forest_path()`` at call
    time. The empty schema is still declared so the closed-world
    contract test in each consuming agent's ``test_args_schemas.py``
    accounts for the tool.
    """


@cyber_tool("Read Attack Plan", args_schema=_ReadAttackForestArgs)
def read_attack_forest_tool() -> AttackForest:
    """Load the Vulnerability Researcher's typed attack plan from
    ``attack_forest.json`` in the current run directory.

    Returns the typed ``AttackForest`` with ``programme_handle``, ``drafted_at``,
    and ``items`` - each item carrying ``probe``, ``target``,
    ``expected_ceiling``, ``rationale``, and ``recon_evidence``. Use this in
    preference to Read Run File on the same artefact: this tool deserialises
    the typed plan, so the agent works against the schema the VR wrote rather
    than a raw JSON blob.

    Raises if no attack plan exists yet for the current run.
    """
    return load_attack_forest(attack_forest_path())
