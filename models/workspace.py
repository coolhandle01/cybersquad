"""
models.workspace - shared @tool return shapes for the per-run workspace.

Lives alongside ``squad.tools.workspace_tools``: the readers there return one of
these models so consumers work against a typed shape instead of a bare
``dict``.
"""

from __future__ import annotations

from pydantic import BaseModel


class RunFile(BaseModel):
    """One file in the per-run shared workspace."""

    name: str  # path relative to the run directory
    size_bytes: int


class RunFileContent(BaseModel):
    """The full contents of one run-directory file."""

    name: str
    size_bytes: int
    content: str
