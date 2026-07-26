"""
tools/workspace.py - read-only access to the per-run shared workspace.

Agents pass artefact basenames through their task context (recon.json,
findings.json, verified.json, ...). These helpers let any agent list and
read those files on demand.

The API is deliberately narrow: inputs are paths *relative to* the run
directory, full stop. No absolute paths, no parent traversal. The shape
itself communicates the contract; we are not in the business of providing
arbitrary-read primitives to LLM-driven agents.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import runtime


def _validate_relative_path(relative_path: str) -> PurePosixPath:
    """Validate ``relative_path`` as a relative path with no parent traversal.

    Raises ValueError on anything that is not a plain relative path. The check
    is on the *input shape*, not the resolved location: the API contract is
    "relative path under the run directory", and shapes that do not match are
    a contract violation, not a near-miss to repair.
    """
    if not relative_path:
        raise ValueError("relative_path must not be empty")
    parsed = PurePosixPath(relative_path)
    if parsed.is_absolute():
        raise ValueError(f"relative_path must be relative, not absolute: {relative_path!r}")
    if ".." in parsed.parts:
        raise ValueError(f"relative_path must not contain '..': {relative_path!r}")
    return parsed


def resolve_run_path(relative_path: str) -> Path:
    """Resolve ``relative_path`` under runtime.run_dir() with the same contract
    read_run_file enforces: relative-only, no parent traversal, no symlink
    escape. Use this in every tool that reads an inter-agent artefact - it
    keeps the "agents pass relative paths" invariant true end-to-end."""
    _validate_relative_path(relative_path)
    run_root = runtime.run_dir().resolve()
    path = (run_root / relative_path).resolve()
    if not path.is_relative_to(run_root):
        raise ValueError(f"relative_path resolves outside the run directory: {relative_path!r}")
    return path


def list_run_files() -> list[dict]:
    """List files in the run directory (recursive) with byte sizes.

    Returns a list of {"name": <path relative to run_dir>, "size_bytes": int}
    sorted by name. Agents use this to discover what their teammates have
    written before deciding which file to sample.
    """
    run_root = runtime.run_dir().resolve()
    if not run_root.is_dir():
        return []
    out: list[dict] = []
    for path in sorted(run_root.rglob("*")):
        if not path.is_file():
            continue
        out.append(
            {
                "name": str(path.relative_to(run_root)),
                "size_bytes": path.stat().st_size,
            }
        )
    return out


def read_run_file(relative_path: str) -> dict:
    """Read a file from the run directory and return its full contents.

    ``relative_path`` is a path *relative to* runtime.run_dir() (e.g.
    "recon.json"). Absolute paths and parent traversal are not accepted.
    Returns {"name": relative_path, "size_bytes": int, "content": str}.
    """
    path = resolve_run_path(relative_path)
    if not path.is_file():
        raise FileNotFoundError(f"{relative_path!r} not found in run directory")
    content = path.read_text(encoding="utf-8", errors="replace")
    return {
        "name": relative_path,
        "size_bytes": path.stat().st_size,
        "content": content,
    }
