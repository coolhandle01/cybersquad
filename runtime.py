"""
runtime.py - Pipeline-scoped context set once at run start.

Two module-level singletons (``run_id`` and ``programme_handle``) carry
workspace context every downstream tool needs: which run folder to
read / write, which programme to attribute outbound HTTP to. They are
set once per process - ``run_id`` by ``main.py``, ``programme_handle`` by
the PM's ``Save Selected Programme`` - and read by tools that need to
locate workspace artefacts.

The single-pipeline-at-a-time invariant is enforced by ``bind_run_id``
and ``bind_programme``: re-binding to a *different* value raises so a
later caller cannot quietly stomp the in-flight run. Re-binding to the
same value is a no-op so pipeline retries and tests that call the
setter twice with the same input do not fail.

Tests bypass the binders via ``monkeypatch.setattr("runtime.<attr>", ...)``
which writes the attribute directly and gets cleaned up between tests
- that path stays open intentionally so test setup does not need a
disposable singleton wrapper.

FIXME #128: under the planned Flow refactor (parallel sub-flows,
``@listen`` feedback loops, DC + TA coordinating on H1 ticket comments)
this module-level pair stops being enough - each in-flight flow would
want its own ``(handle, run_id)`` pair. The structural fix is per-context
state (``contextvars.ContextVar`` or an explicit ``PipelineContext``
threaded via the CrewAI input dict). The bind-conflict guard below is
the load-bearing invariant that will tell us when we have hit that wall
- it raises instead of silently corrupting one flow's run folder with
another's artefacts.
"""

from __future__ import annotations

from pathlib import Path

run_id: str = ""
programme_handle: str = ""


def bind_run_id(new_run_id: str) -> None:
    """Bind ``run_id`` for this process.

    Raises ``RuntimeError`` if a different ``run_id`` is already bound -
    the single-pipeline-at-a-time invariant. Same-value rebind is a
    no-op. See module docstring + #128 for the Flow-era replacement.
    """
    global run_id
    if run_id and run_id != new_run_id:
        raise RuntimeError(
            f"runtime.run_id already bound to {run_id!r}; refusing to rebind to "
            f"{new_run_id!r}. Single-pipeline-at-a-time invariant - see #128."
        )
    run_id = new_run_id


def bind_programme(handle: str) -> None:
    """Bind ``programme_handle`` for this process.

    Raises ``RuntimeError`` if a different handle is already bound -
    the single-pipeline-at-a-time invariant. Same-value rebind is a
    no-op. See module docstring + #128 for the Flow-era replacement.
    """
    global programme_handle
    if programme_handle and programme_handle != handle:
        raise RuntimeError(
            f"runtime.programme_handle already bound to {programme_handle!r}; "
            f"refusing to rebind to {handle!r}. "
            "Single-pipeline-at-a-time invariant - see #128."
        )
    programme_handle = handle


def run_dir() -> Path:
    """Return the run-specific folder: {reports_dir}/programs/{handle}/{run_id}/"""
    from config import config

    if not programme_handle or not run_id:
        raise RuntimeError(
            "runtime.programme_handle and run_id must be bound (via "
            "bind_programme / bind_run_id) before run_dir()"
        )
    return Path(config.reports_dir) / "programs" / programme_handle / run_id


def programme_cache_path(handle: str) -> Path:
    """Return {reports_dir}/programs/{handle}/programme.json"""
    from config import config

    return Path(config.reports_dir) / "programs" / handle / "programme.json"
