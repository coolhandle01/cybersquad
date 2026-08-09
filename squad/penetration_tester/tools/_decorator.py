"""
squad/penetration_tester/tools/_decorator.py - Pentest-specialised tool decorator
and the both-shapes adapters every PT wrapper composes with.

Lives in its own submodule (extracted from the agent's ``__init__.py``
in the PT sub-package split) so the decorator + protocol + helpers can
be referenced from ``probes.py`` / ``cloud.py`` / ``recon.py`` /
``findings.py`` without dragging the registry's import surface into
every wrapper file.
"""

from collections.abc import Callable
from typing import Protocol, cast

from pydantic import BaseModel

from models import AttackGraph, Endpoint, RawFinding
from squad import SquadTool, cyber_tool

_PentestFn = Callable[..., list[RawFinding]]


class _PentestTool(SquadTool, Protocol):
    """Runtime shape of a CrewAI @tool: callable that also exposes .func.

    Inherits ``name`` / ``description`` / ``func`` from ``SquadTool`` and
    adds the call signature so callers (and the pentest factory) keep the
    ``list[RawFinding]`` return type that the squad contract test enforces.
    """

    def __call__(self, *args: object, **kwargs: object) -> list[RawFinding]: ...


def pentest_tool(
    name: str,
    *,
    check_fn: object = None,
    args_schema: type[BaseModel],
) -> Callable[[_PentestFn], _PentestTool]:
    """Pentest-specialised wrapper. Composes ``cyber_tool`` plus classification injection.

    ``cyber_tool`` handles the schema override (and the auto-detected
    typed-target scope guard); ``pentest_tool`` layers four
    categorisation streams from the underlying check function into the
    agent-facing docstring:

    * ``check_fn.owasp_categories`` (from ``@owasp(...)``)
    * ``check_fn.frameworks`` (from ``@framework(...)``)
    * ``check_fn.clouds`` (from ``@cloud(...)``)
    * ``check_fn.services`` (from ``@service(...)``)

    Every pentest probe goes through this wrapper, never bare ``@tool``
    and never raw ``@cyber_tool`` - the OWASP framing is what the PT
    agent's role.md teaches it to reason against, with framework /
    cloud / service stamps layered on for the probes that target a
    specific stack, provider, or named product.
    """

    def decorator(fn: _PentestFn) -> _PentestTool:
        if check_fn is not None:
            for attr, heading in (
                ("owasp_categories", "OWASP Top 10"),
                ("frameworks", "Frameworks targeted"),
                ("clouds", "Cloud providers targeted"),
                ("services", "Services targeted"),
            ):
                values = getattr(check_fn, attr, ())
                if values:
                    lines = "\n".join(f"  - {v}" for v in values)
                    fn.__doc__ = (fn.__doc__ or "").rstrip() + f"\n\n{heading}:\n{lines}\n"
        wrapped = cyber_tool(name, args_schema=args_schema)(fn)
        return cast(_PentestTool, wrapped)

    return decorator


def _parse_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Re-validate the endpoint list before handing it to a probe.

    The wrapper signature is ``list[Endpoint]`` so the agent-facing
    ``args_schema`` shows a typed schema, but CrewAI's
    ``args_schema.model_validate(...).model_dump()`` pass leaves the
    runtime value as ``list[dict]`` by the time the wrapper body runs.
    ``model_validate`` accepts both shapes - it returns the same Endpoint
    when given an instance and constructs one when given a dict - so this
    single helper is the both-shapes adapter for every probe wrapper.
    """
    return [Endpoint.model_validate(e) for e in endpoints]


def _recon_from_path(recon_path: str) -> AttackGraph:
    """Read a serialised AttackGraph from disk.

    ``recon_path`` is a relative path under the run directory. The
    outbound User-Agent is sourced from ``runtime.programme_handle``
    (set by the Programme Manager at run start), so no per-call
    programme attribution is needed here.
    """
    from tools.workspace import resolve_run_path

    return AttackGraph.model_validate_json(resolve_run_path(recon_path).read_text(encoding="utf-8"))
