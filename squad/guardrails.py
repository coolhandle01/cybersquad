"""squad/guardrails.py - function guardrails on pipeline task handoffs.

A CrewAI *function* guardrail has signature ``(TaskOutput) -> tuple[bool, Any]``:
return ``(True, value)`` to pass ``value`` to the downstream task, or
``(False, error)`` to feed ``error`` back to the agent, which re-runs the task
up to its ``max_retries``. Function guardrails validate in plain Python against
our typed workspace artefacts - no LLM judge, no extra LLM spend (the variant
that earns its keep when the output is a typed artefact we already model).

``validate_select_output`` guards the ``select -> recon`` handoff. The Programme
Manager hands the selected programme to recon through the workspace artefact
``<run_dir>/programme.json`` (written by its ``Save Selected Programme`` tool),
not through its free-text answer - so the guardrail validates *that file*, the
exact artefact recon's ``current_programme()`` will read, rather than the
agent's raw response. A malformed or missing ``programme.json`` is caught here,
at the boundary, instead of derailing recon downstream.
"""

# NB: no `from __future__ import annotations` here. CrewAI's Task guardrail
# validator (crewai/task.py) inspects `inspect.signature(fn).return_annotation`
# with get_origin/get_args and does NOT resolve string annotations - under
# PEP 563 the annotation would arrive as the string "tuple[bool, str]",
# get_origin() would return None, and the task would reject the guardrail with
# "If return type is annotated, it must be Tuple[bool, Any]". Keeping the
# annotation a live type object is load-bearing.
from crewai import TaskOutput
from pydantic import ValidationError

from squad.tools.workspace_tools import current_programme


def validate_select_output(result: TaskOutput) -> tuple[bool, str]:
    """Reject a ``select`` task that did not persist a valid ``programme.json``.

    Passes when ``<run_dir>/programme.json`` exists and deserialises to a
    ``Programme`` carrying a non-empty ``handle`` - the snapshot recon reads via
    ``current_programme()``. On failure returns the reason so the agent can call
    ``Save Selected Programme`` (or fix its selection) and retry. The agent's raw
    answer is passed through unchanged on success so the ``context=`` chain to
    recon is unaffected.
    """
    try:
        programme = current_programme()
    except (RuntimeError, FileNotFoundError):
        return (
            False,
            "No programme.json was written to the run directory. Call "
            "'Save Selected Programme' with your chosen handle so the selection "
            "is persisted before you finish.",
        )
    except ValidationError as exc:
        return (False, f"programme.json failed schema validation: {exc}")
    if not programme.handle:
        return (
            False,
            "The persisted programme.json has an empty handle; select a real "
            "programme before finishing.",
        )
    return (True, result.raw)
