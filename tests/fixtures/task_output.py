"""TaskOutput fixture - the unit-test surface for task guardrails.

A CrewAI *function* guardrail has signature ``(TaskOutput) -> (bool, Any)``, so
a guardrail's unit test needs a real ``TaskOutput`` to call it with.
``make_task_output`` builds one with sensible defaults, mirroring the
``programme`` / ``dvwa_programme`` pattern of handing the test the real Pydantic
type rather than a ``MagicMock`` with whatever attributes the test author
thought to set - so the guardrail runs against the same shape CrewAI would hand
it at runtime.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from crewai import TaskOutput


@pytest.fixture()
def make_task_output() -> Callable[..., TaskOutput]:
    """Factory for a ``TaskOutput`` shaped like a finished task's result.

    Defaults cover the common guardrail-test case - only ``raw`` carries
    meaning to a function guardrail, so it is the leading positional argument.
    ``description`` and ``agent`` are required by ``TaskOutput`` and carry
    placeholders, not because a guardrail reads them; override the placeholders
    via keyword.
    """

    def _make(
        raw: str = "",
        *,
        description: str = "select task",
        agent: str = "Programme Manager",
        expected_output: str = "a selected programme",
    ) -> TaskOutput:
        return TaskOutput(
            description=description,
            agent=agent,
            expected_output=expected_output,
            raw=raw,
        )

    return _make
