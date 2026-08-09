"""Test-invocation utilities.

``invoke_tool`` is the production-shape entry point for a
``@cyber_tool`` wrapper - args_schema validation then body call,
matching what CrewAI does at runtime. Tests that exercise
scope-guard behaviour (the ``Target*`` typed aliases' AfterValidators)
go through this so the validator actually fires; ``.func(...)`` alone
bypasses args_schema validation.

``reload_module`` is the boilerplate-killer for tests that need a
module re-imported after monkeypatching env vars.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def invoke_tool():
    """Invoke a ``@cyber_tool`` wrapper the way CrewAI does at runtime.

    CrewAI's tool-call path is ``args_schema.model_validate(payload).
    model_dump()`` -> ``func(**dumped)``. The ``TargetFQDNs`` /
    ``TargetEndpoints`` / ``TargetFQDN`` / ``TargetEndpoint``
    typed aliases run their ``AfterValidator`` during the
    ``model_validate`` step - that IS the scope guard. Tests that
    exercise scope-guard behaviour call wrappers through this fixture
    so the validator actually fires; ``.func(...)`` alone bypasses the
    args_schema and sees the raw input verbatim.
    """

    def _invoke(wrapper, **kwargs):
        validated = wrapper.args_schema.model_validate(kwargs).model_dump()
        return wrapper.func(**validated)

    return _invoke


@pytest.fixture()
def reload_module():
    """Reload a module so monkeypatched env vars take effect on module-level singletons.

    Usage: reload_module(my_module)
    """
    import importlib

    return importlib.reload
