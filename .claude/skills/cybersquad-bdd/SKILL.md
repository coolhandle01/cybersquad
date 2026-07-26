---
name: cybersquad-bdd
description: BDD tests exercise agent reasoning - prompts, skills, how an agent uses its tools - with a real LLM. Load before creating or editing files under tests/features/ or tests/bdd/.
---

# cybersquad BDD tests

BDD tests exercise agent *reasoning*: prompts, skills, and how an agent uses its tools given a context. They are not for tool logic (that is unit tests). They call a real LLM, are slow, and cost tokens.

**BDD tests require a real `ANTHROPIC_API_KEY` in the developer's local environment.** Do not attempt to run them in a remote execution environment or in CI - neither has the LLM key available. These are developer-run tests.

## File layout

```
tests/
  features/
    programme_manager.feature   # Gherkin scenarios - one file per agent
    osint_analyst.feature
  bdd/
    test_programme_manager.py   # step definitions for programme_manager.feature
    test_osint_analyst.py
```

## Running

```bash
pytest -m bdd          # BDD only - needs ANTHROPIC_API_KEY
pytest -m unit         # default CI run - no LLM key needed
pytest                 # everything
```

## Marker

All BDD test files must carry `pytestmark = pytest.mark.bdd` at module level. This keeps them out of `pytest -m unit` runs and out of CI.

## What to mock

Mock the H1 API and any external HTTP calls. **Do not mock the LLM** - the point of a BDD test is to exercise real reasoning. Do not mock CrewAI agent internals.

```python
# correct - mock the boundary, let the LLM run
with patch("squad.programme_manager.h1.list_programmes", return_value=programmes):
    result = run_agent(...)

# wrong - mocking the LLM defeats the purpose
with patch("crewai.Agent.execute_task", return_value="fake output"):
    ...
```

## Writing a .feature file

One feature file per agent. Scenarios describe observable behaviour, not implementation. One observable outcome per scenario. Do not describe internal agent steps ("and the agent calls list_programmes") - describe what comes out, not what happens inside.

```gherkin
Feature: Programme Manager agent

  Scenario: Agent selects a programme that allows automated scanning
    Given the H1 API returns two programmes, one allowing and one prohibiting automated scanning
    When the Programme Manager agent runs
    Then the selected programme allows automated scanning
    And the selected programme accepts new reports
```

## Writing step definitions

Step definitions live in `tests/bdd/test_<agent>.py`. Use `scenarios()` to link to the feature file. Steps receive pytest fixtures via dependency injection - the shared fixtures under `tests/fixtures/` (loaded via `pytest_plugins` in `tests/conftest.py`) are all available, and you should reuse them rather than re-constructing models locally. See the `cybersquad-test-fixtures` skill for the catalogue.

```python
from pytest_bdd import scenarios, given, when, then
import pytest
from unittest.mock import patch

pytestmark = pytest.mark.bdd

scenarios("programme_manager.feature")

@given(
    "the H1 API returns two programmes, one allowing and one prohibiting automated scanning",
    target_fixture="h1_programmes",
)
def h1_programmes(programme):
    open_pgm = programme.model_copy(update={"accepts_new_reports": True})
    closed = programme.model_copy(update={"accepts_new_reports": False, "handle": "closed"})
    return [open_pgm, closed]
```

Use `target_fixture` on `@given` and `@when` steps to name the fixture the step produces; downstream steps receive those fixtures by parameter name.

## Token cost tracking

CrewAI returns token usage on `CrewOutput.token_usage`. Use `estimate_cost()` from `tools/metrics.py` to convert counts to USD and log the cost at the end of each scenario. A significant cost increase between runs is a prompt regression signal.

In `tests/bdd/conftest.py`:

```python
@pytest.fixture()
def log_token_cost(request):
    costs: list[float] = []
    def _record(crew_output, model: str) -> float:
        usage = crew_output.token_usage
        cost = estimate_cost(model, usage.prompt_tokens, usage.completion_tokens)
        costs.append(cost)
        return cost
    yield _record
    print(f"\n[token cost] {request.node.name}: ${sum(costs):.4f}")
```

Spike-detection assertions are useful but optional:

```python
@then("the agent completes within a reasonable token budget")
def check_token_budget(pm_output, log_token_cost):
    cost = log_token_cost(pm_output, "anthropic/claude-sonnet-4")
    assert cost < 0.10, f"Agent cost ${cost:.4f} - possible prompt regression"
```
