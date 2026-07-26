---
name: cybersquad-agent-llm
description: Construct CrewAI Agents in cybersquad with an explicit `crewai.LLM(...)` carrying model, temperature, and max_tokens. A bare model string passed to `Agent(llm=...)` silently ignores temperature and max_tokens. Load before editing crew.py or any code constructing a CrewAI `Agent` or `LLM`.
---

# Agent LLM construction

## Construct the LLM explicitly

```python
from crewai import LLM

llm = LLM(
    model=config.llm.model,
    temperature=config.llm.temperature,
    max_tokens=config.llm.max_tokens,
)
```

Then pass `llm` into `Agent(llm=...)`. Never pass a bare model string to `Agent(llm=...)` directly - CrewAI silently ignores `temperature` and `max_tokens` in that path and the agent runs with defaults that do not match `config.llm`. The CrewAI LLM class and its accepted parameters are documented at <https://docs.crewai.com/en/concepts/llms>; the `Agent` constructor's `llm` parameter at <https://docs.crewai.com/en/concepts/agents>. We pin `crewai>=1.14` in `pyproject.toml`.

## The model prefix

The model name must carry its litellm provider prefix:

```python
# correct
config.llm.model == "anthropic/claude-sonnet-4-20250514"

# wrong - litellm cannot route this
config.llm.model == "claude-sonnet-4-20250514"
```

If you change the default model in `config.py`, keep the `anthropic/` (or other provider) prefix. `tools/metrics.py` strips everything up to and including the first `/` before its pricing-table lookup - do not regress that code path.

## When this applies

- Editing `crew.py`
- Editing anything that imports `crewai.Agent`
- Changing `config.llm.model`, `config.llm.temperature`, or `config.llm.max_tokens`
- Writing a test that instantiates an `LLM` or `Agent`

## Upstream alignment

This skill is a narrow footgun overlay - the footgun is that `Agent(llm="bare-model-string")` silently drops `temperature` and `max_tokens`. The fix is mechanical.

For general agent design (role-goal-backstory framework, when to use one vs many agents, `max_iter` / `max_rpm` tuning, `function_calling_llm` split for tool-call cost, code execution, planning configs with `reasoning_effort`, knowledge sources, agent guardrails), see [crewAIInc/skills `design-agent`](https://github.com/crewAIInc/skills/blob/main/skills/design-agent/SKILL.md). That is the canonical upstream best-practice; this skill complements it, does not replace it. If you are doing anything more than wiring the `LLM` instance, read upstream first.
