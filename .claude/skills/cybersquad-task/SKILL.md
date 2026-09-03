---
name: cybersquad-task
description: Construct CrewAI tasks via build_task(). Prose lives in description.md / expected_output.md. Inter-agent structured handoff uses workspace files, not output_pydantic. Load before editing tasks.py.
---

# cybersquad task conventions

## Construction: build_task() - never bare `Task(...)`

`squad/__init__.py` defines `build_task(task_name, member, agent, context=[...], human_input=hi)`. It reads the per-task `description.md` and `expected_output.md` from the agent's directory, wires the agent, and centralises `human_input` gating via `config.human_input`.

Writing `Task(...)` directly puts prose in Python strings and bypasses the toggle. Use the helper.

## Prose lives in markdown, not Python strings

```
squad/<member>/
    role.md
    goal.md
    backstory.md
    <task_name>/description.md
    <task_name>/expected_output.md
```

Multi-task agents (Vulnerability Researcher has `research/` and `triage/`) get one subdirectory per task. `SquadMember.read()` is the only loader; missing files raise at build time.

This separation is deliberate: prompt iteration is a markdown edit, wiring is a Python edit, and neither blocks the other.

## Inter-agent structured handoff: workspace files, not `output_pydantic`

When data flows between agents (recon -> attack plan -> findings -> verified -> reports), use the workspace-file pair pattern:

- Producer agent calls a typed `@tool` like `Finalise Research(plan: AttackForest)` that validates and writes `attack_forest.json` to the run directory; returns the bare filename.
- The *task's* textual output is freeform briefing prose plus that filename.
- Consumer agent calls a typed `@tool` like `Read Attack Plan -> AttackForest` to deserialise the artefact.

DO NOT use `output_pydantic=SomeModel` on tasks for inter-agent flow. Three reasons:

1. **Size.** AttackGraph is ~115KB / ~30K tokens on real targets. `output_pydantic` puts the full JSON in every downstream `context=`, which torches the LLM window.
2. **Prose-coercion cost.** `output_pydantic` constrains the agent to JSON-only output. Agents naturally want to produce "Here is my reasoning, then the JSON" and JSON parsing breaks on the prose. Suppressing the prose reliably takes non-trivial prompt engineering.
3. **Both-and.** Workspace files let the task's textual output be reasoning-narrative (which the next agent uses to orient) AND the typed artefact be the structured contract (which downstream code consumes). `output_pydantic` collapses these into one.

A consumer agent does not have to re-read the whole artefact to use it. The typed slicers (`Recon Endpoints` / `Recon Open Ports` / `Recon Subdomains`) pull narrow schema-filtered views on demand, and `Recon Semantic Search` (the #169 spike, `squad/tools/recon_search.py`) lets an agent *query* `recon.json` in natural language - a vector search over the same file - without loading it whole. Both are the size argument (reason 1) applied at read time: the workspace file is the contract, the slicer/search is how a downstream agent samples it cheaply. The vector path complements the typed slicers (it catches cross-cutting questions a filter cannot phrase); it is size-dependent, so reach for the typed slicer first when the question fits an axis.

For the tool-side conventions (writer/reader pair, return types, where shared tools live, wrapping CrewAI built-ins like `JSONSearchTool`), load `cybersquad-tool`.

## When `output_pydantic` is acceptable

`output_pydantic` earns its keep when:

- The output is consumed by *orchestration code*, not by another agent in the chain (rare in cybersquad).
- The structure is small enough that the size argument does not apply AND you have a reason to want JSON over prose in the next agent's context.

If unsure, default to workspace files. The pair pattern earns its keep.

## `context=` chain

`context=[prior_task, ...]` lists upstream tasks whose outputs become this task's context. CrewAI's `aggregate_raw_outputs_from_tasks` joins each prior task's `output.raw` with dividers - there is no automatic structured passing.

Use `context=` explicitly even in sequential pipelines. It makes the data-flow graph readable and enables non-linear deps. Example - the Vulnerability Researcher's triage task reads from BOTH `pentest` AND its own earlier `research` task:

```python
triage = build_task(
    "triage", VULNERABILITY_RESEARCHER, agents["vulnerability_researcher"],
    context=[pentest, research, select],
    human_input=hi,
)
```

## `human_input` toggle

Always pass `human_input=hi` where `hi = config.human_input` (set via the `CYBERSQUAD_HUMAN_INPUT` env var). Never hardcode `True` or `False` - the toggle exists so production runs can be unattended while interactive runs gate at each step.

## Guardrails: validate a handoff before it derails downstream

A CrewAI *function* guardrail is `(TaskOutput) -> tuple[bool, Any]`: return `(True, value)` to pass `value` to the next task, or `(False, error)` to feed `error` back to the agent, which re-runs the task up to `max_retries`. Use the **function** variant (plain Python against our typed artefacts), not the LLM-judge variant - our workspace outputs are typed models we can just construct, so there is no free-text judgement to delegate and no extra LLM spend.

Canonical example: `squad/guardrails.py:validate_select_output`, guarding `select -> recon`.

**Validate the workspace artefact, not `result.raw`.** Inter-agent handoff flows through workspace files (see the section above), so the thing that actually derails recon is a malformed `<run_dir>/programme.json`, not the agent's prose answer. `validate_select_output` therefore calls the same `current_programme()` recon will call - validating the exact artefact the next agent reads - and only passes `result.raw` *through* (as the `True` value) so the `context=` chain is unchanged. Keying a guardrail off `result.raw` instead would validate the agent's free-text, which is fragile (agents wrap JSON in prose / fences) and checks the wrong surface.

Wire it through `build_task`, never a bare `Task(guardrail=...)`:

```python
select = build_task(
    "select", PROGRAMME_MANAGER, agents["programme_manager"],
    human_input=hi,
    guardrail=validate_select_output,
    max_retries=2,
)
```

`build_task`'s `guardrail` / `max_retries` params default to `None` (CrewAI's own defaults), so un-guarded tasks are unchanged. Keep `max_retries` modest - guardrail failures should converge or fail loudly, not loop expensively. Unit-test the guardrail directly with the `make_task_output` fixture (`tests/fixtures/task_output.py`) plus the rundir-staging fixtures (`run_dir` / `programme_in_workspace`); see `tests/squad/test_guardrails.py`. Other handoff boundaries (`recon -> research`, ...) stay un-guarded until the pattern earns its keep there.

## Upstream alignment

CrewAI's [crewAIInc/skills `design-task`](https://github.com/crewAIInc/skills/blob/main/skills/design-task/SKILL.md) is the canonical upstream best-practice for task design. Its strong recommendation is `output_pydantic` for structured handoff between tasks. Cybersquad deliberately diverges on that one point - see the "workspace files" section above. The rest of upstream `design-task` (single-purpose tasks, specific `expected_output`, function/LLM guardrails, conditional tasks, async, callbacks) we follow without exception.
