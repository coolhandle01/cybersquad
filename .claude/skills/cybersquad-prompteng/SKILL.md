---
name: cybersquad-prompteng
description: Communication conventions for tool wrappers in cybersquad. The args_schema Field is the LLM's per-parameter documentation; the docstring describes the tool's behaviour and refusal conditions, not its parameters. Builds on cybersquad-tool. Load before editing any @-decorated wrapper or args_schema in squad/.
---

# cybersquad prompt engineering

`cybersquad-tool` carries the *mechanics* of tool wrappers - which decorator, which return shape, which typed primitives. This skill carries the *communication* layer - what the LLM actually reads on tool selection and tool call, and how to write each so it lands well.

## The two LLM-visible surfaces

CrewAI's own custom-tools guide at <https://docs.crewai.com/en/learn/create-custom-tools> documents both surfaces (the `description` class attribute and the `args_schema: Type[BaseModel]` attribute on `BaseTool`) and explicitly recommends explicit Pydantic schemas: *"Defining a Pydantic model as your args_schema provides automatic input validation and clear error messages. Explicit schemas are recommended... they produce better agent behavior and clearer documentation."* Our `@cyber_tool` wrapper makes the explicit `args_schema` keyword-required so the recommendation is enforced, not aspirational.

CrewAI surfaces two distinct strings to the agent at different moments:

1. **Tool description** - the wrapper's function docstring. Read by the LLM when *choosing which tool to call*. Should answer "what does this do, what does it return, when does it refuse, what vocabulary does it draw from".
2. **Per-parameter description** - `Field(description=...)` on each args_schema field. Read by the LLM when *constructing the tool call*. Should answer "what shape is this parameter, what counts as valid, what does a mis-shape signal".

They are not redundant. They run on different LLM passes and answer different questions. Writing one well does not let you skip the other.

## What belongs in the docstring

- **Purpose**: one sentence naming what the tool does in agent terms.
- **Side effects**: writes to the run directory, mutates workspace artefacts, fires outbound HTTP, etc. Name the file paths if the next agent reads them.
- **Return shape**: what the agent will get back. The canonical wire shape, not the Python type.
- **Refusal conditions**: what makes the tool raise. "Refuses if nodes is empty, if any node is missing one of probe / target / rationale" - so the LLM avoids the obvious bad calls upstream of the wrapper.
- **Vocabulary cross-references**: the probe vocabulary appended to `Finalise Research`, the recon evidence kinds catalogue, the Severity enum values. The agent reads these once on tool selection; they do not need re-stating per call.

What does **not** belong: a per-parameter section ("Args: nodes - the typed list of attack-graph nodes, programme_handle - the H1 handle..."). That is what `Field(description=...)` is for, and the args_schema is the canonical place. Re-stating drifts as the schema evolves and adds nothing the LLM cannot read from the args_schema itself.

## What belongs in Field descriptions

- **Canonical format with example**: `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` named in the `vector` field's description, not just in the docstring. The LLM constructing a tool call reads the Field, not the docstring.
- **Constraint with consequence**: "a `Severity` enum (critical / high / medium / low / informational) - unknown values reject upstream". Naming the rejection mechanism teaches the LLM to self-correct rather than retry-with-noise.
- **What a mis-shape signals**: from `FQDN` - "the agent occasionally hands us a URL where we asked for a hostname; the strict reject is the signal that surfaces the mismatch". The Field description teaches the agent the boundary, not just the type.
- **Cross-field guidance**: "must match the handle the OSINT Analyst recon was run against" when fields couple. For workspace-state-sourced values, the right move now is to not take them as parameters at all (see `cybersquad-runtime`).

What does **not** belong: the parameter's name (the field name already says that); markdown formatting (CrewAI passes Field descriptions through plain-text); LLM persona instructions ("you are a careful security researcher" - those belong in the agent's `goal.md`, not on a per-call Field).

## The paranoid-by-design boundary

The args_schema is the surface the body trusts:

- **Shape** is constrained at Pydantic validation time. A mis-shaped value never reaches the body.
- **Scope safety** is constrained by typed args_schema field aliases (`TargetFQDNs` / `TargetEndpoints` / `TargetFQDN` / `TargetEndpoint` from `tools/recon/scope.py`). Each carries a Pydantic `AfterValidator` that runs the scope filter during `args_schema.model_validate(...)` - out-of-scope targets are filtered (lists) or rejected (singles) before any wrapper body sees input. The typed field IS the contract; see `cybersquad-tool` for the picking guidance per shape.

That is what lets the wrapper body be small - it does the work, not the re-checking. The "debatably paranoid" framing is exactly right: the boundary is paranoid so the body does not have to be. Inline scope dances in tool bodies are the anti-pattern this architecture exists to delete.

## Anti-patterns

- A docstring that re-documents the parameters the args_schema already describes (`"""... Args: handle - the H1 programme handle. items - the list of ..."""`). Drift risk; wastes the description surface.
- An empty Field description, or `Field(...)` with no `description=` at all. The args_schema test sweep enforces presence; quality of content is on you.
- A Field description that names the parameter (`"The programme handle to use."`) but not the *shape* or the *constraint*. The field name already says it is the programme handle. The description should say what makes it valid or invalid.
- Per-call instructions on a Field ("only call this when you have high confidence"). LLM-behaviour guidance belongs in the agent's `goal.md` / `backstory.md` (see `cybersquad-skill`), not on individual tool parameters.
- A tool docstring carrying the agent's reasoning frame ("you should use this tool when..."). The docstring describes the tool; the agent's prose describes the agent. Cross-talk leaks one audience into the other.
- A parameter that exists only so the LLM can re-affirm something the workspace already knows (the canonical example: a `programme_handle: str` field, where `runtime.programme_handle` and `<run_dir>/programme.json` already carry the value). If the value is workspace state, drop the parameter and source from `runtime`.

## Worked examples

- **`Calculate CVSS Score`** (`squad/vulnerability_researcher/tools/triage.py`): docstring carries purpose ("Compute the CVSS 3.1 base score... Use this instead of guessing"), return shape ("Returns a value in 0.0-10.0"), and the downstream-check it ties into ("Assess Finding verifies..."). The args_schema docstring names *why* the vector format is in the Field description - "so the LLM picks the right shape upstream of the call". The `vector` Field carries the canonical format string.
- **`Finalise Research`** (`squad/vulnerability_researcher/tools/research.py`): docstring describes the artefact written, the refusal conditions, and points to the Probe Vocabulary / Recon Evidence Kinds catalogues appended to the description. The args_schema docstring names workspace state as the contract for the handle. No `programme_handle` parameter - the workspace knows.
- **Test enforcement**: `tests/squad/<member>/test_args_schemas.py` carries `test_every_field_has_description` and per-tool content assertions like `test_calculate_cvss_description_names_vector_format`. The tests are the executable form of this skill - if a Field description loses its load-bearing content, CI catches it before the agent does.

## Connection to other skills

- **`cybersquad-tool`**: the mechanics (typed primitives, args_schema required, return shapes).
- **`cybersquad-models`**: WHY typed primitives matter at the model layer (the producer side).
- **`cybersquad-skill`**: the agent-facing prose surface (`goal.md` / `backstory.md` / `description.md`). Persona / behaviour rules go there, not on tool Fields.
- **This skill**: HOW to write the LLM-visible surfaces *on tools* so the agent picks the right tool and calls it with the right shape on the first try.
