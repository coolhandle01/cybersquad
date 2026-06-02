---
name: cybersquad-tool
description: Universal rules for every CrewAI `@tool`-wrapped function in cybersquad. Pydantic return shape, typed parameters, explicit `args_schema` via `@cyber_tool`, writer/reader workspace pair. Load before editing any `@tool` wrapper.
---

# cybersquad @tool conventions

Every CrewAI `@tool`-wrapped function the agents see follows these rules. They are universal; `cybersquad-pentest-tool` is a specialisation that adds OWASP + StrEnum + `@pentest_tool` on top of this baseline. If you are touching a pentest probe wrapper, load both.

## Use `@cyber_tool`, not bare `@tool`

`@cyber_tool(name, args_schema=...)` lives in `squad/__init__.py` and is the blessed replacement for `crewai.tools.tool`. It accepts a keyword-required `args_schema` Pydantic class that overrides the schema CrewAI would otherwise infer from the function signature.

```python
from pydantic import BaseModel, Field
from squad import cyber_tool
from tools.recon.scope import TargetFQDNs

class _S3CheckArgs(BaseModel):
    """Explicit args_schema for the S3 Bucket Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "S3 hostnames the OSINT Analyst surfaced in recon.subdomains"
            " (matching ``*.s3.*.amazonaws.com``) or via cert"
            " transparency / historical URLs. Probes each for public"
            " listing or bare 200."
        ),
    )


@cyber_tool("S3 Bucket Check", args_schema=_S3CheckArgs)
def s3_check_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    ...
```

Why this matters: every tool's contract is what the LLM reads when picking the tool, including per-field guidance. The inferred path cannot attach per-field `Field(description=...)`; the explicit path can, and writing those descriptions is where the LLM gets the targeting signal that keeps probes on-scope. Per-field descriptions also reject unknown StrEnum variants upstream of any HTTP request - the validation fires before a mis-call costs a request.

The "validate at the boundary, trust within" stance has a name and a canonical reference: Alexis King's [Parse, don't validate](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/) (2019). Pydantic v2 is the runtime that lets us do this in Python; see `cybersquad-models` for the upstream-alignment pointer to Pydantic's own docs and the version pin (single source of truth, so this skill doesn't drift when the pin moves). An args_schema is the LLM's input parsed into typed values at the boundary; the wrapper body trusts the parsed result and does not re-check shape. The CrewAI side - how `args_schema` and tool `description` are surfaced to the agent - is documented at <https://docs.crewai.com/en/learn/create-custom-tools>.

Rules:

- Class name is underscore-prefixed `_<ToolName>Args`. Every typed tool is registered in `MEMBER.schemas` (a `dict[str, type[BaseModel]]` on the `SquadMember` constant in each agent's `__init__.py`, alongside `tools`). The per-agent contract test under `tests/squad/<agent>/test_args_schemas.py` parametrises over `MEMBER.schemas` and calls the shared assertions in `tests/squad/_contract_assertions.py` - tool wires the explicit schema, every field has a description, closed-world mapping. New typed tools are discovered via the private-prefix class name; a missing `MEMBER.schemas` entry fires the test before reviewers see the PR.
- Every field carries a `Field(description=...)` phrased as agent-facing targeting guidance ("fire when open_ports shows X", "prioritise endpoints where Y"), not type information the schema already encodes.
- Field types mirror the wrapper signature exactly. StrEnum filters stay typed (`list[<StrEnum>] | None`), never `list[str]`. FQDN-shaped fields use the `FQDN` typed-string from `models.primitives`, never bare `str` (see "Typed string primitives" below).
- Schema lives inline in the same module as the wrapper, directly above the decorator. Do not import from a separate file.

Specialist wrappers compose on top of `@cyber_tool`: `@pentest_tool` (pentest probes - layers OWASP categories from `check_fn.owasp_categories` into the docstring) and `@research_brief_tool` (Vulnerability Researcher - layers `PROBE_VOCABULARY` and `RECON_EVIDENCE_KINDS`) both call `cyber_tool` underneath and pass `args_schema=` through.

### Scope guards are built in via the typed args_schema field

The pipeline split this discipline supports: **PM transcribes scope** (from H1's programme detail into a `Programme` snapshot at `<run_dir>/programme.json`); **OSINT inventories the surface** (the discovered hostnames / endpoints in `recon.json` are already filtered through `filter_in_scope` against `programme.in_scope`); **PT attacks the inventoried surface** (the args_schema validation re-checks the agent's pick against the same `programme.in_scope`). The PT never invents targets; it only attacks what OSINT inventoried. Wrappers that fuzz / guess / enumerate beyond OSINT's inventory belong in policy-gated high-risk tooling (see #65 and #67 for the precedent), not in the unconditional probe surface.

Mechanics: four typed aliases in `tools/recon/scope.py` carry the scope guard as a Pydantic `AfterValidator`. Each is `Annotated[<inner>, AfterValidator(...)]` so CrewAI's standard `args_schema.model_validate(...)` runs the filter at parse time - upstream-blessed Pydantic, no per-tool decorator parameter, no wrapper-side introspection.

| Alias | Inner | Semantic |
|---|---|---|
| `TargetFQDNs` | `list[FQDN]` | Filter silently - LLM may pass mixed candidate list, only in-scope survive |
| `TargetEndpoints` | `list[Endpoint]` | Same filter semantic, host-extracted from `Endpoint.url` |
| `TargetFQDN` | `FQDN` | Reject loudly - a single target is the LLM committing; OOS raises ValueError |
| `TargetEndpoint` | `Endpoint` | Same loud-reject semantic |

```python
from squad import cyber_tool
from tools.recon.scope import TargetFQDNs

class _ProbeFQDNsArgs(BaseModel):
    hostnames: TargetFQDNs = Field(description="...")

@cyber_tool("Probe FQDNs", args_schema=_ProbeFQDNsArgs)
def probe_hostnames_tool(hostnames: list[FQDN]) -> list[Endpoint]:
    """The args_schema validation has already dropped out-of-scope
    hostnames; the body just runs the probe."""
    if not hostnames:
        return []
    return list(probe_endpoints_impl(hostnames))
```

The args_schema field type IS the opt-in signal. The `FQDN` primitive (composed into each `Target*` alias) lowercases / strips / rejects empty / rejects schemes-ports-paths at validation time, so the filter input is canonical before the filter sees it - no per-wrapper normalisation step needed.

Rules:

- Use `TargetFQDNs` / `TargetEndpoints` (list filter, silent drop) on multi-target args_schema fields; use `TargetFQDN` / `TargetEndpoint` (single, loud reject) on commit-to-one fields. The matching field type IS the scope-safety signal. A field typed plain `list[FQDN]` / `Endpoint` validates RFC 1123 / URL shape but does *not* scope-check - reach for the `Target*` variant when the agent picks the targets.
- The body must still handle an empty filtered list. The validator does not short-circuit on empty; it forwards the empty list and the body decides.
- Tests for a wrapper with an `Target*` field need `programme_in_workspace` (the conftest fixture) so the validator's `current_programme()` lookup resolves. Tests that exercise the OOS-drop path take `bystander_url` and pass its hostname; tests that invoke a wrapper end-to-end use the `invoke_tool` fixture (mirrors CrewAI's `args_schema.model_validate(...).model_dump()` -> `func(**dumped)` path so the validator actually runs - direct `.func(...)` calls bypass args_schema).
- Do not duplicate the validator inside the body. The whole point of the typed alias is that scope-safety lives in the type signature - the body trusts the validated input.

## Typed string primitives

`models.primitives` carries the typed-string layer every higher-level model composes:

- `FQDN` - `Annotated[str, AfterValidator(...)]`. RFC 1123 hostname check: lowercases, strips, rejects schemes (`://`), ports (`:`), paths (`/`), oversized labels (>63 chars), oversized total (>253 chars), garbage characters. Use it on any field whose value is supposed to be a bare hostname; the agent occasionally hands us a URL and the strict reject is the signal that surfaces the mismatch.
- `HttpUrl` - same shape, validates a parseable http / https URL with a `FQDN`-valid host underneath. Runtime type stays `str` so `.startswith(...)` and string comparisons keep working. Use on any field whose value is supposed to be an HTTP/S URL.

Composition rule: when a higher-level model carries a field that is conceptually a hostname or URL, type it through the primitive. `HostInsight.hostname: FQDN` rather than `: str`; `Endpoint.url: HttpUrl` rather than `: str`; `dict[FQDN, list[int]]` rather than `dict[str, list[int]]` for hostname-keyed dicts. The primitive's validator fires per-field at model construction time, so mis-shaped values reject upstream of every downstream consumer.

**An annotation is not a runtime check - only model construction is.** The validator runs when Pydantic *constructs a model* (a model field, or an args_schema during `model_validate`). A plain function parameter annotated with a primitive - `def host_dir(hostname: FQDN)` - gets *no* validation; Python does not run the `AfterValidator` on a bare call, so the annotation is documentation there, not a guard. A helper that receives a *derived* host - a `RawFinding.target` (bare `str`), a `urlsplit(...).hostname` - is holding an unvalidated value despite the `FQDN` annotation. When such a value reaches a side effect (a filesystem path, a subprocess arg), sanitise it at that point: `recon_host_store.host_dir` rejects `.` / `..` (with `/` already turned to `_` by its sanitiser, nothing else can traverse) precisely because its `FQDN`-typed parameter is not the guarantee it looks like. The type signature is the contract *at a model boundary*; everywhere else it is a comment.

`HttpUrl` keeps its runtime type `str` by delegating to `pydantic.HttpUrl` internally; a future move to surfacing Pydantic's `HttpUrl` object directly (stronger contract, exposes `.host` / `.scheme` / `.port`, but the runtime type stops being `str` so every consumer would need auditing first) remains open.

For the **producer side** - when to define a new typed primitive, the prompt-injection threat model around free-text fields, and the cross-model coupling that the workspace-pair pattern preserves - see the `cybersquad-models` skill, which auto-loads on `models/*.py` edits.

## Return a pydantic model, or `list[<Model>]`

```python
# correct - the agent sees a schema
@cyber_tool("Read Attack Plan", args_schema=_ReadAttackForestArgs)
def read_attack_forest_tool() -> AttackForest:
    return load_attack_forest(attack_forest_path())

@pentest_tool("Reflected XSS Probe", check_fn=check_reflected_xss, args_schema=_XssArgs)
def xss_probe_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    return list(check_reflected_xss(_parse_endpoints(endpoints)))
```

```python
# wrong - the agent sees a JSON-shaped dict and has to reconstitute the schema
# from the docstring
@cyber_tool("Reflected XSS Probe", args_schema=_XssArgs)
def xss_probe_tool(endpoints_json: str) -> list[dict]:
    return [f.model_dump() for f in check_reflected_xss(...)]
```

Never `dict`, `list[dict]`, or bare `list` (no inner type). CrewAI serialises pydantic models to JSON on its own; calling `.model_dump()` in the wrapper just strips the schema. If the underlying helper does not have a typed return yet, add the model before wiring the `@cyber_tool` - the model is the contract.

### The one exception: workspace-handle strings

`finalise_X` / `save_X` tools return the bare filename of the artifact they wrote (`"findings.json"`, `"attack_forest.json"`, `"verified.json"`). That `str` return is intentional - the filename is a handle the next agent passes to a typed reader. Document it in the docstring; do not invent a `WorkspaceHandle` wrapper model.

## Type the parameters too

```python
# correct
@pentest_tool("SSRF Probe", check_fn=check_ssrf, args_schema=_SsrfArgs)
def ssrf_probe_tool(
    endpoints: list[Endpoint],
    payloads: list[SsrfPayload] | None = None,
) -> list[RawFinding]:
    ...
```

```python
# wrong - the agent has no idea what strings are valid
def ssrf_probe_tool(endpoints: list[Endpoint], payloads: list[str] | None = None) -> ...:
```

The legacy `endpoints_json: str` parameter pattern is retired: pass the typed `list[<Model>]` directly. The LLM-side wire format is still JSON, but `args_schema.model_validate(kwargs).model_dump()` happens inside CrewAI before the function is called, so the wrapper receives `list[dict]` and re-validates via `_parse_endpoints` (the both-shapes adapter that accepts either a model instance or a dict). The agent sees a typed Endpoint schema instead of "pass a JSON string" - never reintroduce the JSON-string parameter for structured data.

## Workspace artifacts: writer and reader ship together

Any file an agent writes for the next agent to read needs both halves of the contract in the same PR:

| Writer | Reader |
|---|---|
| `finalise_recon(recon)` -> `recon.json` | `Recon Endpoints` / `Recon Open Ports` / `Recon Subdomains` slicers |
| `finalise_research(plan)` -> `attack_forest.json` | `read_attack_forest_tool` -> `AttackForest` |
| `finalise_triage(...)` -> `verified.json` | (Technical Author's typed reader) |

The reader returns the typed model; downstream agents work against the schema, not raw bytes. Never land a writer without the matching typed reader.

## Where tools live

- **Per-agent**: `squad/<agent>/__init__.py`. Each `@cyber_tool` / `@pentest_tool` is added to that agent's `MEMBER.tools` list.
- **Shared between agents**: `squad/workspace_tools.py`. Re-export through `squad/__init__.py` (`__all__` and the explicit re-export) so consumers `from squad import read_attack_forest_tool`, not from the deeper path.

## Where models live

`models/` is split per domain so the module that owns each shape is obvious at import time. Put a new model in the matching module; do not extend `models/__init__.py` (which is now pure re-exports for backward compat).

| Module | Contents |
|---|---|
| `models.primitives` | `FQDN`, `HttpUrl`, `IpAddr`, `Cidr`, `Email`, `IPType` - the typed-string primitive layer (one module per primitive) |
| `models.finding` | `RawFinding`, `VerifiedVulnerability`, `RawFindingSummary` |
| `models.asset` | the OAM asset / property / relation package - `Endpoint`, `Service`, `Product`, `ProductRelease`, `Url`, `TLSCertificate`, ...; properties `SourceProperty` / `VulnProperty` / `DNSRecordProperty`; relations `Relation` / `RelationType` |
| `models.insight` | `HostRole`, `HostPriority`, `HostInsight`, `HostScore`, `OpenPortsMap`, `HostAnnotation` |
| `models.nvd` | `CVE`, `CvssVector`, `Severity` |
| `models.mitre` | `CWE` |
| `models.attack` | `AttackGraph`, `AttackForest`, `AttackTree` |
| `models.h1` | HackerOne API shapes (incl. `ProgrammeReportSummary`) |

`Severity` lives in `models.nvd` (not `primitives`); `AttackGraph` in `models.attack` (not `asset`); the per-host insight shapes in `models.insight`. The full, authoritative map is the table in `models/__init__.py` - this is a pointer, not a mirror.

Dependency layers flow `primitives -> finding -> h1 -> asset`, with `insight` / `attack` composing on top; modules import only from layers below them. Consumers can still `from models import X` (re-exports preserve the public surface) but inside the package, prefer the per-module path so circular-import dances stay out of reach.

## The `SquadMember.tools` registry

`SquadMember.tools` is typed `list[CrewAITool]` (the `CrewAITool` Protocol in `squad/__init__.py`). The local `_PentestTool` / `_ResearchBriefTool` Protocols inherit from it, so the registry is properly typed end-to-end. The cross-agent contract test walks every `MEMBER.tools` entry and asserts return-type annotations - skill stays in AI context, test stays in CI.

## Anti-patterns to catch

- `[f.model_dump() for f in check_X(...)]` in any wrapper body - drop the comprehension, just `return list(check_X(...))`.
- Return annotation of `dict` for a structured payload that has a pydantic shape already.
- Bare `list` (no inner type) as a return annotation - either it is `list[str]` for a flat handle list, or it is `list[<Model>]` for structured rows.
- `@tool("...")` from `crewai.tools` for a new wrapper. Use `@cyber_tool` (or the appropriate specialist wrapper for probes / research briefs) so `args_schema` is enforced.
- An `args_schema` class with a field that lacks `Field(description=...)`. The whole point of the explicit path is per-field guidance; an empty description is the same gap the inferred path had.
- A field typed `str` whose value is a hostname (`hostname: str`, `host: str`, `domain: str`) or a URL (`url: str`, `endpoint: str`). Use `FQDN` / `HttpUrl` from `models.primitives` - the typed primitives reject mis-shaped values upstream.
- A `dict[str, ...]` whose keys are hostnames - type the key as `dict[FQDN, ...]` so the validator fires on the keys too.
- Adding a new model directly to `models/__init__.py`. The package is split per domain; put it in the matching module and let the re-export carry it.
- New workspace writer with no typed reader.
- `from squad.workspace_tools import ...` in a consumer instead of `from squad import ...` - the re-export exists so the import path stays stable when shared tools move.
- Inline scope dance in a tool body that takes agent-supplied targets (the `_load_programme + filter_in_scope` pattern). Use the typed `Target*` alias on the `args_schema` field so the Pydantic-native `AfterValidator` is what enforces scope; the guarantee lives in the type signature, not in the body.
- Fuzzing or guessing customer cloud-tenant names / bucket names / account names to probe `*.s3.amazonaws.com`, `*.blob.core.windows.net`, or any other third-party infrastructure. The PT only attacks what OSINT inventoried in `recon.subdomains` / `recon.endpoints`; if a candidate name isn't there, OSINT didn't surface it through legitimate discovery (DNS / cert transparency / historical URLs) and the PT can't fabricate it. High-risk post-discovery exploitation that goes beyond OSINT's inventory (credential checks against discovered panels, brute-force, ...) is policy-gated; see #65 (default credential checks) and #67 (credential stuffing) for the canonical pattern (programme-policy parser confirms authorisation, hard per-target cap enforced in code, full rate-limiter respected).
- A new `programme_handle: str` field on an args_schema for a tool whose body would only thread it into `current_programme()` or `filter_in_scope`. Workspace state (`runtime.programme_handle` / `<run_dir>/programme.json`) is the contract; the per-call handle is duplication.
- Direct assignment to `runtime.programme_handle` or `runtime.run_id`. Use the `runtime.bind_programme(...)` / `runtime.bind_run_id(...)` setters - they enforce the single-pipeline-at-a-time invariant by raising on a conflicting rebind (same-value rebind is a no-op for retries and tests). Reads stay on the module attribute. The invariant is load-bearing for the planned Flow refactor in #128 where parallel sub-flows would otherwise silently stomp each other's run folders.

## Canonical examples

These rules apply to every agent's `@cyber_tool` / `@pentest_tool` / `@research_brief_tool` wrappers, not just the pentester's.

- `squad/penetration_tester/__init__.py` and `squad/osint_analyst/__init__.py` are the largest reference surfaces. Each wrapper carries an explicit `_<ToolName>Args` schema directly above the decorator with `Field(description=...)` on every field. Pentest probes (`ssrf_probe_tool`, `idor_probe_tool`) are the shortest StrEnum examples; cloud / infra wrappers (`s3_check_tool`, `mongodb_tool`, `grafana_port_check_tool`) show `list[FQDN]` typed-target fields (auto-scope-filtered); path-style cloud wrappers (`sensitive_files_tool`, `grafana_path_check_tool`, `azure_sas_token_check_tool`) show `list[Endpoint]` typed-target fields; OSINT (`probe_hostnames_tool`, `annotate_host_tool`) show the same composition on the OSINT side.
- `squad/penetration_tester/__init__.py` `recon_endpoints_tool` returns `EndpointPage` - the canonical typed-return example. The wrapper lives on PT but reads OSINT's recon output, so the pattern is cross-agent.
- `squad/workspace_tools.py` `read_attack_forest_tool` returns `AttackForest` - mirror this shape on any new workspace reader (typed return, no `dict`).
- The workspace-handle string family demonstrates the `str` exception (writer returns the filename, next agent passes it to a typed reader):
  - `Finalise Recon` (`squad/osint_analyst/__init__.py`) -> `"recon.json"`
  - `Finalise Research` (`squad/vulnerability_researcher/__init__.py`) -> `"attack_forest.json"`
  - `Finalise Triage` (`squad/vulnerability_researcher/__init__.py`) -> `"verified.json"`
  - `Finalise Reports` (`squad/technical_author/__init__.py`) -> the reports manifest filename

## Upstream alignment

CrewAI's [crewAIInc/skills](https://github.com/crewAIInc/skills) repository publishes three skills today: `getting-started`, `design-agent`, `design-task`. None covers tool conventions at the project level; the closest upstream document is [`design-agent/references/custom-tools.md`](https://github.com/crewAIInc/skills/blob/main/skills/design-agent/references/custom-tools.md), which covers `@tool` vs `BaseTool` mechanics.

This skill *deliberately diverges* from upstream in two places. Being honest about that matters more than pretending compatibility.

### Divergence 1: structured returns from tools (chosen)

Upstream's architectural take is that structured data belongs on the *task* (`output_pydantic` / `output_json`), and tools just return text-fodder for the LLM's reasoning. We put pydantic on tools because:

- The cross-agent contract test that walks every `MEMBER.tools` entry needs introspectable return annotations to enforce the rule.
- Tests call `tool.func(...)` directly and want a typed return.
- `mypy` verifies cross-tool wiring (e.g. that `read_attack_forest_tool` actually returns what `Finalise Research` wrote).
- Probe tools return small, structured `RawFinding` lists - flattening them to text loses the structure agents reason over.

Wire-format equivalence: CrewAI serialises any return value to JSON-text for the LLM, so the agent sees the same text upstream wants *and* we get the Python-side discipline upstream does not.

### Divergence 2: inter-agent handoff via workspace files

A CrewAI task emits exactly one thing - the agent's text response, parked at `task.output.raw`. `output_pydantic` and `output_json` do not add a second channel; they constrain that text to JSON-shape and parse it for orchestration code. The next agent in the pipeline still receives raw text in its context (CrewAI's `aggregate_raw_outputs_from_tasks` joins `output.raw` from prior tasks with dividers), whether that text is freeform Markdown or schema-shaped JSON.

Two reasons we use workspace files for inter-agent structured data instead of `output_pydantic`:

1. **Size (forced).** AttackGraph artefacts run ~115KB / ~30K tokens on real targets. `output_pydantic=AttackGraph` would put that JSON in every downstream `context=` and torch the LLM window. Workspace files + typed slicers (`Recon Endpoints`, `Recon Open Ports`, `Recon Subdomains`) let agents pull narrow views on demand.

2. **The both-and (chosen).** With workspace files, the task's textual output is reasoning-narrative (a freeform briefing the next agent uses to orient) *and* the typed artefact is produced separately by a `Finalise X` tool call. We get narrative reasoning AND schema-enforced structure. `output_pydantic` collapses these into one - the agent must produce JSON-only output, and any reasoning prose it would naturally produce has to be suppressed via non-trivial prompt engineering. Many CrewAI users hit "agent said 'here is my analysis: { ... }' and the JSON parser broke."

The pair pattern (typed `finalise_X` writer + typed `load_X` reader) is the wedge that makes this work. The task-side conventions live in the `cybersquad-task` skill.

### When to revisit

If you find yourself wanting to relax either rule - "this tool's return is small, can it be a string?", "this task's handoff is small, can it use `output_pydantic`?" - re-derive from first principles rather than appealing to the rule. The divergences are intentional but not load-bearing forever.
