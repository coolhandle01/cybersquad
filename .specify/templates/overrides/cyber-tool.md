# Tool Specification: [TOOL NAME]

**Feature Branch**: `[###-tool-name]`
**Created**: [DATE]
**Status**: Draft
**Input**: User description: "$ARGUMENTS"

<!--
  Spec for a cybersquad `@cyber_tool` (squad.cyber_tool): a CrewAI tool a squad
  agent invokes. State only what THIS tool does and how it is verified.
  Universal contributor / CI / testing constraints are INHERITED (see footer) -
  do not restate them. Fill every [PLACEHOLDER]; mark unknowns
  [NEEDS CLARIFICATION: question].
-->

## Purpose *(mandatory)*

[One sentence: the capability this tool gives the agent, and when the agent reaches for it.]

## Tool Contract *(mandatory)*

**Invocation name**: `[tool_name]`  <!-- the @cyber_tool("name") the agent calls -->

**Inputs** (`args_schema`) <!-- each field typed; the Field(description=...) is the agent's per-parameter doc -->

| Field | Type | Meaning (agent-facing) |
|---|---|---|
| `[param]` | `[type]` | [what it is / how the agent supplies it] |

**Returns**: `[typed Pydantic shape, e.g. list[RawFinding] or SomeModel]`  <!-- never a bare dict/str -->

**Behaviour**

- [What the tool does with valid input, deterministically.]

**Refusal / empty outcomes**

- IF [precondition not met], the tool MUST [return empty / no-op / raise X], not [the wrong outcome].

## Requirements *(mandatory)*

<!-- Tool-specific behaviour only, each independently testable. -->

- **FR-001**: The tool MUST [capability].
- **FR-002**: WHEN [trigger], the tool MUST [response].
- **FR-003**: IF [error / edge], the tool MUST [safe outcome].

## Observable Behaviour (test oracles) *(mandatory)*

<!-- WHAT a test asserts on: the observable effect (the outbound request it built, the
     fields of the model it returned), never a value a fake handed back. The
     no-paper-tiger bar and mutation-audit practice are inherited (cybersquad-tests);
     name the concrete oracles for THIS tool here. -->

- [Observable 1: e.g. the exact outbound request - URL, params, headers.]
- [Observable 2: the empty / refusal path returns [X].]

## Success Criteria *(mandatory)*

- **SC-001**: [Measurable outcome, e.g. "returns the expected model for a known-good fixture and the empty result for a known-bad one".]

## Out of Scope *(mandatory)*

<!-- Named gaps, so an absence is a decision not an oversight. -->

- [What this tool deliberately does not do, and where that work lives if anywhere.]

## Assumptions

- [Reasonable defaults chosen where the description was silent; otherwise [NEEDS CLARIFICATION: ...].]

---

*Inherited, not restated here: ASCII-only source, minimal diff, the CI parity stack,
a typed `args_schema` and typed return, the framework-seam rule (logic in a plain
function, not the decorated body), and the test-observability / mutation-audit
doctrine. See `CONTRIBUTING.md` and the `cybersquad-tool` / `cybersquad-tests` skills.*
