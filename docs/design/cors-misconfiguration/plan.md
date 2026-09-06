# Implementation Plan: CORS Misconfiguration Probe

**Branch**: `feat/cors-probe-impl` | **Date**: 2026-09-06 | **Spec**: `docs/design/cors-misconfiguration/spec.md`

**Input**: Feature specification from `docs/design/cors-misconfiguration/spec.md`

## Summary

Rework the existing `check_cors_misconfiguration` probe to the spec: a browser-correct
detection oracle scored in chainability tiers (HIGH credentialed reflection / LOW
uncredentialed reflection / INFORMATIONAL wildcard), two named Origin variants
(`reflected_origin`, `null_origin`) selectable by the agent, one finding per endpoint
with the highest tier winning, and a non-resolving canary origin. The detection loop
moves into an undecorated `_impl` so it is mutation-observable, and the squad wrapper
gains an explicit `endpoints` + `probe_names` args_schema.

## Technical Context

**Language/Version**: Python 3.12 (`requires-python >=3.12`)

**Primary Dependencies**: `requests` (via `tools.http`), `pydantic` (args_schema + models), CrewAI `@tool` (via `@pentest_tool`)

**Storage**: N/A - stateless probe; returns `list[RawFinding]`

**Testing**: `pytest -m unit` with `respx`/`patch`, sockets blocked (`pytest-socket`, `--disable-socket`)

**Target Platform**: Linux; runs inside the CrewAI pentester agent

**Project Type**: Single project (the cybersquad pipeline)

**Performance Goals**: N/A - politeness-throttled via `adaptive_sleep`, not throughput-bound

**Constraints**: ASCII-only source, minimal diff, 96% coverage floor + per-diff ratchet, no real egress in the unit tier

**Scale/Scope**: One probe module + its squad wrapper + its test module

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Requirements in EARS (NON-NEGOTIABLE)**: PASS. `spec.md` states FR-001..FR-007 in EARS with `SHALL` as the sole modal (no `MUST`/`SHOULD`). No new normative requirements are introduced by the plan.

No violations. Complexity Tracking not required.

## Project Structure

### Documentation (this feature)

```text
docs/design/cors-misconfiguration/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   └── cors_misconfiguration.md   # Tool contract
└── tasks.md             # /speckit-tasks output
```

### Source Code (repository root)

```text
tools/pentest/cors.py                         # CorsProbe StrEnum, check_cors_misconfiguration
                                              #   (thin @owasp delegator) + undecorated _cors_impl
tools/pentest/canary.py                       # reuse HOST (non-resolving RFC 2606 .invalid)
squad/penetration_tester/tools/probes/headers.py   # _CorsCheckArgs + cors_check_tool wrapper
squad/penetration_tester/__init__.py          # registry: _CorsCheckArgs mapping (already present)

tests/tools/pentest/test_cors.py              # new dedicated test module (observability + tiers + near-misses)
tests/tools/pentest/test_vuln_tools.py        # drop the superseded cors cases if any remain
```

**Structure Decision**: Single-project layout. The probe logic lives in `tools/pentest/cors.py`;
the agent-facing wrapper and its `args_schema` live in `squad/penetration_tester/tools/probes/headers.py`
(where the current cors wrapper already sits) with the registry mapping in the member `__init__.py`.
Tests move to a dedicated `tests/tools/pentest/test_cors.py` (the probe now warrants its own module).

## Complexity Tracking

> No constitution violations; section intentionally empty.
