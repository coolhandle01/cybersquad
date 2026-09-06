# Implementation Plan: CORS Misconfiguration Probe

**Branch**: `docs/cors-misconfiguration-spec` | **Date**: 2026-09-06 | **Spec**: `docs/design/cors-misconfiguration/spec.md`

**Input**: Feature specification from `docs/design/cors-misconfiguration/spec.md`

## Summary

A pentest probe the penetration-tester agent runs against target endpoints. For each
endpoint it sends untrusted cross-origin `Origin` headers, reads the CORS response, and
reports one finding graded by exploitability. Detection logic lives in a plain function
so it stays mutation-observable; the agent-facing tool wraps it with a typed args schema.

## Technical Context

**Language/Version**: Python 3.12
**Primary Dependencies**: `requests` (via `tools.http`), `pydantic` (args schema + models), CrewAI `@tool` (via `@pentest_tool`)
**Storage**: N/A - stateless probe returning `list[RawFinding]`
**Testing**: `pytest -m unit`, `requests.get` patched, sockets blocked (`pytest-socket`)
**Project Type**: single project (the cybersquad pipeline)
**Constraints**: ASCII-only, minimal diff, 96% coverage floor + per-diff ratchet, no real egress in the unit tier

## Constitution Check

*GATE: pass before Phase 0, re-check after Phase 1.*

- **Requirements in EARS (NON-NEGOTIABLE)**: PASS. `spec.md` states FR-001..FR-010 in EARS with `SHALL` as the only modal.

No violations.

## Project Structure

### Documentation (this feature)

```text
docs/design/cors-misconfiguration/
  spec.md, plan.md, research.md, data-model.md, contracts/, quickstart.md, tasks.md
```

### Source Code

```text
tools/pentest/cors.py                              # CorsProbe + check_cors_misconfiguration over _cors_impl
squad/penetration_tester/tools/probes/headers.py   # _CorsCheckArgs + cors_check_tool wrapper
tests/tools/pentest/test_cors.py                   # probe behaviour
tests/squad/penetration_tester/                    # wrapper + args-schema contract
```

**Structure Decision**: single-project. Probe logic in `tools/pentest/cors.py`; agent-facing
wrapper + schema in `squad/penetration_tester/tools/probes/headers.py`, registered in the
member `__init__.py`. The implementation replaces the endpoint's existing CORS check.

## Design Approach

- Two untrusted origins (`attacker-origin`, a non-resolving `.invalid` host; `null`), sent per endpoint. The caller may select a subset.
- Grade each response: reflected untrusted origin + credentials -> highest; reflected without credentials -> lower; `Access-Control-Allow-Origin: *` -> lowest; otherwise no finding.
- One finding per endpoint, most severe kept. Evidence carries the origin sent and the CORS headers seen.
- Detection loop in an undecorated helper (mutation-observable); the classification decorator wraps a thin delegator.
- Requests are unauthenticated GETs with redirects disabled, throttled between calls; a network error on one endpoint is skipped and the run continues.
