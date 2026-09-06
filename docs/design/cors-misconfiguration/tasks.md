---

description: "Task list for the CORS misconfiguration probe rework"
---

# Tasks: CORS Misconfiguration Probe

**Input**: Design documents in `docs/design/cors-misconfiguration/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md
**Tests**: REQUIRED (TDD - tests written first and shown failing before implementation, per the cybersquad-tests doctrine).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelisable (different file, no dependency on an incomplete task)
- Increments are independently testable slices of the probe.

## Phase 1: Setup

- [x] T001 Confirm the old probe is gone and the suite is green on the branch (baseline before rework).

## Phase 2: Foundational (blocking prerequisites)

- [x] T002 Add the `CorsProbe` StrEnum (`reflected_origin`, `null_origin`) with per-member docstring in `tools/pentest/cors.py`, and the origin-payload map keyed off `tools.pentest.canary.HOST`.
- [x] T003 Add the undecorated `_cors_impl(endpoints, active)` skeleton + the `@owasp(A05_SECURITY_MISCONFIGURATION)` thin delegator `check_cors_misconfiguration(endpoints, probe_names=None)` in `tools/pentest/cors.py` (empty detection body for now).

**Checkpoint**: module imports; `tools/pentest/__init__.py` re-exports `check_cors_misconfiguration` + `CorsProbe`.

## Phase 3: US1 - tiered oracle on the reflected_origin variant (Priority: P1) MVP

**Goal**: reflected untrusted origin scored HIGH (with creds) / LOW (without); wildcard scored INFORMATIONAL; near-misses clean; one finding per endpoint.

**Independent test**: `pytest -m unit tests/tools/pentest/test_cors.py -q` covering the reflected_origin tiers + near-misses.

- [x] T004 [P] [US1] Write failing tests in `tests/tools/pentest/test_cors.py`: reflected_origin emits its exact `Origin` header + `allow_redirects=False` (assert on captured call args); HIGH when `ACAC: true`; LOW without creds; INFORMATIONAL on `ACAO: *`; no finding when no `ACAO` or a different origin is echoed; evidence carries Origin/ACAO/ACAC/status and the chain-vector note on LOW/INFORMATIONAL. (FR-001..FR-004)
- [x] T005 [US1] Implement the tier oracle + evidence in `_cors_impl` for the reflected_origin variant in `tools/pentest/cors.py`; make T004 pass.
- [x] T006 [US1] Implement per-endpoint dedup with highest-tier-wins in `_cors_impl` + a test that a credentialed reflection is reported HIGH even when a lower-tier signal is also present (assert the single finding's `severity_hint`). (FR-005)

**Checkpoint**: reflected_origin fully detects + scores; suite green.

## Phase 4: US2 - null_origin variant + agent-selectable filter (Priority: P2)

**Goal**: the `null` origin payload, and `probe_names` selecting a subset (`None` = all, `[]` = no-op).

- [x] T007 [P] [US2] Write failing tests: `null_origin` sends `Origin: null` and scores HIGH (creds) / LOW (no creds); `probe_names=[CorsProbe.null_origin]` runs only that variant; `probe_names=[]` fires no requests and returns `[]`.
- [x] T008 [US2] Wire the `probe_names` filter (frozenset, `None` = all) through `check_cors_misconfiguration` -> `_cors_impl` in `tools/pentest/cors.py`; make T007 pass.

**Checkpoint**: both variants + filter work; suite green.

## Phase 5: US3 - squad wrapper, args_schema, registry (Priority: P3)

**Goal**: agent-facing `cors_check_tool` with `endpoints` + `probe_names`, throttling + fault isolation, and registry consistency.

- [x] T009 [US3] Add `_CorsCheckArgs` (endpoints: `TargetEndpoints`; probe_names: `list[CorsProbe] | None`) + the `@pentest_tool("CORS Misconfiguration Check", check_fn=check_cors_misconfiguration, args_schema=_CorsCheckArgs)` wrapper `cors_check_tool` in `squad/penetration_tester/tools/probes/headers.py`, documenting each variant.
- [x] T010 [US3] Re-add the registry wiring: imports + `__all__` in `squad/penetration_tester/tools/probes/__init__.py` and `squad/penetration_tester/__init__.py`, the tool-list entry, and the `"CORS Misconfiguration Check": _CorsCheckArgs` schemas map entry.
- [x] T011 [US3] Implement `adaptive_sleep` throttling between requests and per-endpoint/variant fault isolation (log + skip, no abort) in `_cors_impl`; add tests that a network error on one endpoint does not abort the run and that the emitted request shape is correct. (FR-006, FR-007)
- [x] T012 [P] [US3] Re-add the args-schema case for `_CorsCheckArgs` in `tests/squad/penetration_tester/test_args_schema_cases.py` and a `cors_check_tool` wrapper test in `tests/squad/penetration_tester/test_tools.py` (invoke_tool path).

**Checkpoint**: closed-world args-schema contract test passes; agent can call the tool.

## Phase 6: Polish & cross-cutting

- [x] T013 [P] Author `docs/architecture/pentest/cors.md` (the architecture note; keep the PR body small).
- [x] T014 Run the full parity stack (`ruff`, `ruff format --check`, `mypy`, `pylint`, `pytest -m unit`) and the quickstart validation; confirm no socket warnings and coverage floor holds.

## Dependencies

- Phase 2 blocks all user stories.
- US1 -> US2 -> US3 in order (US2 extends the oracle to a second variant; US3 exposes it to the agent).
- Polish after US3.

## Notes

- Tests first in each story; show them failing before implementing.
- Detection logic lives in the undecorated `_cors_impl` (mutation-observable); `check_cors_misconfiguration` stays a thin `@owasp` delegator.
- ASCII-only, minimal diff; commit per logical group.
