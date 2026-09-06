# Tasks: CORS Misconfiguration Probe

Generated from `spec.md` / `plan.md`. Tests are written alongside the code and observe
what the probe does (the Origin it sends, the severity it grades), not stub returns.
The implementation PR checks these off as it completes them.

## Phase 1: Foundational

- [ ] T001 Delete the endpoint's existing CORS implementation (probe body, wrapper, tests) so the feature is built from this spec, not the old code.
- [ ] T002 `tools/pentest/cors.py`: `CorsProbe` (attacker-origin, null-origin) + `check_cors_misconfiguration(endpoints, probe_names=None)` over an undecorated detection helper; attacker origin built from a non-resolving `.invalid` host. (FR-001, FR-006)

## Phase 2: Detection (P1/P2)

- [ ] T003 Grade each response: reflected untrusted origin + credentials -> highest; reflected without credentials -> lower; `Access-Control-Allow-Origin: *` -> lowest; otherwise no finding. (FR-002..FR-005)
- [ ] T004 One finding per endpoint, keeping the most severe result across probes. (FR-007)
- [ ] T005 Evidence carries the origin sent and the CORS headers observed. (FR-008)
- [ ] T006 Unauthenticated GET with redirects disabled; throttle between requests; a network error on one endpoint is skipped and the run continues. (FR-009, FR-010)

## Phase 3: Agent surface (P3)

- [ ] T007 Squad wrapper `cors_check_tool` (endpoints + probe_names) with an explicit args schema; omitting probe_names sends all variants; register it.

## Phase 4: Tests & verification

- [ ] T008 `tests/tools/pentest/test_cors.py`: every severity, the near-misses, request shape, null-origin, most-severe-wins, all-variants default, fault isolation, evidence.
- [ ] T009 Update the wrapper + args-schema contract tests for the new input shape.
- [ ] T010 Full parity green (ruff, format, mypy, pylint, `pytest -m unit`); no socket warnings.
