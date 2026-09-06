# Tasks: CORS Misconfiguration Probe

Implementation of `docs/design/cors-misconfiguration/spec.md`. Tests are written
alongside the code and observe what the probe does (the Origin it sends, the
severity it grades), not stub returns.

- [x] T001 Delete the current CORS implementation (probe body, wrapper, tests) so the feature is built from the spec, not the old code.
- [x] T002 `tools/pentest/cors.py`: `CorsProbe` (attacker-origin, null-origin) + `check_cors_misconfiguration(endpoints, probe_names=None)` over an undecorated `_cors_impl`. (FR-001, FR-006)
- [x] T003 Grade each response: reflected untrusted origin + credentials -> HIGH; reflected without credentials -> LOW; `Access-Control-Allow-Origin: *` -> INFORMATIONAL; otherwise no finding. (FR-002..FR-005)
- [x] T004 One finding per endpoint, keeping the most severe result across probes. (FR-007)
- [x] T005 Evidence carries the origin sent and the CORS headers observed. (FR-008)
- [x] T006 Send unauthenticated GETs with redirects disabled; `adaptive_sleep` between requests; a network error on one endpoint skips it and the run continues. (FR-009, FR-010)
- [x] T007 Squad wrapper `cors_check_tool` (endpoints + probe_names) via `_CorsCheckArgs`; `probe_names` omitted sends all variants.
- [x] T008 `tests/tools/pentest/test_cors.py`: every severity, the near-misses, request shape, null-origin, highest-severity-wins, all-variants default, fault isolation, evidence.
- [x] T009 Full parity green (ruff, format, mypy, pylint, `pytest -m unit`); no socket warnings.
