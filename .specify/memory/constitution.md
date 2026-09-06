# cybersquad Constitution

## Core Principles

### I. Requirements in EARS (NON-NEGOTIABLE)

Every normative requirement in a specification SHALL be written in EARS (Easy
Approach to Requirements Syntax), with `SHALL` as the single requirement modal,
in one of these forms:

- **Ubiquitous**: The <system> SHALL <response>.
- **Event-driven**: WHEN <trigger>, the <system> SHALL <response>.
- **State-driven**: WHILE <state>, the <system> SHALL <response>.
- **Unwanted behaviour**: IF <condition>, THEN the <system> SHALL <response>.
- **Optional feature**: WHERE <feature is included>, the <system> SHALL <response>.

Each requirement SHALL be atomic and independently testable. The EARS keywords
(`WHEN` / `WHILE` / `IF` / `THEN` / `WHERE`) and the modal `SHALL` are written in
upper case. `MUST` and `SHOULD` SHALL NOT be used as the requirement modal;
`SHALL` is the only normative verb in a spec.

## Governance

This constitution is intentionally minimal: it currently asserts only the
requirements-notation principle. Other project rules (test-first, the framework
seam, ASCII / minimal-diff, the CI parity stack) are governed by `CONTRIBUTING.md`
and the `cybersquad-*` skills until they are ratified here. Where this
constitution and another document conflict on requirement notation, this
constitution wins.

**Version**: 0.1.0 | **Ratified**: 2026-09-06 | **Last amended**: 2026-09-06
