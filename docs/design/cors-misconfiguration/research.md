# Research: CORS Misconfiguration Probe

Grounded in the OWASP Web Security Testing Guide, "Testing Cross Origin Resource
Sharing" (WSTG-CLNT-07).

## Decision: two untrusted origin probes - attacker origin and `null`

- **Decision**: send an attacker-controlled origin and, separately, the literal `null`
  origin; the caller may run all or a subset.
- **Rationale**: OWASP calls out both a plain untrusted origin (to catch servers that
  reflect any request `Origin`) and the `null` origin (reachable from a sandboxed
  iframe / `data:` document, and sometimes allow-listed). They exercise different
  server behaviours, so both are worth sending.

## Decision: grade findings by exploitability

- **Decision**: reflected untrusted origin + credentials -> highest; reflected without
  credentials -> lower; `Access-Control-Allow-Origin: *` -> lowest; a validated origin or
  no CORS header -> no finding.
- **Rationale**: OWASP treats reflected origin with credentials as the directly
  exploitable case (an attacker page reads authenticated responses), a reflected origin
  or wildcard without credentials as a weaker exposure of unauthenticated data, and a
  validated allow-list as safe. Surfacing the weaker cases at a lower severity (rather
  than dropping them) lets the vulnerability researcher decide whether they chain.

## Decision: non-resolving attacker origin

- **Decision**: build the attacker origin from a host that does not resolve (RFC 2606
  `.invalid`).
- **Rationale**: a target that reflects the origin cannot cause a browser (or the probe)
  to reach a real third party.

## Decision: detection logic in a plain function

- **Decision**: keep the per-endpoint detection loop in an undecorated helper; the
  classification decorator wraps a thin delegator.
- **Rationale**: the mutation-audit tool skips decorated function bodies, so detection
  logic inside the decorated function would be invisible to it (cybersquad-tests).

## Out of scope (from the spec)

- Origin-validation bypasses built from the target's own domain (trusted-subdomain,
  prefix/suffix regex).
- Preflight-only (`OPTIONS`) policies and non-GET methods.
