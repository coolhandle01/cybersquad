# Pentest Probe Specification: CORS Misconfiguration

**Feature Branch**: `001-cors-misconfiguration`
**Created**: 2026-09-06
**Status**: Draft
**Input**: User description: "Detect exploitable CORS misconfiguration: reflected untrusted Origin or null origin with credentials"

## Purpose *(mandatory)*

Detect endpoints whose CORS policy lets an attacker-controlled web origin read authenticated (credentialed) cross-origin responses, so the agent can flag credential-exposing origins.

## Vulnerability & Classification *(mandatory)*

- **Class**: CORS misconfiguration (permissive cross-origin resource sharing)   **CWE**: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
- **OWASP**: `OWASPCategory.A05_SECURITY_MISCONFIGURATION`
- **Reference (RTFM)**: OWASP WSTG - Testing Cross Origin Resource Sharing (WSTG-CLNT-07). Read for the credentialed-reflection rule; the browser rule that `Access-Control-Allow-Origin: *` cannot carry credentials is the crux.

## Tool Contract *(mandatory)*

**Invocation name**: `cors_misconfiguration` (wraps `check_cors_misconfiguration`)

**Inputs** (`args_schema`)

| Field | Type | Meaning (agent-facing) |
|---|---|---|
| `endpoints` | `list[Endpoint]` | The discovered URLs to probe. |
| `probe_names` | `list[CorsProbe] \| None` | Which origin probes to send; `None` = all, `[]` = no-op. |

**Returns**: `list[RawFinding]` with `vuln_class == "CORS"`, `severity_hint == Severity.HIGH`

**Evidence** each finding carries: the probed `Origin` sent, the response `Access-Control-Allow-Origin`, the response `Access-Control-Allow-Credentials`, and the HTTP status.

## Detection Oracle *(mandatory)*

- **A finding is raised IFF**, for an untrusted probed origin `O` (a non-resolving canary origin, or the literal `null`), the response carries `Access-Control-Allow-Origin` exactly equal to `O` **and** `Access-Control-Allow-Credentials: true` (value compared case-insensitively). This is the combination a browser honours to expose a credentialed response to `O`'s JavaScript.
- **NOT a finding** (each MUST stay clean):
  - No `Access-Control-Allow-Origin` header (no CORS granted).
  - `Access-Control-Allow-Origin: *` - browsers refuse to send credentials to a wildcard, so this is not a credentialed exploit (sensitivity-dependent info only; see Out of Scope).
  - `Access-Control-Allow-Origin` echoing a *different* origin than `O` (a same-origin or allow-listed origin) - the server validated the origin.
  - `Access-Control-Allow-Origin: O` but `Access-Control-Allow-Credentials` absent or not `true` - not a credentialed exploit (see Out of Scope).
- **Request shape**: `GET ep.url` with header `Origin: <O>`, redirects disabled; read only the `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` response headers (case-insensitive lookup).

## Payload / Variant Catalogue *(if multi-variant)*

| Variant | Payload (`Origin` header) | Defeats |
|---|---|---|
| `reflected_origin` | `https://<canary-host>` (a non-resolving RFC 2606 `.invalid` origin) | Servers that reflect any request Origin into `Access-Control-Allow-Origin`. |
| `null_origin` | `null` | Servers that allow-list the `null` origin (reachable by an attacker from a sandboxed iframe / `data:` document). |

## Requirements *(mandatory)*

- **FR-001**: WHEN the response for a probed origin `O` has `Access-Control-Allow-Origin == O` and `Access-Control-Allow-Credentials == "true"` (case-insensitive), the probe MUST emit one finding for that endpoint.
- **FR-002**: IF the response has no `Access-Control-Allow-Origin`, or `Access-Control-Allow-Origin: *`, or an origin other than `O`, or `Access-Control-Allow-Credentials` absent/not `true`, THEN the probe MUST NOT emit a finding.
- **FR-003**: The probe MUST send the `Origin` header exactly as the variant specifies and MUST issue the request with redirects disabled.
- **FR-004**: The probe MUST emit at most one finding per endpoint URL (stop probing an endpoint after its first firing variant).
- **FR-005**: The probe MUST throttle between requests via `adaptive_sleep`, and a network error on one endpoint/variant MUST be logged and skipped without aborting the run.

## Observable Behaviour (test oracles) *(mandatory)*

- The emitted request for each variant carries the exact `Origin` header for that variant and `allow_redirects=False` (assert via captured call args).
- A fixture that reflects the probed origin with `Access-Control-Allow-Credentials: true` yields exactly one finding; the evidence contains the probed `Origin`, the reflected `Access-Control-Allow-Origin`, and `Access-Control-Allow-Credentials`.
- Each NOT-a-finding case in the oracle (no ACAO; `*`; different origin; reflected-without-credentials) has a test that stays clean - the fake decides from the request's `Origin`, it does not blindly echo it.
- `null_origin`: a fixture allow-listing `null` with credentials yields a finding; the same without credentials does not.

## Out of Scope *(mandatory)*

- `Access-Control-Allow-Origin: *` without credentials: intended for public APIs; flagging it needs a judgement about response sensitivity the probe cannot make.
- Reflected origin *without* `Access-Control-Allow-Credentials: true`: exposes only unauthenticated responses; low value, sensitivity-dependent.
- Origin-validation *bypasses* that require synthesising an origin from the target's own host (trusted-subdomain, prefix/suffix matching, e.g. `https://<target>.attacker.tld`) - a natural follow-on variant, not this probe.
- Preflight-only (`OPTIONS`) policies and non-`GET` methods; the probe issues a simple `GET`.
- Confirming the endpoint actually returns sensitive or authenticated data (a triage / Vulnerability Researcher concern).

## Assumptions

- Endpoints are in-scope discovered URLs; the probe sends unauthenticated `GET` requests.
- The canary origin host is non-resolving (RFC 2606 `.invalid`), so an over-permissive server cannot cause traffic to a real third party.

---

*Inherited, not restated here: the `@pentest_tool` / `@owasp` decorator stack, the framework seam (detection loop in an undecorated `_impl`), the two-docstring split (lean agent-facing wrapper vs contributor-facing `check_cors_misconfiguration`), a typed `args_schema` and `list[RawFinding]` return, a non-resolving canary, adaptive throttling, ASCII / minimal-diff / the CI parity stack, and the test-observability / mutation doctrine. See `CONTRIBUTING.md` and the `cybersquad-tool` / `cybersquad-pentest-tool` / `cybersquad-tests` skills.*
