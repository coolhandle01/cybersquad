# Pentest Probe Specification: CORS Misconfiguration

**Feature Branch**: `001-cors-misconfiguration`
**Created**: 2026-09-06
**Status**: Draft
**Input**: User description: "Detect exploitable CORS misconfiguration: reflected untrusted Origin or null origin with credentials"

## Purpose *(mandatory)*

Detect endpoints whose CORS policy lets an attacker-controlled web origin read cross-origin responses, so the agent surfaces both the directly exploitable cases (credentialed reads) and the weaker signals that can chain into a larger exploit.

## Vulnerability & Classification *(mandatory)*

- **Class**: CORS misconfiguration (permissive cross-origin resource sharing)   **CWE**: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
- **OWASP**: `OWASPCategory.A05_SECURITY_MISCONFIGURATION`
- **Reference (RTFM)**: OWASP WSTG - Testing Cross Origin Resource Sharing (WSTG-CLNT-07). The browser rule that `Access-Control-Allow-Origin: *` cannot carry credentials is the crux of the severity tiers below.

## Tool Contract *(mandatory)*

**Invocation name**: `cors_misconfiguration` (wraps `check_cors_misconfiguration`)

**Inputs** (`args_schema`)

| Field | Type | Meaning (agent-facing) |
|---|---|---|
| `endpoints` | `list[Endpoint]` | The discovered URLs to probe. |
| `probe_names` | `list[CorsProbe] \| None` | Which origin probes to send; `None` = all, `[]` = no-op. |

**Returns**: `list[RawFinding]` with `vuln_class == "CORS"`. `severity_hint` is the *standalone* severity and is tiered per the oracle below (`HIGH` / `LOW` / `INFORMATIONAL`); whether a lower-tier finding composes into a real exploit is the Vulnerability Researcher's call at triage - the probe surfaces the signal, it does not suppress it on standalone severity.

**Evidence** each finding carries: the probed `Origin` sent, the response `Access-Control-Allow-Origin`, the response `Access-Control-Allow-Credentials`, the HTTP status, and - for a `LOW`/`INFORMATIONAL` finding - a one-line note of the chain vector (any origin can read the uncredentialed response; e.g. cross-origin disclosure of an anti-CSRF token or other response data that enables a follow-on attack).

## Detection Oracle *(mandatory)*

For an untrusted probed origin `O` (a non-resolving canary origin, or the literal `null`), read `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC, compared case-insensitively). Report tier (severity is a hint, not a gate - each tier is a finding):

- **HIGH** - `ACAO == O` **and** `ACAC == "true"`: a browser exposes credentialed (authenticated) responses to `O`'s JavaScript. Direct cross-origin theft of authenticated data.
- **LOW** - `ACAO == O` and `ACAC` absent / not `true`: any origin can read the *uncredentialed* response. Not authenticated-data theft on its own, but a chain enabler (reading a token, or data that feeds a later step).
- **INFORMATIONAL** - `ACAO == "*"`: browsers refuse to send credentials to a wildcard, so no credentialed read; any origin can still read uncredentialed responses (same chain caveat). Ubiquitous on public APIs, hence the lowest tier.

- **NOT a finding** (each of these SHALL stay clean):
  - No `Access-Control-Allow-Origin` header (no CORS granted).
  - `ACAO` echoing an origin *other* than `O` (a same-origin or allow-listed origin) - the server validated the origin.

- **Request shape**: `GET ep.url` with header `Origin: <O>`, redirects disabled; read only the `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` response headers (case-insensitive lookup).

## Payload / Variant Catalogue *(if multi-variant)*

| Variant | Payload (`Origin` header) | Defeats |
|---|---|---|
| `reflected_origin` | `https://<canary-host>` (a non-resolving RFC 2606 `.invalid` origin) | Servers that reflect any request Origin into `Access-Control-Allow-Origin`. |
| `null_origin` | `null` | Servers that allow-list the `null` origin (reachable by an attacker from a sandboxed iframe / `data:` document). |

(`ACAO: *` is not a payload - it is a wildcard *response* that either variant can elicit; it is scored at the `INFORMATIONAL` tier above.)

## Requirements *(mandatory)*

- **FR-001**: WHEN `ACAO == O` and `ACAC == "true"` (case-insensitive), the probe SHALL emit a `HIGH` finding for that endpoint.
- **FR-002**: WHEN `ACAO == O` and `ACAC` is absent or not `true`, the probe SHALL emit a `LOW` finding whose evidence names the chain vector.
- **FR-003**: WHEN `ACAO == "*"`, the probe SHALL emit an `INFORMATIONAL` finding whose evidence names the chain vector.
- **FR-004**: IF there is no `Access-Control-Allow-Origin`, or it echoes an origin other than `O` and is not `*`, THEN the probe SHALL NOT emit a finding.
- **FR-005**: The probe SHALL emit at most one finding per endpoint URL; WHEN more than one variant/tier would fire, the **highest** severity tier wins.
- **FR-006**: The probe SHALL send the `Origin` header exactly as the variant specifies and SHALL issue the request with redirects disabled.
- **FR-007**: The probe SHALL throttle between requests via `adaptive_sleep`, and IF a network error occurs on one endpoint/variant, THEN it SHALL be logged and skipped without aborting the run.

## Observable Behaviour (test oracles) *(mandatory)*

- The emitted request for each variant carries the exact `Origin` header for that variant and `allow_redirects=False` (assert via captured call args).
- Reflected origin **with** credentials -> one `HIGH` finding; reflected origin **without** credentials -> one `LOW` finding; `ACAO: *` -> one `INFORMATIONAL` finding. The fake decides from the request's `Origin`, it does not blindly echo it.
- No `ACAO`, and a *different* reflected origin, each -> no finding.
- `null_origin` with credentials -> `HIGH`; without -> `LOW`.
- Precedence: an endpoint eliciting a credentialed reflection is reported `HIGH` even if a lower-tier signal is also present (assert the single emitted finding's `severity_hint`).
- Evidence carries the probed `Origin`, `ACAO`, `ACAC`, and status; `LOW`/`INFORMATIONAL` findings carry the chain-vector note.

## Out of Scope *(mandatory)*

- Origin-validation *bypasses* that require synthesising an origin from the target's own host (trusted-subdomain, prefix/suffix matching, e.g. `https://<target>.attacker.tld`) - a natural follow-on variant, not this probe.
- Preflight-only (`OPTIONS`) policies and non-`GET` methods; the probe issues a simple `GET`.
- Deciding whether a `LOW` / `INFORMATIONAL` finding *actually* chains in this application, and confirming the endpoint returns sensitive or authenticated data - both are triage / Vulnerability Researcher concerns. The probe surfaces the signal; triage weighs the chain.

## Assumptions

- Endpoints are in-scope discovered URLs; the probe sends unauthenticated `GET` requests.
- The canary origin host is non-resolving (RFC 2606 `.invalid`), so an over-permissive server cannot cause traffic to a real third party.

---

*Inherited, not restated here: the `@pentest_tool` / `@owasp` decorator stack, the framework seam (detection loop in an undecorated `_impl`), the two-docstring split (lean agent-facing wrapper vs contributor-facing `check_cors_misconfiguration`), a typed `args_schema` and `list[RawFinding]` return, a non-resolving canary, adaptive throttling, ASCII / minimal-diff / the CI parity stack, and the test-observability / mutation doctrine. See `CONTRIBUTING.md` and the `cybersquad-tool` / `cybersquad-pentest-tool` / `cybersquad-tests` skills.*
