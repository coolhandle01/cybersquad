# Research: CORS Misconfiguration Probe

## Decision: browser-correct oracle scored in three chainability tiers

- **Decision**: Score a reflected untrusted origin by whether the response also
  carries `Access-Control-Allow-Credentials: true` - HIGH with credentials, LOW
  without - and score `Access-Control-Allow-Origin: *` as INFORMATIONAL.
- **Rationale**: The Fetch standard forbids a browser from exposing a credentialed
  response when `ACAO` is the wildcard `*`; credentials are only sent when `ACAO`
  echoes the exact requesting origin and `ACAC` is `true`. So wildcard + credentials
  is *not* a credentialed-read primitive, and scoring it HIGH (as the prior
  implementation did) is a false severity. Reflected-origin + credentials is the
  real credentialed-read; reflected-origin without credentials, and wildcard, still
  expose uncredentialed cross-origin reads that can chain (token/JSON disclosure),
  so they are findings at lower tiers, not silence.
- **Reference (RTFM)**: OWASP WSTG - Testing Cross Origin Resource Sharing
  (WSTG-CLNT-07).
- **Alternatives considered**: The prior single-tier `HIGH if creds else MEDIUM`
  on `acao in (evil, "*")` - rejected: it mis-scores wildcard, uses one hard-coded
  origin, and emits MEDIUM where the standalone risk is lower but still real.

## Decision: two named Origin variants (reflected_origin, null_origin)

- **Decision**: `CorsProbe` StrEnum with `reflected_origin` (Origin = a non-resolving
  canary origin) and `null_origin` (Origin = `null`). `None` = all; `[]` = no-op.
- **Rationale**: They defeat distinct validator classes - naive reflection of any
  request Origin vs. an allow-list that trusts the `null` origin (reachable from a
  sandboxed iframe / `data:` document). The multi-variant pattern
  (cybersquad-pentest-tool) lets the agent pick a subset.
- **Alternatives considered**: A single fixed Origin (prior behaviour) - rejected: it
  cannot detect `null`-origin allow-listing, a distinct real misconfiguration.

## Decision: non-resolving canary origin

- **Decision**: Build the reflected-origin payload from `tools.pentest.canary.HOST`
  (`cybersquad-canary.invalid`, RFC 2606 `.invalid`).
- **Rationale**: An over-permissive server that echoes our Origin cannot cause the
  browser (or us) to reach a real third party; the host never resolves.
- **Alternatives considered**: A hard-coded `evil.example.com` (prior) - rejected:
  `example.com` resolves and is not ours.

## Decision: undecorated `_impl` framework seam

- **Decision**: Put the per-endpoint detection loop in an undecorated
  `_cors_impl(...)`; `check_cors_misconfiguration` is the thin `@owasp`-decorated
  delegator.
- **Rationale**: `mutmut` skips decorated function bodies, so detection logic inside
  the `@owasp` body would be mutation-invisible. The seam keeps the oracle
  mutation-observable (cybersquad-tests doctrine).
- **Alternatives considered**: Logic in the decorated body - rejected: paper-tiger
  risk (mutants survive unseen).

## Decision: wrapper takes endpoints + probe_names (interface change)

- **Decision**: The `cors_check_tool` wrapper accepts `endpoints` (scope-guarded
  `TargetEndpoints`) and `probe_names: list[CorsProbe] | None`, per the spec's Tool
  Contract, replacing the prior `recon_path`-only signature.
- **Rationale**: The multi-variant pattern requires the variant filter on the
  agent-facing surface; the spec's Inputs table defines exactly these two fields.
  Matches sibling probes (ssrf, hpp) that let the agent target endpoints + variants.
- **Alternatives considered**: Keep `recon_path` and hide variants - rejected:
  the agent could not select a subset, contradicting the spec and the pattern.
