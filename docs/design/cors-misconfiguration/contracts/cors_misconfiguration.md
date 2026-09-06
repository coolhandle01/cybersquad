# Tool Contract: cors_misconfiguration

Agent-facing CrewAI tool wrapping `check_cors_misconfiguration`.

## Inputs (`_CorsCheckArgs`)

| Field | Type | Meaning (agent-facing) |
|---|---|---|
| `endpoints` | `TargetEndpoints` (scope-guarded `list[Endpoint]`) | The discovered URLs to probe. |
| `probe_names` | `list[CorsProbe] \| None` | Which origin probes to send; `None`/omitted = all, `[]` = no-op. |

## Behaviour

- For each endpoint, for each active variant: issue `GET <url>` with the variant's
  `Origin` header, redirects disabled; read `ACAO` + `ACAC` (case-insensitive).
- Emit at most one finding per endpoint URL, highest tier winning (see data-model).
- Throttle between requests via `adaptive_sleep`; a network error on one
  endpoint/variant is logged and skipped without aborting the run.

## Returns

`list[RawFinding]` with `vuln_class == "CORS"`; `severity_hint` tiered per the oracle.

## Refusal / empty outcomes

- No `ACAO`, or an `ACAO` echoing an origin other than the probed one (and not `*`)
  -> no finding for that endpoint.
- `probe_names == []` -> no requests, empty list.
