# Data Model: CORS Misconfiguration Probe

## CorsProbe (StrEnum, `tools/pentest/cors.py`)

| Member | Value | Origin header sent | Defeats |
|---|---|---|---|
| `reflected_origin` | `reflected-origin` | `https://<canary HOST>` | servers reflecting any request Origin into ACAO |
| `null_origin` | `null-origin` | `null` | servers allow-listing the `null` origin |

`None` selects all members; `[]` is a no-op. No synthetic `all` member.

## Detection tiers (severity_hint)

Inputs read per request: `ACAO` = `Access-Control-Allow-Origin`, `ACAC` =
`Access-Control-Allow-Credentials` (case-insensitive), for the probed origin `O`.

| Condition | Tier (`Severity`) |
|---|---|
| `ACAO == O` and `ACAC == "true"` | `HIGH` |
| `ACAO == O` and `ACAC` absent / not `true` | `LOW` |
| `ACAO == "*"` | `INFORMATIONAL` |
| no `ACAO`, or `ACAO` != `O` and != `*` | (no finding) |

One finding per endpoint URL; when multiple variants/tiers fire, the highest tier
wins (`HIGH` > `LOW` > `INFORMATIONAL`).

## RawFinding (existing model, `models`)

| Field | Value |
|---|---|
| `title` | `CORS Misconfiguration - <url>` |
| `vuln_class` | `"CORS"` (stable) |
| `target` | `ep.url` |
| `evidence` | probed `Origin`, `ACAO`, `ACAC`, HTTP status; plus a one-line chain-vector note for LOW/INFORMATIONAL |
| `tool` | probe tool name |
| `severity_hint` | tier above (`Severity.HIGH` / `LOW` / `INFORMATIONAL`) |

`Severity` members used: `HIGH`, `LOW`, `INFORMATIONAL` (from `models`).
