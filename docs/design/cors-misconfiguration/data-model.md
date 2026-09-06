# Data Model: CORS Misconfiguration Probe

## Origin probe (CorsProbe)

| Probe | Origin sent | Catches |
|---|---|---|
| attacker-origin | a non-resolving `.invalid` host | servers reflecting any request Origin |
| null-origin | `null` | servers allow-listing the `null` origin |

The caller selects which probes to send; omitting the selection sends all.

## Severity grading

Read per response for the origin sent: `ACAO` = `Access-Control-Allow-Origin`,
`ACAC` = `Access-Control-Allow-Credentials` (keyword compared case-insensitively).

| Response | Severity |
|---|---|
| `ACAO` == origin sent AND `ACAC` == `true` | highest |
| `ACAO` == origin sent AND `ACAC` not `true` | lower |
| `ACAO` == `*` | lowest |
| no `ACAO`, or `ACAO` a different (validated) origin | no finding |

One finding per endpoint; when several probes match, the most severe is kept.

## Finding

Each finding records: the target endpoint, the vulnerability class, the severity, and
evidence naming the origin sent plus the `ACAO` / `ACAC` headers observed.
