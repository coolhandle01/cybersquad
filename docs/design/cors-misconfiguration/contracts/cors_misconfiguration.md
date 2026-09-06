# Contract: CORS Misconfiguration Check (agent tool)

The penetration-tester agent invokes this tool.

## Inputs

| Field | Meaning |
|---|---|
| endpoints | the target endpoints to probe (scope-checked) |
| probe_names | which origin probes to send; omit to send all |

## Behaviour

- For each endpoint, for each selected origin probe: send an unauthenticated GET with
  the untrusted `Origin`, redirects disabled; read `Access-Control-Allow-Origin` and
  `Access-Control-Allow-Credentials`.
- Grade per the data model; report at most one finding per endpoint (most severe).
- Throttle between requests; a network error on one endpoint is skipped, the run continues.

## Output

A list of findings (vulnerability class `CORS`), each carrying the severity, the origin
sent, and the CORS headers observed.
