# Proposal: Dockerised Tool Infrastructure + Observability Stack

## Problem

The scan tools (subfinder, httpx, nmap, nuclei, sqlmap) are currently assumed
to be on `PATH`. This has several failure modes:

- **Version drift** — different machines run different tool versions, producing
  inconsistent results and CI failures
- **Blast radius** — a misconfigured scan tool running on the host has access
  to the operator's entire network namespace
- **No resource limits** — a runaway nuclei or sqlmap job can saturate the
  host's CPU/network indefinitely
- **No audit trail** — tool invocations are not captured anywhere beyond
  application logs
- **Observability gap** — token cost and HTTP metrics are tracked in
  `tools/metrics.py`, but scan volume, tool runtimes, and per-programme cost
  are invisible

---

## Proposed architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  docker-compose.yml                                                      │
│                                                                          │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────────────┐ │
│  │  bounty-squad │   │  scan-runner │   │  observability               │ │
│  │  (Python app) │──▶│  (tools only)│   │  ┌──────────┐  ┌──────────┐ │ │
│  │               │   │              │   │  │Prometheus│  │ Langfuse │ │ │
│  │  Port: none   │   │  subfinder   │   │  └────┬─────┘  │ Port:3000│ │ │
│  │  Net: internal│   │  httpx       │   │       │         └────┬─────┘ │ │
│  └──────────────┘   │  nmap        │   │  ┌────▼─────┐        │       │ │
│                      │  nuclei      │   │  │ Grafana  │   ┌────▼─────┐ │ │
│                      │  sqlmap      │   │  │ Port:3001│   │Postgres  │ │ │
│                      │              │   │  └──────────┘   └──────────┘ │ │
│                      │  Net: scan   │   └──────────────────────────────┘ │
│                      └──────────────┘                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

### Networks

| Network | Purpose |
|---|---|
| `internal` | App ↔ scan-runner communication only. No internet access. |
| `scan` | scan-runner → target hosts. Egress only, no inbound. |
| `observability` | App + scan-runner → Prometheus push gateway. Isolated. |

The application container has **no direct internet access** — all outbound
traffic goes through the scan-runner. This means a prompt-injection attack that
tricks an agent into making an arbitrary HTTP call is blocked at the network
layer.

---

## Services

### `bounty-squad` (application)

- Base image: `python:3.12-slim`
- Mounts: `./reports` (write), `./prompts` (read-only)
- Env: all existing `.env` vars, plus `SCAN_RUNNER_URL=http://scan-runner:8080`
- Resource limits: 2 CPU, 4 GB RAM
- No external network access

### `scan-runner` (tool executor)

A thin FastAPI service that wraps each scan tool as an HTTP endpoint. The Python
agent code calls the scan-runner API instead of shelling out directly.

```
POST /scan/subfinder   {"domain": "example.com", ...}
POST /scan/httpx       {"targets": [...], ...}
POST /scan/nmap        {"hosts": [...], "ports": "80,443", ...}
POST /scan/nuclei      {"targets": [...], "templates": [...], ...}
POST /scan/sqlmap      {"url": "...", "params": [...], ...}
```

Each endpoint:
1. Validates the request against the scope guard (same `filter_in_scope` logic,
   but enforced server-side — belt and braces)
2. Runs the tool with pre-pinned binary versions
3. Streams stdout/stderr to structured logs
4. Returns parsed JSON output
5. Pushes a Prometheus metric on completion (tool, duration, finding_count)

Tool versions are pinned in the scan-runner `Dockerfile` via checksummed
downloads, not `apt install`. This guarantees reproducibility.

### `prometheus` + `grafana`

Standard `prom/prometheus` and `grafana/grafana` images, version-pinned.
Grafana on port 3001 (Langfuse takes 3000). Datasource and dashboards
provisioned via config files — no manual setup.

| Dashboard | Key panels |
|---|---|
| **Pipeline runs** | Run count, success/fail rate, median duration, token cost per run |
| **Scan activity** | Tool call rate, per-tool latency histogram, finding count by severity |
| **Programme ROI** | Estimated bounty / actual cost ratio per programme |
| **Rate limiting** | Requests/sec vs configured `SCAN_DELAY`, 429 count |

### `langfuse` + `postgres` — LLM observability

[Langfuse](https://langfuse.com) is self-hosted, open-source, and provides
per-run traces of every LLM call: prompt sent, tool calls made, response
received, token counts, latency. This is the layer Prometheus can't give you —
*why* the agent made a decision, not just *that* it did.

**Service setup:**

```yaml
langfuse:
  image: langfuse/langfuse:2
  ports: ["3000:3000"]
  environment:
    DATABASE_URL: postgresql://langfuse:langfuse@postgres:5432/langfuse
    NEXTAUTH_SECRET: changeme
    LANGFUSE_SECRET_KEY: changeme
    LANGFUSE_PUBLIC_KEY: changeme
  depends_on: [postgres]

postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_USER: langfuse
    POSTGRES_PASSWORD: langfuse
    POSTGRES_DB: langfuse
  volumes: ["postgres_data:/var/lib/postgresql/data"]
```

**Python integration** — add `langfuse` to dependencies and configure the
LangChain callback (zero application code changes required):

```python
# crew.py — one addition to build_crew()
from langfuse.callback import CallbackHandler

langfuse_handler = CallbackHandler()   # reads LANGFUSE_* env vars
return Crew(..., callbacks=[langfuse_handler])
```

Each pipeline run then appears in the Langfuse UI as a trace tree:
`build_crew → ProgrammeManager → [tool: list_programmes] → ...`

**New env vars:**

```
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_HOST=http://langfuse:3000   # internal docker network address
```

---

## Firewall rules (scan-runner)

The scan-runner container applies `iptables` rules on startup:

- **Egress allowed:** port 80, 443, target-specific ports declared in scope
- **Egress blocked:** RFC 1918 ranges (prevents SSRF from scan tools reaching
  internal infra), port 25 (SMTP), port 22 except explicit allow-list
- **Inbound:** only from `bounty-squad` container on port 8080

These are declared in a `firewall.sh` script that runs as the container
entrypoint, then drops to a non-root user.

---

## Changes required in the Python codebase

1. `tools/recon_tools.py` — replace `subprocess.run(["subfinder", ...])` etc.
   with `httpx.post(f"{config.scan_runner_url}/scan/subfinder", ...)`. The
   scope guard moves to the scan-runner, but keep a client-side check too.
2. `tools/vuln_tools.py` — same pattern for nuclei and sqlmap.
3. `config.py` — add `scan_runner_url: str` field.
4. `tools/metrics.py` — add Prometheus push client for scan metrics.
5. Tests — `scan_runner_url` defaults to a mock server in unit tests (no change
   to existing test structure needed; just add `conftest.py` fixture for the
   mock server URL).

---

## New files

```
docker-compose.yml
docker-compose.override.yml       # local dev overrides (hot reload etc.)
Dockerfile                        # bounty-squad application image
scan-runner/
  Dockerfile
  main.py                         # FastAPI app
  tools/                          # thin wrappers around binaries
  firewall.sh
  requirements.txt
observability/
  prometheus.yml
  grafana/
    datasources/prometheus.yml
    dashboards/pipeline-runs.json
    dashboards/scan-activity.json
  langfuse/
    docker-compose.langfuse.yml   # can be included or run standalone
```

---

## Security notes

- Scan-runner runs as UID 1000, no `CAP_NET_ADMIN` except for the `iptables`
  setup step (which runs as root then drops privileges)
- All tool binaries are verified by SHA-256 at image build time
- The scan-runner API has no authentication (internal network only) — add mTLS
  if the deployment moves to a multi-tenant environment
- `sqlmap` is explicitly rate-limited server-side regardless of client config
  (`--delay` enforced, `--risk` capped at 1 by the server)

---

## Implementation order

1. `scan-runner` Dockerfile + FastAPI skeleton + one tool endpoint (subfinder)
2. Update `tools/recon_tools.py` to use the HTTP API
3. `docker-compose.yml` with `bounty-squad` + `scan-runner` + networks
4. Prometheus + Grafana services + provisioning config
5. Firewall script
6. Remaining tool endpoints (httpx, nmap, nuclei, sqlmap)
7. Update `tools/vuln_tools.py`
8. Dashboard JSON files
9. CI: add `docker compose build` step to lint job

---

## Open questions

- Should the scan-runner be a separate repo or live inside this one as a
  sub-directory? Keeping it here simplifies versioning but couples the
  Python app and the tool runner release cycles.
- Rate limiting per programme vs global rate limit: the current `SCAN_DELAY`
  is global. Per-programme rate limits (declared in `Programme.rate_limit`)
  would be more accurate but require the scan-runner to be stateful.
