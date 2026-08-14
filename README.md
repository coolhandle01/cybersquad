# cybersquad

An autonomous bug bounty pipeline powered by [CrewAI](https://github.com/crewAIInc/crewAI) and Claude. Six AI agents model a full-stack security team: they select HackerOne programmes, map attack surface, run vulnerability scans, triage findings, write professional disclosure reports, and submit them - all in a sequential, auditable pipeline.

> **Legal notice** - You are solely responsible for ensuring every target is in scope, every scan is authorised, and every submission is accurate. Never disable or bypass the approval checkpoints.

---

## How it works

```
Programme Manager --> OSINT Analyst --> Penetration Tester --> Vulnerability Researcher --> Technical Author --> Disclosure Coordinator --> HackerOne API
```

With `CYBERSQUAD_HUMAN_INPUT=true` (the default) the pipeline pauses after programme selection, triage, and report writing, and waits for your confirmation before continuing. Set it to `false` for unattended runs.

| Agent | Responsibility | Tools |
|---|---|---|
| Programme Manager | Ranks H1 programmes by bounty value; verifies automated scanning is permitted | Browse / Hydrate / Save Selected Programme (HackerOne API) |
| OSINT Analyst | Enumerates subdomains, live endpoints, open ports; passive TLS/DNS checks; network path tracing; LLM endpoint detection; IP/ASN ownership enrichment; targeted service-version scans | Run Initial Sweep, List Subdomains / Endpoints / Open Ports, Discover Subdomains, Discover Historical URLs, Discover Webpages, Discover Takeover Candidates, Discover LLM Endpoints, Lookup IP Assets, Lookup RDAP for ASN, Discover Host Services, Lookup CWE, Lookup OWASP Guidance, Annotate Host, List Uncovered Hosts, Finalise Recon (backed by subfinder, httpx, nmap, testssl.sh, dirfuzz, waybackurls, cert transparency, tracepath, dnsx, Team Cymru, RDAP) |
| Penetration Tester | 50+ targeted checks selected per-engagement based on recon evidence | 7 multi-variant probe families (injection / auth / headers / disclosure / client-side / network / external) plus per-service `@cyber_tool` wrappers for cloud + DB checks; Save Findings persists the typed `RawFinding` chain. Backed by nuclei (tag-filtered by technology), sqlmap, nosqli, plus the cloud-service / panel / per-engine database catalogue (Elasticsearch, CouchDB, Redis, MongoDB, PostgreSQL, MySQL; cPanel/WHM, Plesk, DirectAdmin, Webmin, Grafana, Kibana, Portainer, Consul/Vault; S3, Azure Blob) |
| Vulnerability Researcher | Triages raw findings, assigns CVSS 3.1 scores, validates scope | NVD CVE Lookup, List Programme Reports, Finalise Research (research task); List / Read Raw Findings, Calculate CVSS Score, Lookup CWE, Lookup OWASP Guidance, Assess Raw Finding, Discard Finding, Finalise Triage (triage task) |
| Technical Author | Renders complete HackerOne-format Markdown disclosure reports | Sanitise Evidence, Lookup CWE, Lookup OWASP Guidance, Calculate CVSS Score, List Programme Reports, Draft Vulnerability Report, Finalise Reports |
| Disclosure Coordinator | Submits reports via H1 API and records submission metadata | Submit Report, Check H1 Duplicate (HackerOne API) |
| _Shared (every agent after the Programme Manager)_ | Read the typed JSON artefacts earlier agents wrote to the run directory | List Run Files, Read Run File |

Agents do not pass artefacts inline. Each stage writes a typed JSON file to the run directory (`programme.json`, `attack_graph.json`, `recon.json`, `findings.json`, `verified.json`, `reports.json`) and the next agent reads it back through a Pydantic model. Mis-shaped values reject at the reader, not silently mid-pipeline. The in-flight programme handle is workspace state too - bound once at run start by `runtime.bind_programme(...)` and read by every tool that needs scope context. Every agent-picked target field is typed (`TargetFQDNs` / `TargetEndpoints` / `TargetFQDN` / `TargetEndpoint` from `tools/recon/scope.py`); Pydantic's `AfterValidator` runs the scope filter during `args_schema.model_validate(...)`, so an LLM that picks an out-of-scope target sees its tool call rejected before any HTTP request fires.

### Optional: provisioned MCP servers

Beyond the per-agent tool surface above, the squad can be provisioned with [Model Context Protocol](https://modelcontextprotocol.io/) servers at `build_crew()` time. These add crew-wide capabilities visible to every agent; the contributor discipline (build-time-only attach, exact version pins, explicit tool allowlists, two-line audit log) lives in [`.claude/skills/cybersquad-mcp/SKILL.md`](./.claude/skills/cybersquad-mcp/SKILL.md), which auto-loads on any edit to `mcp_servers/` or `crew.py`.

| MCP | Provides | Enable via |
|---|---|---|
| [`mcp-server-time`](https://github.com/modelcontextprotocol/servers/tree/main/src/time) | `get_current_time`, `convert_time` - date-aware reasoning across the pipeline | `pip install -e ".[mcp]"` + `CYBERSQUAD_MCP_TIME_ENABLED=true` |

Defaults are off so a fresh checkout starts without subprocess dependencies. Adding a new MCP follows the runbook in the skill (vet vendor; pin `==`; declare allowlist; two-line audit log; mock-adapter wiring test). Future MCPs (Playwright via #23, MISP) land here as they ship.

---

## Requirements

**Python 3.12+**

**External binaries** - install and ensure each is on your `PATH`:

| Binary | Purpose |
|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing and technology detection |
| [nmap](https://nmap.org) | Port scanning |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning |
| [sqlmap](https://sqlmap.org) | SQL injection detection |
| [nosqli](https://github.com/Charlie-belmer/nosqli) | NoSQL injection detection |
| [testssl.sh](https://testssl.sh) | TLS configuration and certificate assessment |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secret scanning in exposed JS source maps |
| [ffuf](https://github.com/ffuf/ffuf) | Directory and path fuzzing |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Historical URL discovery via Wayback Machine |
| tracepath / traceroute | Network path tracing for CDN/WAF bypass detection |

**API credentials:**
- A [HackerOne](https://hackerone.com) account with API access
- An [Anthropic](https://console.anthropic.com) API key

---

## Installation

```bash
git clone https://github.com/coolhandle01/cybersquad.git
cd cybersquad

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"

# Optional - provisioned MCP servers (off by default; see "Optional: provisioned MCP servers" above)
pip install -e ".[mcp]"
```

---

## Configuration

```bash
cp .env.example .env
$EDITOR .env
```

**Required:**

```
H1_API_USERNAME=your-h1-username
H1_API_TOKEN=your-h1-api-token
ANTHROPIC_API_KEY=your-anthropic-key
CYBERSQUAD_CONTACT_EMAIL=you@example.com
```

`CYBERSQUAD_CONTACT_EMAIL` is surfaced in the outbound `User-Agent` on every HTTP request the squad makes (alongside the platform, programme handle, and your H1 username). A SOC operator who sees the traffic can verify the run against their HackerOne dashboard and reach you directly instead of banning the IP.

**Key tunables** (all have sensible defaults - see `.env.example` for the full list):

| Variable | Default | Purpose |
|---|---|---|
| `CREWAI_MODEL` | `anthropic/claude-sonnet-4-6` | LLM model (litellm format) |
| `H1_MIN_BOUNTY` | `500` | Minimum max-bounty in USD to consider a programme |
| `H1_MAX_PROGRAMMES` | `10` | Number of programmes evaluated per run |
| `MIN_SEVERITY` | `medium` | Discard findings below this severity |
| `SCAN_MODE` | `normal` | Rate-limit profile: `stealth` (2s delay, low rate), `normal` (0.5s), `raid` (0.05s + 429-adaptive backoff). Individual vars (`SCAN_DELAY`, `NUCLEI_RATE_LIMIT`, etc.) override the profile when set. |
| `REPORTS_DIR` | `./reports` | Directory for generated report files |
| `CYBERSQUAD_HUMAN_INPUT` | `true` | Pause for operator approval between stages; set `false` for automated runs |
| `CYBERSQUAD_MCP_TIME_ENABLED` | `false` | Provision the time MCP server. Requires `pip install -e ".[mcp]"`. |
| `CYBERSQUAD_MCP_TIME_TIMEZONE` | `UTC` | IANA timezone the time MCP assumes when the agent omits one |
| `CYBERSQUAD_MCP_CONNECT_TIMEOUT` | `10` | Per-adapter connection timeout in seconds (CrewAI default is 30) |

---

## Running the pipeline

```bash
# Preview agents, tools, and pipeline order - no execution, no API calls
python main.py --dry-run

# Full run (pauses for human approval at each stage by default)
python main.py

# Fully automated - no pauses
CYBERSQUAD_HUMAN_INPUT=false python main.py

# Verbose LLM output
python main.py --verbose
```

Generated reports are saved to `REPORTS_DIR` as Markdown files.

---

## Project layout

```
cybersquad/
+-- main.py            # CLI entrypoint
+-- crew.py            # Assembles LLM, agents, tasks, and approval gates
+-- tasks.py           # Pipeline wiring - context chaining and approval gates
+-- runtime.py         # Pipeline-scoped context (run_id, programme_handle)
+-- mcp_servers/       # Provisioned MCP servers (build_crew()-time only; see cybersquad-mcp skill)
|   +-- __init__.py    # provisioned_mcp_tools() orchestrator + ProvisionedMCPTools registry
|   +-- _common.py     # Shared utilities (adapter-stack pre-flight)
|   +-- _time.py       # The time MCP (one submodule per provisioned MCP)
+-- config.py          # Env-var-backed configuration (singleton: config.*)
|
+-- models/            # Pydantic data contracts between agents
|   +-- primitives.py  # Typed strings (FQDN, HttpUrl) + Severity StrEnum
|   +-- finding.py     # RawFinding (PT output)
|   +-- triage.py      # TriageAssessment, VerifiedVulnerability (VR output)
|   +-- report.py      # AuthoredDraft, DisclosureReport (TA / DC output)
|   +-- h1.py          # Programme + ScopeItem + bounty table
|   +-- ...            # asset, attack, cve, cwe, dns, insight, owasp, workspace
|
+-- squad/             # One sub-package per agent
|   +-- __init__.py    # @cyber_tool decorator, build_agent / build_task helpers
|   +-- tools/         # Shared CrewAI wrapper layer
|   |   +-- workspace_tools.py  # Shared read-only wrappers + current_programme()
|   +-- <member>/
|   |   +-- __init__.py        # MEMBER = SquadMember(...) constant - registry assembly
|   |   |                      #   (imports wrappers from <member>/tools/, re-exports them)
|   |   +-- tools/             # The member's @cyber_tool / @pentest_tool /
|   |   |                      #   @research_brief_tool wrapper layer
|   |   +-- role.md            # Agent role line
|   |   +-- goal.md            # Agent goal (edit to tune behaviour)
|   |   +-- backstory.md       # Agent backstory
|   |   +-- skills/<name>/SKILL.md   # Per-agent skills the runtime CrewAI sees
|   |   +-- <task>/
|   |       +-- description.md       # Task description (one folder per task)
|   |       +-- expected_output.md   # Task expected output
|   +-- penetration_tester/
|       +-- tools/
|           +-- probes/<family>.py # @pentest_tool wrappers (injection, auth, headers,
|           |                      #   disclosure, client_side, network, external)
|           +-- cloud/*.py         # Cloud-service @cyber_tool wrappers (S3, DBs, panels)
|           +-- recon.py           # Recon-query @cyber_tool wrappers
|
+-- tools/             # Tool implementations (the inner check_X helpers / "kernels")
|   +-- h1_api.py          # HackerOne REST client
|   +-- http.py            # Programme-attributed HTTP session
|   +-- workspace.py       # Run-dir path resolution + traversal guard
|   +-- metrics.py         # Token usage and cost tracking
|   +-- report_tools.py    # Markdown report renderer
|   +-- triage_tools.py    # Per-finding validation + assessment persistence
|   +-- research_tools.py  # Attack plan finalisation
|   +-- recon/             # Recon helpers + scope guard (recon/scope.py)
|   +-- pentest/           # Multi-variant probe helpers (StrEnum + check_X)
|   +-- cloud/             # Cloud / DB check_X helpers
|
+-- tests/             # pytest unit tests (@pytest.mark.unit), 1530+ cases, 90% floor
+-- .claude/skills/    # Contributor skills (auto-loaded on file-path match)
+-- proposals/         # Design proposals for upcoming features
+-- CLAUDE.md          # AI contributor guide (skills + conventions)
+-- CONTRIBUTING.md    # Universal contributor guide
+-- pyproject.toml
+-- .env.example
```

The two-layer split (`squad/<member>/` for the `@`-decorated agent-facing wrappers, `tools/` for the underlying `check_X` and helper functions) keeps the LLM-visible contract narrow and lets the implementations evolve without breaking the agent boundary.

---

## Development

### Tests

```bash
# Unit tests - no network, no binaries, all mocked
H1_API_USERNAME=test H1_API_TOKEN=test CYBERSQUAD_CONTACT_EMAIL=test@example.invalid pytest -m unit

# With coverage
H1_API_USERNAME=test H1_API_TOKEN=test CYBERSQUAD_CONTACT_EMAIL=test@example.invalid pytest -m unit --cov --cov-report=term-missing
```

Coverage floor is **90%**. Every new public function in `tools/` requires a unit test. Every bug fix requires a regression test.

### Full CI stack (run before every push)

```bash
ruff check .
ruff format --check .
mypy . --ignore-missing-imports
H1_API_USERNAME=test H1_API_TOKEN=test CYBERSQUAD_CONTACT_EMAIL=test@example.invalid pytest -m unit --cov --cov-report=term-missing
bandit -c pyproject.toml -r . -q
```

All five must pass. CI runs the same checks on every push.

### Adding a new agent

1. Create `squad/<role>/` with:
   - `__init__.py` declaring a `MEMBER = SquadMember(...)` constant
   - The three Agent prose files at the member root: `role.md`, `goal.md`, `backstory.md`
   - One `<task>/` subdirectory per pipeline task, each with `description.md` and `expected_output.md`
   - Optional `skills/<name>/SKILL.md` for runtime skills the CrewAI agent should see
2. Import `MEMBER` into `_SQUAD` in `crew.py`.
3. Wire its task(s) into `build_tasks()` in `tasks.py` with the correct `context` dependencies.
4. Add unit tests for any new tool functions.

### Tuning prompts

Edit the Agent prose (`role.md` / `goal.md` / `backstory.md` at the member root) or the per-task prose (`<task>/description.md` / `expected_output.md`). No Python changes required. Verify with `--dry-run` and note the rationale in your PR.

### Conventions

- `CLAUDE.md` carries the AI-contributor guide and the `.claude/skills/` catalogue (auto-loaded on file-path matches via the `PreToolUse` hook).
- `CONTRIBUTING.md` carries the universal rules: ASCII only, minimal diff, FIXME/TODO grammar, the CI parity stack.

---

## Contributing

- **Branch naming** - `feat/`, `fix/`, `chore/`, or `docs/` prefixes.
- **One concern per PR** - a new agent, a new tool, a config change - not all three.
- **No secrets in code** - credentials belong in `.env` (gitignored). New config fields go in `config.py` and must be documented in `.env.example`.
- **Scope and safety** - changes to scanning behaviour must preserve rate-limiting and the scope guard in `tools/recon/scope.py`. `filter_in_scope()` is a hard safety boundary; every wrapper's agent-input fields are typed as `TargetFQDNs` / `TargetEndpoints` (silent-filter lists) or `TargetFQDN` / `TargetEndpoint` (loud-reject singles), and Pydantic's `AfterValidator` runs the filter during `args_schema.model_validate(...)` - before the wrapper body sees anything. Do not weaken it or move it body-side.

### CI jobs

| Job | Tools |
|---|---|
| `lint` | ruff, mypy |
| `test` | pytest (90% coverage floor) |
| `sast` | bandit, semgrep |

---

## Ethical and legal considerations

- **Only scan authorised targets.** The Programme Manager filters for programmes that explicitly permit automated scanning. Do not remove or weaken this check.
- **Respect rate limits.** Use `SCAN_MODE=stealth` or `normal` against live production targets. `raid` mode is for lab environments or programmes that explicitly invite aggressive testing. Hammering a target can violate programme terms and get you banned.
- **Read before you approve.** When running with `CYBERSQUAD_HUMAN_INPUT=true`, review the programme selection and the report carefully before confirming each pause.
- **Check for duplicates.** Submitting a known duplicate wastes triage time and reflects poorly on the submission record.
- **Handle reports carefully.** The `reports/` directory contains vulnerability details and evidence. It is gitignored - do not commit or share its contents.

---

## Background reading

Load-bearing structural decisions in cybersquad cite a canonical external spec at the assertion site. The index below is the same set, grouped by concern, for a contributor wanting one map.

**Vulnerability scoring and classification**

- [FIRST CVSS v3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document) - the vector grammar, metric short codes, and base-score formula implemented by `Calculate CVSS Score` in `tools/report_tools.py` and surfaced by `squad/vulnerability_researcher/tools/triage.py`.
- [FIRST CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3-1) - hand-verification entry point for a vector / score pair.
- [OWASP Top 10:2021](https://owasp.org/Top10/2021/) - the A01..A10 codes encoded by `OWASPCategory` in `tools/pentest/owasp.py` and stamped onto every `check_X` via `@owasp(...)`.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) - canonical remediation guidance keyed by topic slug, looked up by `tools/owasp_data.py` and cited in every disclosure's Remediation section.

**LLM safety**

- [OWASP Top 10 for LLM Applications - LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) - the threat model the prompt-injection-aware fields in `models/` defend against (direct vs indirect; tool-captured free text vs agent-produced free text).

**Framework and data-shape primitives**

- [CrewAI - LLMs concept](https://docs.crewai.com/en/concepts/llms) and [Agents concept](https://docs.crewai.com/en/concepts/agents) - the `LLM(...)` / `Agent(llm=...)` contract that `crew.py` relies on; the "bare model string silently ignores temperature and max_tokens" footgun is documented here.
- [CrewAI - Create Custom Tools](https://docs.crewai.com/en/learn/create-custom-tools) - the `BaseTool.description` and `args_schema: Type[BaseModel]` surfaces our `@cyber_tool` wrapper makes mandatory.
- [Model Context Protocol specification](https://modelcontextprotocol.io/) - the MCP spec the `cybersquad-mcp` contributor skill codifies. The 2025-06-18 *Security and Trust & Safety* section ("tool annotations should be considered untrusted, unless obtained from a trusted server") is the canonical source for the rules `mcp_servers.py` implements: build-time-only provisioning, exact vendor version pins, explicit tool allowlists, two-line audit log.
- [CrewAI - MCP integration overview](https://docs.crewai.com/en/mcp/overview) and [security](https://docs.crewai.com/en/mcp/security) - the framework wrappers we provision through (`MCPServerAdapter`, `StdioServerParameters`). CrewAI's security page carries the timing observation we design around: the risk "materializes simply by connecting and listing tools" - so provisioning, not just calling, is the attack surface.
- [Alexis King, "Parse, don't validate" (2019)](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/) - the canonical reference for our boundary-typed-validation discipline. Pydantic v2 is the runtime: [docs.pydantic.dev/2.12/concepts/models/](https://docs.pydantic.dev/2.12/concepts/models/).

**Transport and tokenisation**

- [RFC 9110 section 10.1.5 - User-Agent](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5) - the header semantics underlying `tools/http.py`'s structured UA.
- [Sennrich et al., Neural Machine Translation of Rare Words with Subword Units (ACL 2016, arXiv:1508.07909)](https://arxiv.org/abs/1508.07909) - the canonical BPE reference. The mechanism (frequency-trained subword vocabulary) is why the ASCII-only rule in `CONTRIBUTING.md` has measurable downstream cost, not just stylistic motivation.

**Attack-graph reasoning**

The `AttackGraph` / `AttackTree` / `AttackForest` shape in `models/attack.py` and `models/asset.py` is grounded in three papers, each carrying the worldview of one agent role. The longer-form companion is [`docs/academic-grounding.md`](./docs/academic-grounding.md).

- [Schneier, *Attack Trees* (Dr. Dobb's Journal, December 1999)](https://www.schneier.com/academic/archives/1999/12/attack_trees.html) - the original goal-decomposition formalism. Maps to the VR's per-probe sub-goal trees.
- [Sheyner, Haines, Jha, Lippmann, Wing, *Automated Generation and Analysis of Attack Graphs* (IEEE S&P 2002)](https://doi.org/10.1109/SECPRI.2002.1004377) - model-checked attack graphs and the MDP framing of "which path to try first." Maps to the PT's expected-value search; cited in the `AttackForest` docstring.
- [Ou, Govindavajhala, Appel, *MulVAL: A Logic-based Network Security Analyzer* (USENIX Security 2005)](https://www.usenix.org/legacy/event/sec05/tech/full_papers/ou/ou.pdf) - the Datalog-based reasoner that scales attack-graph generation to real networks by representing fact-derivations rather than state transitions.

---

## Licence

MIT - see `LICENSE`.
