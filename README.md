# Bounty Squad

An autonomous bug bounty pipeline powered by [CrewAI](https://github.com/crewAIInc/crewAI) and Claude. Six AI agents model a full-stack security team: they select HackerOne programmes, map attack surface, run vulnerability scans, triage findings, write professional disclosure reports, and submit them — all in a sequential, auditable pipeline with human approval gates.

> **Legal notice** — You are solely responsible for ensuring every target is in scope, every scan is authorised, and every submission is accurate. Never disable or bypass the approval checkpoints.

---

## How it works

```
Programme Manager ──▶ OSINT Analyst ──▶ Penetration Tester
                                                │
                                    [scan-approval gate]
                                                │
                                                ▼
Disclosure Coordinator ◀── Technical Author ◀── Vulnerability Researcher
        │
[submission-approval gate]
        │
        ▼
  HackerOne API
```

At each approval gate the pipeline pauses, renders a summary of what the agent produced, and waits for your explicit confirmation before continuing.

| Agent | Responsibility | Tools |
|---|---|---|
| Programme Manager | Ranks H1 programmes by bounty value; verifies automated scanning is permitted | HackerOne API |
| OSINT Analyst | Enumerates subdomains, live endpoints, and open ports | subfinder, httpx, nmap |
| Penetration Tester | Runs templated and targeted scans against discovered surface | nuclei, sqlmap |
| Vulnerability Researcher | Triages raw findings, assigns CVSS 3.1 scores, validates scope | — |
| Technical Author | Renders complete HackerOne-format Markdown disclosure reports | — |
| Disclosure Coordinator | Submits reports via H1 API and records submission metadata | HackerOne API |

---

## Requirements

**Python 3.12+**

**External binaries** — install and ensure each is on your `PATH`:

| Binary | Purpose |
|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing and technology detection |
| [nmap](https://nmap.org) | Port scanning |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning |
| [sqlmap](https://sqlmap.org) | SQL injection detection |

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
```

**Key tunables** (all have sensible defaults — see `.env.example` for the full list):

| Variable | Default | Purpose |
|---|---|---|
| `CREWAI_MODEL` | `anthropic/claude-sonnet-4-20250514` | LLM model (litellm format) |
| `H1_MIN_BOUNTY` | `500` | Minimum max-bounty in USD to consider a programme |
| `H1_MAX_PROGRAMMES` | `10` | Number of programmes evaluated per run |
| `MIN_SEVERITY` | `medium` | Discard findings below this severity |
| `SCAN_DELAY` | `0.5` | Seconds between scan requests |
| `NUCLEI_RATE_LIMIT` | `10` | Nuclei requests per second |
| `REPORTS_DIR` | `./reports` | Directory for generated report files |

---

## Running the pipeline

```bash
# Preview agents, tools, and pipeline order — no execution, no API calls
python main.py --dry-run

# Full run with interactive approval checkpoints
python main.py

# Verbose LLM output
python main.py --verbose
```

The pipeline pauses twice: once after programme selection (before any scanning begins) and once after the report is written (before submission to H1). At each checkpoint a summary panel is displayed and you must explicitly approve to continue.

Generated reports are saved to `REPORTS_DIR` as Markdown files.

---

## Project layout

```
cybersquad/
├── main.py            # CLI entrypoint
├── crew.py            # Assembles LLM, agents, tasks, and approval gates
├── tasks.py           # Pipeline wiring and checkpoint index definitions
├── config.py          # Env-var-backed configuration (singleton: config.*)
├── models.py          # Pydantic data contracts between agents
│
├── squad/             # One sub-package per agent
│   ├── __init__.py    # SquadMember dataclass + build_agent() / build_task() helpers
│   └── <member>/
│       ├── __init__.py        # @tool functions + MEMBER = SquadMember(...) constant
│       ├── role.md            # Agent role line
│       ├── goal.md            # Agent goal (edit to tune behaviour)
│       ├── backstory.md       # Agent backstory
│       ├── description.md     # Task description
│       └── expected_output.md # Task expected output
│
├── tools/
│   ├── approval.py    # CliApprovalGate and make_approval_callback
│   ├── h1_api.py      # HackerOne REST client
│   ├── metrics.py     # Token usage and cost tracking
│   ├── recon_tools.py # subfinder / httpx / nmap wrappers + scope guard
│   ├── report_tools.py# Markdown report renderer and file writer
│   └── vuln_tools.py  # nuclei / sqlmap / custom check wrappers
│
├── tests/             # pytest unit tests (@pytest.mark.unit)
├── proposals/         # Design proposals for upcoming features
├── pyproject.toml
└── .env.example
```

---

## Development

### Tests

```bash
# Unit tests — no network, no binaries, all mocked
H1_API_USERNAME=test H1_API_TOKEN=test pytest -m unit

# With coverage
H1_API_USERNAME=test H1_API_TOKEN=test pytest -m unit --cov --cov-report=term-missing
```

Coverage floor is **70%**. Every new public function in `tools/` requires a unit test. Every bug fix requires a regression test.

### Full CI stack (run before every push)

```bash
ruff check .
ruff format --check .
mypy . --ignore-missing-imports
H1_API_USERNAME=test H1_API_TOKEN=test pytest -m unit --cov --cov-report=term-missing
bandit -c pyproject.toml -r . -q
```

All five must pass. CI runs the same checks on every push.

### Adding a new agent

1. Create `squad/<role>/` with `__init__.py` (declaring a `MEMBER = SquadMember(...)` constant) and the five prose files: `role.md`, `goal.md`, `backstory.md`, `description.md`, `expected_output.md`.
2. Import `MEMBER` into `_SQUAD` in `crew.py`.
3. Wire its task into `build_tasks()` in `tasks.py` with the correct `context` dependencies.
4. Add unit tests for any new tool functions.

### Tuning prompts

Edit any of the five prose files in `squad/<member>/`: `role.md`, `goal.md`, `backstory.md` (Agent) or `description.md`, `expected_output.md` (Task). No Python changes required. Verify with `--dry-run` and note the rationale in your PR.

---

## Contributing

- **Branch naming** — `feat/`, `fix/`, `chore/`, or `docs/` prefixes.
- **One concern per PR** — a new agent, a new tool, a config change — not all three.
- **No secrets in code** — credentials belong in `.env` (gitignored). New config fields go in `config.py` and must be documented in `.env.example`.
- **Scope and safety** — changes to scanning behaviour must preserve rate-limiting and the scope guard in `recon_tools.py`. `filter_in_scope()` is a hard safety boundary; do not weaken it.

### CI jobs

| Job | Tools |
|---|---|
| `lint` | ruff, mypy |
| `test` | pytest (70% coverage floor) |
| `sast` | bandit, semgrep |

---

## Ethical and legal considerations

- **Only scan authorised targets.** The Programme Manager filters for programmes that explicitly permit automated scanning. Do not remove or weaken this check.
- **Respect rate limits.** `SCAN_DELAY` and `NUCLEI_RATE_LIMIT` exist for a reason. Aggressive scanning can violate programme terms and get you banned.
- **Read before you approve.** The approval checkpoints are not decorative. Review the programme selection and the report carefully before confirming each gate.
- **Check for duplicates.** Submitting a known duplicate wastes triage time and reflects poorly on the submission record.
- **Handle reports carefully.** The `reports/` directory contains vulnerability details and evidence. It is gitignored — do not commit or share its contents.

---

## Licence

MIT — see `LICENSE`.
