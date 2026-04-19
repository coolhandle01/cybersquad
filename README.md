# Bounty Squad

An autonomous bug bounty pipeline powered by [CrewAI](https://github.com/joaomdmoura/crewAI) and Claude. Six AI agents model a full-stack security team: they discover programmes, map attack surface, run scans, triage findings, write professional reports, and submit them to HackerOne — all in a sequential, auditable pipeline.

> **Legal notice** — You are responsible for ensuring every target is in scope, every scan is authorised, and every submission is accurate. The pipeline includes a human approval gate before submission. Never bypass it.

---

## Architecture

```
Programme Manager → OSINT Analyst → Penetration Tester
                                           ↓
Disclosure Coordinator ← Technical Author ← Vulnerability Researcher
```

| Agent | Role | External tools |
|---|---|---|
| Programme Manager | Ranks H1 programmes by bounty value and automated-scanning permission | HackerOne API |
| OSINT Analyst | Enumerates subdomains, live endpoints, and open ports | subfinder, httpx, nmap |
| Penetration Tester | Runs templated and targeted scans against discovered surface | nuclei, sqlmap |
| Vulnerability Researcher | Triages raw findings, assigns CVSS scores, writes descriptions | — |
| Technical Author | Renders HackerOne-format Markdown reports | — |
| Disclosure Coordinator | Submits reports via H1 API, records submission metadata | HackerOne API |

Each agent's task prompt lives in `prompts/<role>.md` — edit those files to tune behaviour without touching Python.

---

## Requirements

**Python** — 3.11 or later.

**External binaries** — install these and ensure they are on your `PATH`:

| Binary | Purpose |
|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration |
| [httpx](https://github.com/projectdiscovery/httpx) (CLI, not the Python lib) | HTTP probing and tech detection |
| [nmap](https://nmap.org) | Port scanning |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning |
| [sqlmap](https://sqlmap.org) | SQL injection detection |

**API keys** — you need:
- A [HackerOne](https://hackerone.com) account with API credentials
- An [Anthropic](https://console.anthropic.com) API key

---

## Installation

```bash
git clone <repo-url>
cd cyberz

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

---

## Configuration

Copy the example env file and fill in your credentials:

```bash
cp .env.example .env
$EDITOR .env
```

Required variables:

```
H1_API_USERNAME=your-h1-username
H1_API_TOKEN=your-h1-api-token
ANTHROPIC_API_KEY=your-anthropic-key
```

Everything else has a sensible default. See `.env.example` for the full reference. Key tunables:

| Variable | Default | Purpose |
|---|---|---|
| `H1_MIN_BOUNTY` | `500` | Minimum max-bounty (USD) to consider a programme |
| `H1_MAX_PROGRAMMES` | `10` | How many programmes to evaluate per run |
| `MIN_SEVERITY` | `medium` | Discard findings below this severity |
| `SCAN_DELAY` | `0.5` | Seconds between scan requests |
| `NUCLEI_RATE_LIMIT` | `10` | Nuclei requests per second |
| `LLM_MODEL` | see `.env.example` | Claude model ID |
| `REPORTS_DIR` | `reports/` | Where generated reports are saved |

---

## Running the pipeline

```bash
# Dry run — prints agents, tools, and prompts without executing anything
python main.py --dry-run

# Full run (pauses for human approval before submission)
python main.py

# Verbose output
python main.py --verbose
```

Before the Disclosure Coordinator submits, the pipeline pauses and shows you the programme handle, vulnerability class, severity, and target. Type `yes` to proceed or anything else to abort.

Saved reports land in `reports/` as Markdown files named `{timestamp}_{programme}_{title}.md`.

---

## Development

### Project layout

```
cyberz/
├── agents.py          # CrewAI agent definitions + LangChain tool wrappers
├── tasks.py           # Loads prompts and wires tasks to agents
├── crew.py            # Assembles agents + tasks into a Crew
├── main.py            # CLI entrypoint
├── config.py          # Env-var-backed dataclass config (singleton: config.*)
├── models.py          # Pydantic pipeline data models
├── prompts/           # One markdown file per agent role (description + expected output)
├── tools/
│   ├── h1_api.py      # HackerOne REST API client
│   ├── recon_tools.py # subfinder / httpx / nmap wrappers + scope filtering
│   ├── vuln_tools.py  # nuclei / sqlmap / CORS check wrappers
│   └── report_tools.py# Markdown report renderer + file writer
└── tests/             # pytest unit tests (marked with @pytest.mark.unit)
```

### Running tests

```bash
# Unit tests only (no real network or binary calls — all mocked)
H1_API_USERNAME=test H1_API_TOKEN=test pytest -m unit

# With coverage report
H1_API_USERNAME=test H1_API_TOKEN=test pytest -m unit --cov --cov-report=term-missing
```

Coverage must stay at or above **70%**. The CI will fail if it drops.

### Linting and formatting

```bash
ruff check .                        # lint
ruff format .                       # auto-format
mypy . --ignore-missing-imports     # type checking
```

### Security scanning

```bash
bandit -c pyproject.toml -r . -q
semgrep scan --config=p/python --config=p/security-audit
```

All three jobs run automatically in CI on every push.

---

## Contributing

1. **Branch naming** — use `fix/`, `feat/`, or `chore/` prefixes. CI triggers on these patterns.

2. **One concern per PR** — a new agent, a new tool wrapper, a config change — one thing at a time.

3. **Tests are not optional** — every new function in `tools/` needs a unit test. Every bug fix needs a regression test that fails without the fix.

4. **No secrets in code** — credentials go in `.env` (gitignored). Add new config to `config.py` and document it in `.env.example`.

5. **Prompt changes** — edit the relevant file in `prompts/`. Verify the pipeline still structures correctly with `--dry-run` and note the rationale in your PR description.

6. **Scope and safety** — changes to scanning behaviour must preserve rate-limiting and scope enforcement. `filter_in_scope()` in `recon_tools.py` is a hard safety boundary.

### CI checks (must all pass)

| Job | What it runs |
|---|---|
| `lint` | `ruff check`, `ruff format --check`, `mypy` |
| `test` | `pytest -m unit` with coverage floor |
| `sast` | `bandit`, `semgrep` |

---

## Ethical and legal considerations

- **Only scan authorised targets.** The programme manager filters for programmes that explicitly permit automated scanning — do not disable this check.
- **Respect rate limits.** `SCAN_DELAY` and `NUCLEI_RATE_LIMIT` exist for a reason. Aggressive scanning can violate programme rules.
- **Review before submitting.** The human approval gate is not decorative. Read the report before confirming.
- **Check for duplicates.** Before submitting, verify the finding hasn't already been reported. Duplicate submissions waste triage time.
- **Data handling.** Reports contain vulnerability details and evidence. The `reports/` directory is gitignored — do not commit or share it.

---

## Licence

MIT — see `LICENSE`.
