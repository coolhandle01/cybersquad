# Bounty Squad — AI Contributor Guide

This file is for AI assistants working on this codebase. It covers the architecture, conventions, safety invariants, and the things most likely to trip you up.

**Read `README.md` first.** Setup, install, env vars, and how to run the pipeline all live there. This file only covers what the README doesn't.

---

## Before you push — non-negotiable

1. **Work inside a virtualenv with the full dev deps installed.**

   ```bash
   python -m venv .venv
   .venv/bin/pip install -e ".[dev]"
   ```

   If you skip this, `mypy` will silently pass locally because it can't resolve `crewai`, `crewai.tools`, or `langchain_anthropic` — and CI will then fail on type errors you never saw. Every other tool is similarly affected. **No venv, no valid local signal.**

2. **Run the entire CI stack locally, in order, before every push.** A ruff pass alone is not enough. The full set:

   ```bash
   .venv/bin/ruff check .
   .venv/bin/ruff format --check .
   .venv/bin/mypy . --ignore-missing-imports
   H1_API_USERNAME=test H1_API_TOKEN=test .venv/bin/pytest -m unit --cov --cov-report=term-missing
   .venv/bin/bandit -c pyproject.toml -r . -q
   ```

   All five must pass. If any fail, fix before pushing — never "push and let CI tell me".

3. **Never push a change you haven't actually executed.** A passing mypy run after a `type: ignore` removal means nothing if the file wasn't reachable. Run the tests.

---

## What this project does

Bounty Squad is a six-agent CrewAI pipeline that autonomously selects HackerOne bug bounty programmes, maps their attack surface, runs vulnerability scans, triages findings, writes professional disclosure reports, and submits them via the H1 API. Agents run sequentially; each passes structured output to the next via CrewAI's `context` chaining.

---

## Key files

| File | Purpose |
|---|---|
| `main.py` | CLI entrypoint. Calls `check_env()` before importing crew — keep it that way. |
| `config.py` | All env-var reading lives here. Singleton: `from config import config`. |
| `models.py` | Pydantic contracts between agents. Change these carefully — they cross agent boundaries. |
| `crew.py` | Assembles the `Crew`: builds LLM, agents, tasks. No module-level side effects. |
| `tasks.py` | Pipeline wiring — context dependencies and `human_input` gates. Thin — keep it that way. |
| `squad/__init__.py` | `SquadMember` dataclass + `build_agent()` / `build_task()` helpers. Each helper reads prose from a single-purpose `.md` file. |
| `squad/<member>/{role,goal,backstory}.md` | Three single-purpose files driving the CrewAI Agent. Edit to tune agent behaviour. |
| `squad/<member>/{description,expected_output}.md` | Two single-purpose files driving the Task description and expected output. |
| `squad/<member>/__init__.py` | Tool functions (`@tool`) + a module-level `MEMBER = SquadMember(...)` constant. |
| `tools/h1_api.py` | HackerOne REST client. Singleton: `from tools.h1_api import h1`. |
| `tools/recon_tools.py` | Wraps subfinder, httpx, nmap. Contains the scope guard. |
| `tools/vuln_tools.py` | Wraps nuclei, sqlmap, custom checks. |
| `tools/report_tools.py` | Renders Markdown reports and writes them to disk. |

---

## Conventions

### Config

All environment variables are read in `config.py` using `field(default_factory=lambda: ...)`. This is intentional — it means values are read at instantiation time, not at class-definition time, which lets `monkeypatch.setenv()` work correctly in tests. Do not change field defaults to bare expressions.

```python
# correct
max_programmes: int = field(default_factory=lambda: int(os.getenv("H1_MAX_PROGRAMMES", "10")))

# wrong — evaluated once at import time, monkeypatch has no effect
max_programmes: int = int(os.getenv("H1_MAX_PROGRAMMES", "10"))
```

### Models

Use `StrEnum` (not `(str, Enum)`) for string enumerations — ruff rule UP042 enforces this. Use `X | None` not `Optional[X]`. Use `model_copy(update={...})` in tests to create variants.

### Agents

Always construct the LLM explicitly using `crewai.LLM`:

```python
from crewai import LLM
llm = LLM(model=config.llm.model, temperature=config.llm.temperature, max_tokens=config.llm.max_tokens)
```

The model name must include the provider prefix for litellm routing, e.g.
`anthropic/claude-sonnet-4-20250514`. Passing a bare model string directly to
`Agent(llm=...)` silently ignores `temperature` and `max_tokens`.

### Prompts

Each agent's prose lives in five single-purpose markdown files inside its package: `role.md`, `goal.md`, `backstory.md`, `description.md`, `expected_output.md`. `SquadMember.read("<name>")` loads `<name>.md` and strips whitespace. Missing files raise `FileNotFoundError` at agent/task build time. No separators, no parsing.

---

## Safety invariants — do not break these

**Scope enforcement** — `filter_in_scope()` in `recon_tools.py` uses an exact-match or dot-boundary check:

```python
if host == pattern or host.endswith("." + pattern):
```

A bare `host.endswith(pattern)` would allow `evil.notexample.com` to match `example.com`. Do not simplify this.

**Automated-scanning gate** — `parse_programme()` in `h1_api.py` sets `allows_automated_scanning=False` when the policy text contains keywords like "no automated" or "automated scanning prohibited". The Programme Manager is instructed to discard such programmes. Do not remove or weaken this check.

**Import order in `main.py`** — `check_env()` must run before `build_crew()` is imported or called. The crew import triggers `crew.py`, which imports `config`, which reads env vars. If credentials are missing, `check_env()` should exit cleanly before that happens.

**No module-level side effects in `crew.py`** — the old `crew = build_crew()` at module level has been deliberately removed. Do not re-introduce it.

---

## Testing

All tests are marked `@pytest.mark.unit` and must run without network access, real API credentials, or external binaries. Use `monkeypatch` and `unittest.mock` to isolate.

```bash
H1_API_USERNAME=test H1_API_TOKEN=test pytest -m unit
```

Tests that reload modules for config isolation use `importlib.reload()` — this is the correct pattern for testing env-var-backed dataclasses.

Coverage floor is 70%. Every new public function in `tools/` needs a test. Every bug fix needs a regression test.

---

## Adding a new agent

1. Create `squad/<role-name>/` with:
   - `__init__.py` — `@tool` functions + `MEMBER = SquadMember(slug=..., dir=Path(__file__).parent, tools=[...])`
   - `role.md`, `goal.md`, `backstory.md` — drive the CrewAI Agent
   - `description.md`, `expected_output.md` — drive the Task
2. Import the new `MEMBER` into `_SQUAD` in `crew.py`.
3. Wire its task into `build_tasks()` in `tasks.py` with correct `context` dependencies.
4. Add unit tests covering the new tool's logic.

---

## Adding a new config value

1. Add a field to the appropriate dataclass in `config.py` using `default_factory=lambda: os.getenv(...)`.
2. Document it in `.env.example` with a comment explaining valid values.
3. If the value is used in a tool, thread it through via `config.<section>.<field>` — do not hardcode fallback values in the tool.

---

## CI

Three jobs run on every push: `lint` (ruff + mypy), `test` (pytest, 70% coverage floor), and `sast` (bandit + semgrep). The local commands in the "Before you push" section above mirror them exactly — use those.

Notes on fixing findings:

- **ruff** — `ruff check --fix` and `ruff format` resolve most issues automatically.
- **mypy** — ensure all public functions have annotated parameters and return types. If a real dep (crewai, pydantic) has incomplete stubs and you need to suppress a false positive, use a targeted `# type: ignore[<code>]` rather than a blanket ignore.
- **bandit** — suppress with `# nosec B<code>` (bandit's own directive, *not* `# noqa`). Keep the accompanying `# noqa: S<code>` for ruff — both are needed:

  ```python
  os.getenv("FOO", "/tmp/bar")  # nosec B108  # noqa: S108
  ```

- **GitHub Actions pins** — every action must be pinned to a full-length commit SHA, not a tag. Branch protection enforces this. Add the version as a trailing comment for readability:

  ```yaml
  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4.3.1
  ```

- **upload-artifact v4 and hidden files** — `.coverage` and other dotfiles are skipped by default. Set `include-hidden-files: true` on the step.
