# Contributing to cybersquad

Thanks for working on this. This file is the contributor surface: setup pointers, the rules every change must follow, and the safety invariants that hold across the codebase. If you are working with Claude Code, also read `CLAUDE.md` for the AI-specific instructions and the skill catalogue.

For project setup (Python version, external binaries, API credentials, install commands), see `README.md`.

## Before you commit

Work inside a virtualenv with full dev dependencies installed. Without it, `mypy` cannot resolve `crewai`, `crewai.tools`, or `langchain_anthropic` and will silently pass.

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Use Python 3.12 - it is the version CI pins (`.github/workflows/ci.yml`) and the `requires-python` floor.

Then run the full CI stack locally, in this order. All six must pass before pushing - never "push and let CI tell me":

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy . --ignore-missing-imports
.venv/bin/pylint .
H1_API_USERNAME=ci-user H1_API_TOKEN=ci-token CYBERSQUAD_CONTACT_EMAIL=ci@example.invalid .venv/bin/pytest -m unit --cov --cov-report=term-missing
.venv/bin/bandit -c pyproject.toml -r . -q
```

Advisory (not CI-gated): periodically run `vulture` to surface dead code that the import graph cannot see. Pydantic model fields trigger false positives at lower confidence, so 80% is the gospel floor:

```bash
.venv/bin/pip install vulture       # one-off, not in [dev]
.venv/bin/vulture --min-confidence 80 squad/ tools/ models/ runtime.py crew.py
```

Treat findings as candidates for removal, not removal mandates - check the import graph (re-exports, conditional consumers) before deleting.

`pytest --cov` runs with **branch coverage on** by default - it is wired in `pyproject.toml`'s `[tool.coverage.run] branch = true`. The 90% `fail_under` gate applies to combined line + branch coverage. A green run means every conditional you touched has both its True and False path exercised.

Never push a change you haven't actually executed. A passing `mypy` run after removing a `# type: ignore` means nothing if the file wasn't reachable.

Read the actual file before planning any change. Check `proposals/` for in-flight design work.

## Test-first discipline

cybersquad is a TDD codebase. For any new behaviour, bug fix, or modification you make, the discipline is:

1. **Write the failing test first.** Capture the behaviour you want, or the bug you're fixing. The test should fail for the *right reason* - re-run and check the failure message before writing any production code.
2. **Write the minimum production code** to make that test pass. Resist the urge to also write the next thing, or the abstraction, or the helper. Just pass the one test.
3. **Re-run the suite.** Green.
4. **Refactor under green tests** if the code that just landed needs tidying.
5. **Loop.** Next failing test, next minimum code, next green.

This discipline is not negotiable for code that ships. Bug-fix PRs without a regression test are rejected. Feature PRs without coverage of every conditional path you wrote are rejected.

### Branch coverage on your diff is 100% or you say why

The 90% project-wide floor catches drift. On the lines you write, modify, or fix, the bar is higher: **every conditional has both branches exercised by a test**. `--cov-report=term-missing` (already in the default `pytest --cov` invocation) prints the missing line + branch numbers; cross-reference them against your diff before you push. If a branch is genuinely unreachable, mark it `# pragma: no cover` with a one-line comment explaining why - silent suppression is the same anti-pattern as a bare `# noqa`.

Line coverage at 100% does not mean tested. Branch coverage at 100% on your diff means the conditional has been thought about.

## Universal rules

These apply to every edit, no exceptions.

### ASCII only

All source files, comments, docstrings, and `.md` prose must be plain ASCII. No em dashes, en dashes, curly quotes, box-drawing characters, arrows, bullets, or emoji. Use `-` not em-dash, `->` not the Unicode arrow, `|` not the Unicode pipe. Unicode in source inflates token counts for every AI tool that reads this codebase.

The mechanism, briefly: modern LLM tokenisers are byte-pair-encoding variants trained on corpus frequency (Sennrich et al., [Neural Machine Translation of Rare Words with Subword Units](https://arxiv.org/abs/1508.07909), ACL 2016). The vocabulary is biased toward common-corpus sequences, so high-frequency ASCII (`-`, `->`, `|`, `'`, `"`) is typically one token, while uncommon Unicode punctuation (em-dash, smart quotes, non-breaking space, box-drawing characters, emoji) routinely fragments into multiple bytes / tokens under byte-level BPE. The exact ratio is tokeniser-dependent - this is an emergent property of frequency-trained vocabularies, not a per-character constant - but the direction is consistent and the cost compounds across every agent context window the codebase ever lands in.

### Minimal diff

One PR does one thing. Before any commit, run `git diff origin/main --stat` and ask: does every changed file relate to the stated task? If not, revert the unrelated change or move it to its own branch. Leave whitespace, formatting, and import order alone unless the linter required the change. Do not rewrite working code to a "cleaner" form unless cleanliness was the task.

### Cite the standard you diverge from

When the codebase deliberately departs from a documented standard, named best practice, or upstream framework convention, the divergence must carry a link to the thing it diverges from. Future-you reading the code six months from now needs to be able to follow the URL, read the upstream practice, and recover the *reasoning* behind the departure - not infer it from the absence of a citation, and not rediscover it by reading the spec from scratch.

This is the Chesterton's Fence rule with a sign on the fence. A divergence without a citation is indistinguishable from sloppiness; the citation is what marks it as deliberate.

State three things in the same paragraph or docstring as the divergence:

1. **Cite the upstream practice with a URL.** "RFC 9110 section 10.1.5 defines...", "CrewAI's design-agent skill recommends...", "OWASP Top 10:2021 categorises...". The URL must back the specific claim, not just be vaguely topical.
2. **Name the departure explicitly.** "Deliberate departure from...", "Diverges from upstream by...", "This skill *deliberately diverges*...". Grep-discoverable so future-contributor `grep -ri "divergen\|departure from"` surfaces the same set every time.
3. **Name what the departure buys.** SOC-operator parseability, cross-agent contract-test discipline, mypy verification of inter-tool wiring, avoiding a 30K-token JSON blob in every downstream context. A divergence without a stated reason is a future migration target.

Current divergences in the codebase, each carrying its citation - this is the worked register, not an exhaustive list:

- `tools/http.py` `user_agent()` - structured `"<product>; <key>: <value>"` UA vs the typical product-token form. Cites [RFC 9110 section 10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5). Buys SOC-operator parseability of programme handle, researcher, and contact email without external metadata correlation.
- `cybersquad-tool` skill `Divergence 1` - Pydantic typed returns from tools vs upstream's "tools return text-fodder for LLM reasoning" stance. Cites [crewAIInc/skills `design-agent/references/custom-tools.md`](https://github.com/crewAIInc/skills/blob/main/skills/design-agent/references/custom-tools.md). Buys cross-agent contract tests, mypy verification of tool wiring, and typed test access to `tool.func(...)`.
- `cybersquad-tool` skill `Divergence 2` and `cybersquad-task` skill - workspace files (typed `finalise_X` writer + typed `load_X` reader) for inter-agent structured handoff vs CrewAI's `output_pydantic`. Cites [crewAIInc/skills `design-task`](https://github.com/crewAIInc/skills/blob/main/skills/design-task/SKILL.md). Buys: avoidance of ~30K-token recon artefacts in every downstream `context=`, and a reasoning-narrative + typed-artefact split that `output_pydantic` collapses.

When you add a new divergence, append it to the register above in the same PR. A new divergence that ships without a citation is treated like a `# noqa` without an explanation: not a hard block, but a reviewer-facing flag that the assumption is unverified.

### Defer to upstream where upstream covers it

The partner rule to "Cite the standard you diverge from". Where the codebase **does not** diverge - where upstream's general case is the case - link the canonical reference and stay silent on the general material. Don't restate what upstream already covers competently; duplication becomes drift the moment upstream updates, and the contributor reading our skill loses the discoverability hop to the source of truth.

A skill, module docstring, or design comment that competently practices this looks like `cybersquad-agent-llm`'s Upstream alignment section: it names what upstream covers (general agent design - role-goal-backstory, `max_iter` / `max_rpm` tuning, `function_calling_llm` split, guardrails), links the canonical upstream source ([crewAIInc/skills `design-agent`](https://github.com/crewAIInc/skills/blob/main/skills/design-agent/SKILL.md)), and confines the cybersquad-side content to the narrow project-specific footgun (the bare-model-string `Agent(llm=...)` path silently dropping `temperature` and `max_tokens`).

Skills already practicing this, as the worked register:

- `cybersquad-agent-llm` defers to crewAIInc/skills `design-agent` for general agent design.
- `cybersquad-task` defers to crewAIInc/skills `design-task` for general task design.
- `cybersquad-tool` defers to crewAIInc/skills `design-agent/references/custom-tools.md` for tool mechanics.
- `cybersquad-skill` defers to CrewAI's runtime skill documentation for skill-authoring mechanics.
- `cybersquad-models` defers to [Pydantic v2 documentation](https://docs.pydantic.dev/2.12/) for general Pydantic usage.

A new contributor skill that does **not** carry an Upstream alignment section is fine if either: (a) there is no canonical upstream for the topic - some patterns are genuinely cybersquad-specific (the `runtime.bind_*` singleton-per-pipeline pattern is an example) - or (b) the skill explicitly builds on another cybersquad skill, named in its frontmatter `description:` (e.g. `cybersquad-pentest-tool` builds on `cybersquad-tool`; `cybersquad-prompteng` builds on `cybersquad-tool`). State the case in either form so the absence is read as deliberate, not as oversight.

### Preserve names, comments, and structure unless the change is the task

Code carries intent. Symbol names, comment wording, and file layout all encode what the original author understood. A drive-by rename inside an unrelated PR breaks `git blame` continuity, loses the author's framing, and makes the diff argue about two things at once.

- **Comments**: leave them alone unless they are actively incorrect (lying about what the code does). Do not reword for "style".
- **Symbol names**: rename only when (a) the new name is materially clearer, *and* (b) renaming is in scope for this PR.
- **Structure**: moving code between files, splitting functions, extracting helpers - all valid, all out of scope unless that *is* the task.

Before deleting or simplifying anything that looks redundant (Chesterton's Fence): find out why it was put there. See the safety invariants below for documented examples.

### Linter and SAST findings are engineering signal

ruff / mypy / bandit / semgrep findings are not bureaucracy. Each one is the tool flagging an assumption it could not verify. Before suppressing:

1. Read the finding. What is the tool worried about?
2. Identify the unstated assumption. Why is the code actually safe or correct?
3. Choose the cheaper fix. Often making the assumption explicit in code is cheaper than suppressing the warning.
4. If you must suppress, the suppression must carry a one-line comment explaining the why. No bare `# noqa`, `# type: ignore`, or `# nosec`.

```python
# acceptable - the why is in the comment
os.getenv("FOO", "/tmp/bar")  # nosec B108  # noqa: S108 - intentional dev default, prod requires FOO

# not acceptable
result = something_dangerous()  # nosec
```

The flip side: when you encounter a suppression in unfamiliar code, the suppressions are the codebase telling you where the load-bearing assumptions live. The one-line `why` is the original author handing you context the type system or scanner could not encode - read it before you change anything that depends on it.

### Pylint says split, not suppress

Pylint is scoped (see `[tool.pylint]` in `pyproject.toml`) to the design rules that fire when a module, function, or class outgrows its single responsibility. When it fails on code you edited, split the unit - pull a cohesive piece into its own module, extract a helper. Suppression (`# pylint: disable=...`) is reserved for cases where the unit genuinely is one thing; same grammar as other suppressions, one-line comment explaining why.

### FIXME and TODO grammar

Use a consistent shape so these are greppable and actionable:

```python
# FIXME: this swallows ConnectTimeout but should retry once - tracked in #NN
# TODO: extract the cookie-jar logic when test_csrf.py stabilises
```

`FIXME` means the code is wrong or incomplete in a way that should be fixed. `TODO` means the code is fine but improvement is possible later. Include enough context that another contributor could act on it without scrolling git history. If you cannot phrase the FIXME or TODO clearly, the right answer is "ask", not "note it".

### Surface concerns, do not silently override

When you find yourself wanting to break a stated rule (rename for clarity in a non-rename PR, suppress a linter finding you do not understand, change a comment that might actually be correct), stop. The options in order of preference:

1. Ask. A one-line question is cheap and prevents wrong work.
2. Note it via FIXME or TODO using the grammar above, and proceed with the original task untouched.
3. Open an issue. Default to a **sub-issue of the parent feature** so it lands in the same PR. Standalone "follow-up" issues need explicit justification of why the concern is orthogonal - name the parent feature or issue number the work belongs under. A feature PR that opens three "follow-on" `feat` issues is the same PR landing with three known gaps; the burnup graph notices.

### Reviewer-surfaced gaps default to blockers

When a PR review surfaces a gap - UA not wired, evidence flow missing, scope guard incomplete, invariant the rest of the codebase enforces this one wrapper does not - the default is **blocker, sub-issue under the parent feature, address before merge**. The exceptions are narrow:

- The gap is genuinely about a different feature. Name it: "this belongs under #N, not the current PR".
- The cost of holding the PR exceeds the cost of two follow-ups landing later. Justify in the PR thread, not as an unspoken assumption.

If you find yourself reaching for the exception, write down the orthogonal scope explicitly. "Follow-up" as a verbal shrug is the trap this section is closing - the same PR landing with three "follow-on" issues attached is the same PR landing with three known gaps, and the project's issue count grows linearly with features-shipped-with-gaps rather than features-shipped-clean.

### Tests: derive variants with `model_copy(update=...)`

When deriving a test variant from a canonical fixture model, do not reconstruct the model from scratch via the constructor. Use `model_copy`:

```python
# correct
out_of_scope = programme.model_copy(update={"in_scope": []})

# wrong - duplicates every other field
out_of_scope = Programme(handle=programme.handle, name=programme.name, ...)
```

### Five-file prompt layout

Each agent's prose lives in exactly five single-purpose markdown files inside its package:

```
squad/<member>/
    role.md
    goal.md
    backstory.md
    description.md
    expected_output.md
```

`SquadMember.read("<name>")` loads `<name>.md` and strips whitespace. Missing files raise `FileNotFoundError` at agent or task build time. If you need to add expertise to an agent, do it inside one of these five files, not by introducing a sixth.

## Safety invariants - do not weaken

These exist for reasons that are not obvious from the code alone. Touching any of them requires deliberate, explained intent.

- **Scope enforcement** in `tools/recon/scope.py`: `if host == pattern or host.endswith("." + pattern)`. A bare `host.endswith(pattern)` would let `evil.notexample.com` match `example.com`.
- **Automated-scanning gate**: the Programme Manager reads `policy_text` and discards any programme whose policy forbids automated tools, scanners, fuzzing, brute force, or rate testing. The discard rule lives in `squad/programme_manager/description.md`; `policy_text` is the source of truth and there is intentionally no boolean shortcut on the `Programme` model.
- **Import order in `main.py`**: `check_env()` must run before `build_crew()` is imported. The crew import chain reads env vars; `check_env()` must exit cleanly first.
- **No module-level side effects in `crew.py`**. The old `crew = build_crew()` at module level was deliberately removed.
- **`default_factory=lambda` in `config.py`** preserves `monkeypatch.setenv` semantics in tests. Do not "simplify" to direct env reads at class-definition time.

## Pull requests

Pushing a branch and opening its PR are one action, not two. A pushed branch with no PR is invisible to review, to CI's per-PR gates (the `diff-cover` ratchet only runs on `pull_request` events), and to the maintainer's mental model - so open the PR the moment you push, and subscribe to it so review comments and CI events reach you. Most contributors are auto-subscribed by GitHub; some integrations - AI sessions included - need an explicit subscribe step. The only branch you push without opening a PR is one the maintainer has explicitly told you to leave alone.

## Where to find more

- `docs/architecture.md` - what the project does, key files
- `docs/git-workflow.md` - branch naming, fresh-from-main flow, commit-message rules
- `docs/testing.md` - pytest invocation, coverage floor, shared fixtures
- `docs/ci.md` - ruff/mypy/bandit guidance, SHA pinning, `upload-artifact` gotcha
- `docs/contributing/adding-an-agent.md` - the agent recipe
- `docs/contributing/adding-a-tool.md` - the tool recipe, including probe-StrEnum and `default_factory=lambda` rules
- `docs/contributing/adding-config.md` - config knobs and their tests
