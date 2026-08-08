# cybersquad - AI Contributor Guide

**Read `CONTRIBUTING.md` first.** It carries the universal rules (ASCII only, minimal diff, preserve names and comments, linter findings as signal, FIXME/TODO grammar, surface concerns), the `Before you commit` CI parity stack, and the safety invariants. Everything below is AI-contributor-specific layered on top.

## Before you start work on an issue

The contributor skills below auto-load on the first matching edit, which is too late - by then you have already chosen an approach. Read the relevant skill at issue-scoping time so the conventions are in your head while you are still deciding what to build.

Then ask: what canonical knowledge will this issue produce that does not yet live in a skill? Update the skill **first** - or at least sketch the update in this conversation - so the work that follows is the skill being applied, not the skill being discovered. By the time the code lands the skill update is part of the same PR, written by an expert against captured intent rather than documented after the fact.

## Handling PR review feedback

When you have an open PR and a reviewer surfaces a gap, treat it as a **blocker on this PR** by default - file as a sub-issue of the parent feature and address it before merge. See `CONTRIBUTING.md`'s "Reviewer-surfaced gaps default to blockers". Standalone "follow-up" issues need a named orthogonal scope; if you cannot name the orthogonal feature, the work belongs in the current PR.

Watching a PR means investigating each review event and deciding whether the surfaced gap belongs in this PR or somewhere else - not optimising for closing the current PR by deferring everything to "follow-ups" that grow the open-issue count without growing the project.

## Git essentials

The full flow is in `docs/git-workflow.md`; these are the non-negotiables, inline so they land before the first commit rather than two hops away:

- **Branch**: cut fresh from current `main` and name it `<type>/<short-description>`, where `<type>` matches the commit type (`feat/`, `fix/`, `docs/`, `refactor/`, `chore/`, ...). A branch ruleset blocks `claude/*` and other off-convention names. If a harness placed you on a synthetic branch while a real PR branch exists, switch to the PR branch and surface the mismatch.
- **Commit**: Conventional Commits - `<type>(<scope>)?: <subject>`, lowercase imperative subject (e.g. `refactor(squad): lift wrappers into tools/`).
- **Before you push**: run the CONTRIBUTING "Before you commit" CI parity stack, and `git diff origin/main --stat` to confirm only intended changes are staged.
- **Never** force-push, `git push --delete`, or `git branch -D` a shared / PR branch without an explicit plain-words maintainer authorisation in the immediately preceding message; `--force-with-lease` is no exception. `git-guard.sh` enforces this at the tool boundary.
- Never include session URLs (`https://claude.ai/code/session_...`) in commit messages or PR bodies - they reference private conversations.

## Skills

Two skill systems run in this repo. They do not interact - one targets the
contributor (you, editing code), the other targets the runtime crew (agents
executing the pipeline).

### Contributor skills (Claude Code)

Skills under `.claude/skills/` auto-load via a `PreToolUse` hook on `Write`/`Edit`/`Read` configured in `.claude/settings.json`. The relevant skill's full `SKILL.md` is injected into context on the first matching tool call per session, deduplicated so repeated edits or reads of the same scope are silent. `Read` is matched as well as `Write`/`Edit` so a **reviewer** - who reads, greps and runs tests but never edits - loads the governing skill too, not only the author. (A per-session sentinel means the extra `Read` matching costs one injection per scope, not one per read.)

| Skill | Triggers on |
|---|---|
| `cybersquad-tool` | Any `*.py` file under `squad/` at any depth - member `__init__.py`s (now pure registry assembly), the per-member wrapper modules under `squad/<member>/tools/` (including the `probes/` and `cloud/` sub-packages, and the `recon.py` / `findings.py` / `research.py` / `triage.py` / `curation.py` / `discovery.py` / `selection.py` / `submission.py` / `authoring.py` modules), and the `squad/tools/workspace_tools.py` shared layer. Guarded out of the `tests/squad/` mirror so test edits do not over-trigger. |
| `cybersquad-pentest-tool` | `tools/pentest/**` and the `@pentest_tool` wrapper surface: `squad/penetration_tester/__init__.py`, `squad/penetration_tester/tools/_decorator.py`, `squad/penetration_tester/tools/probes/**`. Cloud wrappers use `@cyber_tool` (not `@pentest_tool`) so they stack on the universal skill only. |
| `cybersquad-prompteng` | Same trigger as `cybersquad-tool` (`*/squad/*.py`). Carries the *communication* layer - the two LLM-visible surfaces (tool docstring + `Field(description=...)`), the division of labour between them, what to say in each, what NOT to say twice. Specialist after `cybersquad-tool` (mechanics) so the communication rules land more prominently. |
| `cybersquad-models` | Any `*.py` file under `models/`. Carries the LLM-facing contract: typed primitives, workspace artefact shapes, prompt-injection awareness on free-text fields. The consumer-side rules (how a wrapper *uses* these models) live in `cybersquad-tool`. |
| `cybersquad-oam` | Any `*.py` file under `models/asset/`. Stacks on `cybersquad-models` (specialist last). The OWASP Open Asset Model vocabulary the asset package implements: assets as typed nodes, relations as typed edges, properties hung off assets, the faithful-to-amass mapping, the OAM-names-win naming rule, and provenance stamping. Points to `docs/academic-grounding.md` for the longer-form grounding. |
| `cybersquad-runtime` | `runtime.py`, `main.py` |
| `cybersquad-agent-llm` | `crew.py` |
| `cybersquad-mcp` | Any file under `mcp_servers/` (the package with the orchestrator + one submodule per MCP), plus stacks on `crew.py` where the provisioned-MCP tool list is distributed to agents. Carries the threat-model rules from #144: build-time provisioning only, no runtime attach, disjoint sets for provisioned vs. discovered MCPs, explicit tool allowlist, audit log. |
| `cybersquad-task` | `tasks.py` |
| `cybersquad-tests` | Any file under `tests/` (including the `tests/squad/` mirror). Shared fixtures **and** the test-observability doctrine (observe don't just execute; the paper-tiger taxonomy; mutation-audit practice). |
| `cybersquad-bdd` | `tests/features/**` or `tests/bdd/**` |
| `cybersquad-skill` | Any agent-facing markdown under `squad/`: `squad/skills/<name>/SKILL.md`, `squad/<member>/skills/<name>/SKILL.md`, `squad/<member>/role.md`/`goal.md`/`backstory.md`, `squad/<member>/<task>/description.md`/`expected_output.md` |

Grouped by concern: tool wrappers, pipeline plumbing, tests, agent-facing prose. Where two skills can match the same file (tool + pentest-tool on a probe; models + oam on an asset model; test-fixtures + bdd on a BDD test) the specialist is loaded last so it lands more prominently in context. Editing `runtime.py` directly loads `cybersquad-runtime` only - consumer-side rules (the `import runtime` propagation property tests rely on) live in `cybersquad-tool` because that is the skill the tool author already sees.

The `in_tests` pre-classifier in the hook is load-bearing: `*` crosses `/` in bash case patterns, so without it `*/squad/*.py` would over-match `tests/squad/<member>/test_*.py` and pull the wrapper-author skills into test edits where they do not apply.

The hook is wired in `.claude/settings.json`; the matching logic lives in `.claude/hooks/load-skill.sh`. If a hook fails to fire in your session, run `/hooks` once (or restart) - the watcher only sees `.claude/settings.json` if it existed at session start. You can always also load a skill manually via the `Skill` tool.

Three more hooks live alongside it, all wired in the same `.claude/settings.json`:

- `session-start.sh` (`SessionStart`) - injects the workflow non-negotiables (read CONTRIBUTING first, the `<type>/<short-description>` branch convention, branch identity, force-push policy) into context before the first edit, since those rules have no edit to hang a skill load off. Surfaces the current branch and warns on harness-synthetic `claude/*` names or detached HEAD.
- `session-setup.sh` (`SessionStart`, web only) - a teller, not a doer: it surfaces the one fact the repo cannot supply - the web container's default `python` is 3.11, below pyproject's 3.12 floor, while a usable `python3.12` is present - and injects that plus the exact venv-build command as context, then leaves the build to you applying CONTRIBUTING "Before you commit". It deliberately does not provision the env: a hook that silently builds the venv trains dependence on the hook and contradicts CONTRIBUTING's venv steps wherever it does not fire. Gated on `$CLAUDE_CODE_REMOTE`, so a local contributor's environment is untouched.
- `git-guard.sh` (`PreToolUse:Bash`) - hard-denies destructive git history/branch operations (force-push, `push --delete`, colon-refspec push, `branch -D`, `reset --hard`, `clean -f`) unless there is explicit plain-words maintainer authorisation. The mechanical complement to `docs/git-workflow.md`'s force-push policy. Fails open on unexpected input.

### Runtime crew skills (CrewAI)

Skills the CrewAI agents see at execution time live next to the squad packages and are loaded via `crewai.skills`.

| Layout | Loaded by | Visible to |
|---|---|---|
| `squad/skills/<name>/SKILL.md` | `Crew(skills=[SQUAD_SKILLS_DIR])` in `crew.py` | every agent |
| `squad/<member>/skills/<name>/SKILL.md` | `Agent(skills=[member.skills_dir])` in `squad/__init__.py:build_agent` | that member only |

Authoring conventions (audience, voice, METADATA/INSTRUCTIONS layering, common contributor-perspective leaks): see the `cybersquad-skill` contributor skill, which auto-loads on edits to either path.

## Required MCP

- **Filesystem MCP** - configure `@modelcontextprotocol/server-filesystem` with this repo's absolute path in `claude_desktop_config.json`.
