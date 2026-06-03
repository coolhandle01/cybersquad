# cybersquad - AI Contributor Guide

**Read `CONTRIBUTING.md` first.** It carries the universal rules (ASCII only, minimal diff, preserve names and comments, linter findings as signal, FIXME/TODO grammar, surface concerns), the `Before you commit` CI parity stack, and the safety invariants. Everything below is AI-contributor-specific layered on top.

## Before you start work on an issue

The contributor skills below auto-load on the first matching edit, which is too late - by then you have already chosen an approach. Read the relevant skill at issue-scoping time so the conventions are in your head while you are still deciding what to build.

Then ask: what canonical knowledge will this issue produce that does not yet live in a skill? Update the skill **first** - or at least sketch the update in this conversation - so the work that follows is the skill being applied, not the skill being discovered. By the time the code lands the skill update is part of the same PR, written by an expert against captured intent rather than documented after the fact.

## Commit messages

Never include session URLs (`https://claude.ai/code/session_...`) in commit messages or PR bodies. They reference private conversations.

## Skills

Two skill systems run in this repo. They do not interact - one targets the
contributor (you, editing code), the other targets the runtime crew (agents
executing the pipeline).

### Contributor skills (Claude Code)

Skills under `.claude/skills/` auto-load via a `PreToolUse` hook on `Write`/`Edit` configured in `.claude/settings.json`. The relevant skill's full `SKILL.md` is injected into context on the first matching edit per session, deduplicated so repeated edits to the same scope are silent.

| Skill | Triggers on |
|---|---|
| `cybersquad-tool` | Any `*.py` file under `squad/` at any depth - member `__init__.py`s, sub-package wrappers under `probes/` and `cloud/`, the `recon.py` / `findings.py` / `research.py` / `triage.py` / `curation.py` / `discovery.py` modules, and the `workspace_tools.py` shared layer. Guarded out of the `tests/squad/` mirror so test edits do not over-trigger. |
| `cybersquad-pentest-tool` | `tools/pentest/**` and the `@pentest_tool` wrapper surface: `squad/penetration_tester/__init__.py`, `squad/penetration_tester/_decorator.py`, `squad/penetration_tester/probes/**`. Cloud wrappers use `@cyber_tool` (not `@pentest_tool`) so they stack on the universal skill only. |
| `cybersquad-prompteng` | Same trigger as `cybersquad-tool` (`*/squad/*.py`). Carries the *communication* layer - the two LLM-visible surfaces (tool docstring + `Field(description=...)`), the division of labour between them, what to say in each, what NOT to say twice. Specialist after `cybersquad-tool` (mechanics) so the communication rules land more prominently. |
| `cybersquad-models` | Any `*.py` file under `models/`. Carries the LLM-facing contract: typed primitives, workspace artefact shapes, prompt-injection awareness on free-text fields. The consumer-side rules (how a wrapper *uses* these models) live in `cybersquad-tool`. |
| `cybersquad-oam` | Any `*.py` file under `models/asset/`. Stacks on `cybersquad-models` (specialist last). The OWASP Open Asset Model vocabulary the asset package implements: assets as typed nodes, relations as typed edges, properties hung off assets, the faithful-to-amass mapping, the OAM-names-win naming rule, and provenance stamping. Points to `docs/academic-grounding.md` for the longer-form grounding. |
| `cybersquad-runtime` | `runtime.py`, `main.py` |
| `cybersquad-agent-llm` | `crew.py` |
| `cybersquad-mcp` | Any file under `mcp_servers/` (the package with the orchestrator + one submodule per MCP), plus stacks on `crew.py` where the provisioned-MCP tool list is distributed to agents. Carries the threat-model rules from #144: build-time provisioning only, no runtime attach, disjoint sets for provisioned vs. discovered MCPs, explicit tool allowlist, audit log. |
| `cybersquad-task` | `tasks.py` |
| `cybersquad-test-fixtures` | Any file under `tests/` (including the `tests/squad/` mirror) |
| `cybersquad-bdd` | `tests/features/**` or `tests/bdd/**` |
| `cybersquad-skill` | Any agent-facing markdown under `squad/`: `squad/skills/<name>/SKILL.md`, `squad/<member>/skills/<name>/SKILL.md`, `squad/<member>/role.md`/`goal.md`/`backstory.md`, `squad/<member>/<task>/description.md`/`expected_output.md` |

Grouped by concern: tool wrappers, pipeline plumbing, tests, agent-facing prose. Where two skills can match the same file (tool + pentest-tool on a probe; models + oam on an asset model; test-fixtures + bdd on a BDD test) the specialist is loaded last so it lands more prominently in context. Editing `runtime.py` directly loads `cybersquad-runtime` only - consumer-side rules (the `import runtime` propagation property tests rely on) live in `cybersquad-tool` because that is the skill the tool author already sees.

The `in_tests` pre-classifier in the hook is load-bearing: `*` crosses `/` in bash case patterns, so without it `*/squad/*.py` would over-match `tests/squad/<member>/test_*.py` and pull the wrapper-author skills into test edits where they do not apply.

The hook is wired in `.claude/settings.json`; the matching logic lives in `.claude/hooks/load-skill.sh`. If a hook fails to fire in your session, run `/hooks` once (or restart) - the watcher only sees `.claude/settings.json` if it existed at session start. You can always also load a skill manually via the `Skill` tool.

### Runtime crew skills (CrewAI)

Skills the CrewAI agents see at execution time live next to the squad packages and are loaded via `crewai.skills`.

| Layout | Loaded by | Visible to |
|---|---|---|
| `squad/skills/<name>/SKILL.md` | `Crew(skills=[SQUAD_SKILLS_DIR])` in `crew.py` | every agent |
| `squad/<member>/skills/<name>/SKILL.md` | `Agent(skills=[member.skills_dir])` in `squad/__init__.py:build_agent` | that member only |

Authoring conventions (audience, voice, METADATA/INSTRUCTIONS layering, common contributor-perspective leaks): see the `cybersquad-skill` contributor skill, which auto-loads on edits to either path.

## Required MCP

- **Filesystem MCP** - configure `@modelcontextprotocol/server-filesystem` with this repo's absolute path in `claude_desktop_config.json`.
