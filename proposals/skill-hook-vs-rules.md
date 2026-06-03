# Spike: evaluate `.claude/rules/` as a (partial) replacement for the `load-skill.sh` skill-loading hook

Status: proposal, decision pending pilot.
Follows: #165 (contributor-tooling hooks).

This document is the captured background for a spike. It is intended to also
be filed as a GitHub issue; the issue can link here rather than duplicate the
content.

## Context

#165 added the contributor-tooling hooks (`session-start.sh`, `session-setup.sh`,
`git-guard.sh`) and documented the pre-existing `load-skill.sh` `PreToolUse`
hook, which auto-loads the matching `.claude/skills/<name>/SKILL.md` on
`Write`/`Edit` to matching paths.

While documenting it we realised `.claude/rules/` - a first-party Claude Code
feature - does that same path-conditional instruction loading natively via
`paths:` frontmatter (docs:
https://code.claude.com/docs/en/memory , "Organize rules with .claude/rules/").
`load-skill.sh` is, in effect, a hand-rolled version of it. This spike decides
whether to lean on the native feature.

## Question (time-boxed)

Can `.claude/rules/` with `paths:` frontmatter replace some or all of
`load-skill.sh`, and what (if anything) must stay bespoke?

## Background captured

### Load/unload model

The context window is append-only. Almost nothing "unloads" mid-session; the
only mid-session remover is compaction. So "unloaded" means either (a) never
loaded because the trigger never fired, or (b) summarised away by compaction.
Always-on sources (`CLAUDE.md`, SessionStart context) are typically
preserved/re-injected across compaction; one-off tool-injected blobs are the
most likely to be dropped.

### Mechanism comparison

| Mechanism | Unit that loads | Loaded (enters context) | "Unloaded" | Lifetime |
|---|---|---|---|---|
| `CLAUDE.md` (+ `@`-imports, `CLAUDE.local.md`) | whole file(s) | session start, unconditionally | never mid-session; only compaction (usually re-expanded) | sticky, whole session |
| `.claude/rules/` - no frontmatter | whole rule file | session start, unconditionally (merged with CLAUDE.md) | never mid-session | sticky, whole session |
| `.claude/rules/` - with `paths:` | whole rule file | first access to a file matching the glob (read/open/edit) | not loaded at all if no matching path is touched; once in, stays (not evicted on leaving the path) | from first match to session end |
| Native skill metadata (`name`+`description`) | frontmatter only | session start, unconditionally (model knows the skill exists) | never | sticky, whole session (cheap) |
| Native skill body (`SKILL.md` + bundled files) | full skill content | on invocation (model judges `description` relevant, or user/command invokes) | absent until invoked; stays after | from invocation to session end |
| `load-skill.sh` (the current hook) | full `SKILL.md` body | first `Write`/`Edit` to a path matching the hook's `case` globs (`PreToolUse`), once per session via sentinel | not injected until a matching edit; dedup blocks re-injection; once in, stays | from first matching edit to session end |
| SessionStart hooks (`session-start.sh`, `session-setup.sh`) | the `additionalContext` string | session start, and re-fired on resume/compact | never mid-session | sticky; re-injected across resume |

### Migration analysis

Migrates cleanly to `.claude/rules/` + `paths:`:

- The path -> instruction mapping itself (the bulk of what the hook does).
- The `in_tests` pre-classifier disappears: it exists only because bash `case`
  globs let `*` cross `/`, so `*/squad/*.py` over-matches `tests/squad/...`.
  Real glob semantics (`squad/**/*.py` vs `tests/**`) distinguish them natively.
- Per-session "load once" is free (no `$TMPDIR` sentinel bookkeeping).
- Dependency-free and cross-platform: no `bash`/`jq` requirement; works wherever
  Claude Code runs, including surfaces where the hook never fires.

What would be lost or change:

- Explicit stack ordering (the big one): the hook injects generic-then-specialist
  (`cybersquad-tool` before `cybersquad-pentest-tool`) so the specialist lands
  later and more prominently. Rules expose no documented prominence lever beyond
  filename sort; would need numeric prefixes (`10-`, `20-`) and verification that
  load order honours them.
- Trigger shifts from edit to access: the hook fires on `Write`/`Edit`; `paths:`
  rules also fire on read/open, so they load more eagerly. Arguably an
  improvement (`CLAUDE.md` notes the hook "fires on the first edit, which is too
  late to shape the approach"), but it is a behaviour change.
- The curated single-blob presentation (joined stack with `---` separators and a
  "first edit this session" header) goes away; rules load independently.

Verdict (pending pilot): likely a hybrid - move the mapping to `.claude/rules/`
with `paths:` (kills the bash glob hazard, the `jq`/`bash` dependency, and the
sentinel bookkeeping), then empirically test specialist prominence ordering. If
filename-ordered rules preserve it, retire the hook entirely; if not, keep a thin
hook for only the stacking cases.

### Unknowns to pin (do not assume)

1. Whether path-scoped rules re-trigger per access or load once, and their exact
   load ordering - not deeply documented; verify before relying on filename
   prefixes for prominence.
2. Whether rules survive compaction the way `CLAUDE.md` does (always-on rows do;
   conditional rules may behave closer to tool-injected blobs).

## Spike deliverable / acceptance criteria

- Pilot on one skill pair (`cybersquad-tool` + `cybersquad-pentest-tool`) against
  a pentest-probe path: express as path-scoped rules and observe load order,
  trigger timing, and whether specialist prominence is preserved.
- Pin the two unknowns above empirically.
- Update this proposal with a Decision: keep hook / full migration / hybrid.
- No production migration in this spike - decision + proposal only.

## Out of scope

- Runtime crew skills (`squad/skills/...`, `squad/<member>/skills/...`) -
  CrewAI-loaded, unaffected.
- The agent-eval / BDD track (separate work).
