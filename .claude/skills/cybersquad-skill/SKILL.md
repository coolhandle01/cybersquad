---
name: cybersquad-skill
description: Markdown under squad/ is read by the runtime CrewAI agent, not by you. No codebase paths, no Python vocabulary, no framework meta. Load before editing.
---

# Runtime agent prose

The markdown files under `squad/` that the agent reads at execution
time - SKILL.md files (squad-wide under `squad/skills/<name>/` and
member-specialist under `squad/<member>/skills/<name>/`), per-member
`role.md` / `goal.md` / `backstory.md`, and per-task
`description.md` / `expected_output.md` - are loaded into a CrewAI
agent's context, not yours. The agent's perspective is narrower than
yours, and prose that drifts into your perspective wastes its
context or misleads it.

## METADATA vs INSTRUCTIONS (SKILL.md only)

Each SKILL.md has two layers the agent sees differently:

- **METADATA** (the frontmatter `name` and `description`) is loaded
  into a menu of available skills the agent sees every turn. Cheap,
  always visible.
- **INSTRUCTIONS** (the body) is promoted into the agent's system
  prompt only when the agent activates the skill. Per-turn cost
  once activated.

The `description` is the menu entry the agent picks from. Phrase it
as the operational context where the skill applies, not as repo-meta:

- Good: "How the Programme Manager reads a HackerOne programme's
  policy_text - the conservative posture and how to handle silence."
- Bad: "Restates the cybersquad's hard scope rules in language every
  agent must operate under."

The other prose files (`role.md`, `goal.md`, `backstory.md`,
`description.md`, `expected_output.md`) have no progressive disclosure
- they are always in the agent's context for the relevant task. Same
voice rules apply.

## What the agent knows

Examples below are PM-flavored. Other squad members know analogous
things relevant to their role - probe results and evidence for the
Penetration Tester, recon artefacts for the OSINT Analyst, draft
reports for the Technical Author, submission state for the
Disclosure Coordinator.

- HackerOne API concepts: programmes, scope items, `policy_text`,
  `bounty_table`, `asset_type`, `in_scope`, `eligible_for_bounty`,
  `state`, `accepts_new_reports`, `triage_active`, `max_severity`,
  `authorisation_basis`, `selection_rationale`.
- The other squad members by role (Programme Manager, OSINT Analyst,
  Penetration Tester, Vulnerability Researcher, Technical Author,
  Disclosure Coordinator) and their handoff artefacts.
- Its own `@tool` functions by name and docstring.
- The operator - a real person who receives surfaced concerns.

## What the agent does not know

- This repository's name, layout, or any file path within it.
  References like `tools/recon/scope.py` mean nothing to the agent -
  it does not navigate the source tree.
- That it is implemented in Python. Avoid "predicate", "function",
  "method", "class", "module", "callable", "dict", "JSON", "hook",
  "callback", "downstream code".
- Software-architecture jargon for the squad as a whole. Avoid
  framework terms like "pipeline", "orchestration", "DAG", "stage"
  when naming the squad's structure. The agent's mental model is:
  it is part of a squad whose members run in order. Plain English
  for steps within the agent's own task ("your workflow per finding",
  "next step", "first do X") is fine - what is not fine is calling
  the squad's structure a pipeline.
- The contributor-side skill loader, `.claude/`, or any Claude Code
  concept. The skills the agent sees are the ones we provision via
  `Crew(skills=...)` and `Agent(skills=...)`. They need no qualifier
  like "the CrewAI skills", "the runtime skills", or "the crew skill"
  - to the agent they are just skills.
- That there is enforcement code beneath it. Telling the agent
  "this is enforced in code, you cannot relax it" implies the agent
  could try - it cannot, and saying so wastes context.
- The output contract. The shape of `selection_rationale`,
  `authorisation_basis`, the per-task output schema - those live in
  `expected_output.md`. Do not restate them in a SKILL.md; the skill
  teaches reasoning, the expected output specifies the artefact.

## Voice

- Address the agent as "you". The body is instruction, not
  description.
- Operational vocabulary only. If a sentence only makes sense to
  someone who has read your code, rewrite it.
- Other squad members can be named by role ("the Programme Manager
  records `authorisation_basis`") - the agent knows who runs before
  it and who runs after.

## Common leaks

Real bad-good pairs from runtime prose shipped under this skill:

- Bad: "This skill is a restatement of the safety invariants
  enforced in code (`tools/recon/scope.py` and the H1 programme-
  detail loader)." Filesystem reference plus meta-framing about what
  skills do.
- Bad: "You are the gate, not a Python predicate downstream of you."
  Programming concept leak. Good: "You are the gate. No other squad
  member will catch this if you miss it."
- Bad: "...nothing further down the pipeline will." Architecture
  jargon. Good: "...no other squad member will." (Same leak in three
  files before this skill was tightened.)
- Bad: "the detail a downstream tester would need", "the downstream
  VR consumes this directly". "Downstream" frames the squad as a
  pipeline even when the role beside it is named correctly - the same
  pipeline-jargon leak wearing a role name. Naming the member is
  right; the directional qualifier is the leak. Good: "the detail the
  Penetration Tester would need", "the Vulnerability Researcher
  consumes this directly." (Five instances across the OSINT Analyst's
  backstory / description / expected_output before this skill was
  tightened.)
- Bad: "the scope-discipline crew skill is the final word." The
  qualifier "crew" is framework-side; the agent sees one class of
  skill. Good: "the scope-discipline skill is the final word."
- Bad: "Restates the cybersquad's hard scope and authorisation rules
  in language every agent must operate under." Repo name plus
  meta-framing.
- Bad: A SKILL.md section titled "Recording the basis" that restates
  what `expected_output.md` already specifies for `authorisation_basis`.
  Two contracts for the same field is one place to drift.

The pattern across these: contributor-perspective phrasing where
operational phrasing was needed, or skill-side content that belonged
in `expected_output.md`.

## When this skill fires

Auto-loads on edits to any agent-facing markdown under `squad/`:

- `squad/skills/<name>/SKILL.md` (squad-wide skills)
- `squad/<member>/skills/<name>/SKILL.md` (member specialist skills)
- `squad/<member>/role.md`, `goal.md`, `backstory.md` (per-member identity)
- `squad/<member>/<task>/description.md`, `expected_output.md` (per-task instructions and output contract)

All five file types share the same audience (the CrewAI agent at
execution time) and the same voice rules.

## Upstream alignment

Frontmatter mechanics (`name`, `description`, lowercase alphanumeric
+ hyphens, description-as-trigger) follow Anthropic's `skill-creator`
contract. See [anthropics/skills `skill-creator`](https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md).

For CrewAI's own framework on the prose layer the runtime SKILL.md
complements - role-goal-backstory construction, task descriptions
and expected outputs, agent capability tuning - see
[crewAIInc/skills `design-agent`](https://github.com/crewAIInc/skills/blob/main/skills/design-agent/SKILL.md)
and [`design-task`](https://github.com/crewAIInc/skills/blob/main/skills/design-task/SKILL.md).
Those are the upstream canonicals. This skill is the cybersquad-
specific overlay - the leaks named above are the ones we have
actually shipped, not theoretical risks.

cybersquad runtime skills are progressive-disclosure markdown only -
no `scripts/` or `references/` directories. Revisit if the tools
layer stabilises and an executable-skill use case appears.
