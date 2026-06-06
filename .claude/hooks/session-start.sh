#!/usr/bin/env bash
#
# Claude Code SessionStart hook.
#
# Injects the cybersquad workflow-discipline reminders into context at the
# top of every session, BEFORE the first edit. The contributor skills under
# .claude/skills/ auto-load on the first matching Write/Edit, which CLAUDE.md
# notes is "too late - by then you have already chosen an approach". The
# sequencing rules (read CONTRIBUTING.md first), the branch-naming convention,
# and the branch-identity rule have no edit to hang off, so they live here:
# emitted once at session start via hookSpecificOutput.additionalContext.
#
# Also surfaces the current branch and flags it when it looks like a
# harness-synthetic name (claude/*) or a detached HEAD - the exact failure
# mode docs/git-workflow.md "Branch identity" is closing.
#
# Wired via .claude/settings.json. Never blocks session start - any
# unexpected condition exits 0 with no output.
#
set -uo pipefail

# Bail quietly on anything unexpected - this hook must never wedge startup.
trap 'exit 0' ERR

# Current branch, best-effort. Empty string on detached HEAD or non-repo.
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")

branch_note=""
case "$branch" in
    claude/*)
        branch_note="WARNING: current branch '$branch' is a harness-synthetic name. The repo convention is <type>/<short-description> (see docs/git-workflow.md), and a branch ruleset blocks pushing claude/* names. If a real PR branch exists for this work, switch to it and surface the mismatch before editing."
        ;;
    HEAD|"")
        branch_note="NOTE: detached HEAD or no branch resolved. Establish the correct PR/feature branch before committing."
        ;;
    *)
        branch_note="Current branch: $branch"
        ;;
esac

read -r -d '' body <<EOF || true
cybersquad workflow reminders (injected at session start - read before your first edit):

- CONTRIBUTING.md is the canonical contributor surface. Read it first; it carries the ASCII-only rule, the minimal-diff rule, the "Before you commit" CI parity stack (ruff / ruff format / mypy / pylint / pytest / bandit, run inside a .venv), and links the rest (docs/git-workflow.md, docs/testing.md, and the skill catalogue in CLAUDE.md).

- Map the issue to its touchpoints and read only the relevant skill(s) + docs/ entry at scoping time. The .claude/skills/ hook fires on the first edit, which is too late to shape the approach.

- Branch naming: <type>/<short-description> (feat/, fix/, docs/, refactor/, chore/, ...). See docs/git-workflow.md. Do NOT push claude/* or other harness-synthetic branch names - a branch ruleset blocks them.

- Branch identity: when a PR exists, its head branch is the canonical workspace. If a harness placed you on a synthetic branch while a real PR branch exists for the same work, switch to the PR branch and surface the mismatch before making changes.

- Never force-push, git push --delete, or git branch -D a shared/PR branch without an explicit plain-words maintainer authorisation in the immediately preceding message. --force-with-lease is no exception. Vented frustration ("just force it then") is not authorisation.

$branch_note
EOF

jq -n --arg content "$body" '
    {
        hookSpecificOutput: {
            hookEventName: "SessionStart",
            additionalContext: $content
        }
    }
'

exit 0
