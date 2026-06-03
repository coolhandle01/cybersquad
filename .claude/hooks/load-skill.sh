#!/usr/bin/env bash
#
# Claude Code PreToolUse hook for Write|Edit.
#
# Maps the target file path to a stack of cybersquad skills and injects each
# matched skill's SKILL.md content into the model context via
# hookSpecificOutput.additionalContext - effectively auto-loading the relevant
# skills before each edit.
#
# Stacking: a path may match more than one skill (e.g. a pentest probe wrapper
# matches both the generic cybersquad-tool and the specialist
# cybersquad-pentest-tool). Generic skills are matched first and specialists
# layer on top, so the specialist appears later in the context window.
#
# Session-scoped sentinel: each skill is injected at most once per session, on
# the first matching Edit/Write. Subsequent edits in the same session are silent
# for skills that have already loaded.
#
# Wired via .claude/settings.json. Silently noops if jq is missing or the
# expected stdin shape is absent - never blocks the edit.
#
set -uo pipefail

# Bail quietly on anything unexpected - this hook must never break a tool call.
trap 'exit 0' ERR

command -v jq >/dev/null 2>&1 || exit 0

input=$(cat)
file_path=$(echo "$input" | jq -r '.tool_input.file_path // ""')
session_id=$(echo "$input" | jq -r '.session_id // ""')

[ -z "$file_path" ] && exit 0
[ -z "$session_id" ] && exit 0

# Repo-root anchor: hook runs from project cwd; resolve skill paths against it.
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
skills_root="$repo_root/.claude/skills"
state_dir="${TMPDIR:-/tmp}/cybersquad-skills-$session_id"
mkdir -p "$state_dir"

# Build the matched-skill stack. Generic matchers come first; specialists
# layer on top. Each branch is independent so a path can match more than one.
matches=()

# Pre-classify: paths under tests/ get the tests skills, never the
# wrapper-author ones. `*` crosses `/` in case patterns, so without
# this guard ``*/squad/*.py`` over-matches the ``tests/squad/<member>/``
# mirror dirs and pulls cybersquad-tool / cybersquad-pentest-tool
# into test edits where they do not apply.
case "$file_path" in
    */tests/*) in_tests=1 ;;
    *)         in_tests=0 ;;
esac

# Tool wrappers - generic -> specialist stacks so the specialist
# appears later (more prominent) in context.
#
# cybersquad-tool covers any Python file under squad/ at any depth -
# the catch-all pattern matches the wrapper files under
# squad/<member>/tools/**/*.py (including probes/, cloud/) alongside the
# member __init__.py files and the squad/tools/ shared layer. Decorator
# implementation files (_decorator.py) are inclusive false positives:
# they implement the conventions the skill enforces, so loading is
# appropriate rather than noisy.
if [ "$in_tests" = 0 ]; then
    case "$file_path" in
        */squad/*.py)
            matches+=(cybersquad-tool)
            ;;
    esac
    # cybersquad-pentest-tool covers the @pentest_tool wrapper surface
    # (squad/penetration_tester/tools/probes/) and its check_X helper
    # layer (tools/pentest/). Cloud wrappers use @cyber_tool, not
    # @pentest_tool, so they correctly stay on the universal skill only.
    case "$file_path" in
        */tools/pentest/*.py \
        |*/squad/penetration_tester/__init__.py \
        |*/squad/penetration_tester/tools/_decorator.py \
        |*/squad/penetration_tester/tools/probes/*.py)
            matches+=(cybersquad-pentest-tool)
            ;;
    esac
    # cybersquad-prompteng stacks on cybersquad-tool with the
    # communication layer - docstring-vs-Field division of labour,
    # what to say in each, what NOT to say twice. Same trigger
    # surface as cybersquad-tool so wrapper edits load mechanics +
    # communication side by side, specialist last.
    case "$file_path" in
        */squad/*.py)
            matches+=(cybersquad-prompteng)
            ;;
    esac
fi

# cybersquad-models covers the LLM-facing schema layer - typed primitives,
# workspace artefact shapes, args_schema return models. Triggers on any
# Python file under models/ at any depth.
case "$file_path" in
    */models/*.py)
        matches+=(cybersquad-models)
        ;;
esac

# cybersquad-oam stacks on cybersquad-models for the OAM asset layer - the
# asset / property / relation shapes under models/asset/ that implement
# OWASP amass's Open Asset Model. Generic model rules load first; the OAM
# specialist (faithful-to-amass, OAM-names-win, properties-as-annotations)
# layers on top. No in_tests guard, matching cybersquad-models: the OAM
# contract is relevant when testing the asset shapes too.
case "$file_path" in
    */models/asset/*.py)
        matches+=(cybersquad-oam)
        ;;
esac

# Pipeline plumbing - one skill per file; no stacking.
case "$file_path" in
    */runtime.py|*/main.py)
        matches+=(cybersquad-runtime)
        ;;
esac
case "$file_path" in
    */crew.py)
        matches+=(cybersquad-agent-llm)
        ;;
esac
# cybersquad-mcp covers the MCP provisioning discipline - the
# build-time wiring rule and the disjoint-set rule for provisioned
# vs. discovered MCPs. Triggers on any file in the provisioning
# package (which holds the orchestrator + one submodule per MCP),
# and stacks on crew.py edits because crew.py is where the
# provisioned-tool list is distributed to agents.
case "$file_path" in
    */mcp_servers/*.py|*/crew.py)
        matches+=(cybersquad-mcp)
        ;;
esac
case "$file_path" in
    */tasks.py)
        matches+=(cybersquad-task)
        ;;
esac

# Tests - generic -> specialist stacks so BDD-specific guidance lands
# on top of the shared-fixture catalogue for BDD edits.
case "$file_path" in
    */tests/*)
        matches+=(cybersquad-test-fixtures)
        ;;
esac
case "$file_path" in
    */tests/features/*|*/tests/bdd/*)
        matches+=(cybersquad-bdd)
        ;;
esac

# Agent-facing prose (runtime CrewAI sees these, not Claude).
case "$file_path" in
    */squad/skills/*/SKILL.md \
    |*/squad/*/skills/*/SKILL.md \
    |*/squad/*/role.md \
    |*/squad/*/goal.md \
    |*/squad/*/backstory.md \
    |*/squad/*/*/description.md \
    |*/squad/*/*/expected_output.md)
        matches+=(cybersquad-skill)
        ;;
esac

[ "${#matches[@]}" -eq 0 ] && exit 0

# Emit each matched skill once per session, joined into a single
# additionalContext blob in stack order (generic first, specialist on top).
combined=""
for skill_name in "${matches[@]}"; do
    sentinel="$state_dir/$skill_name"
    [ -f "$sentinel" ] && continue

    skill_path="$skills_root/$skill_name/SKILL.md"
    [ -f "$skill_path" ] || continue

    touch "$sentinel"
    content=$(cat "$skill_path")
    header="Auto-loading skill $skill_name (matched on file path; this is its first edit this session)."
    if [ -n "$combined" ]; then
        combined="$combined"$'\n\n---\n\n'
    fi
    combined="${combined}${header}"$'\n\n'"${content}"
done

[ -z "$combined" ] && exit 0

jq -n --arg content "$combined" '
    {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            additionalContext: $content
        }
    }
'

exit 0
