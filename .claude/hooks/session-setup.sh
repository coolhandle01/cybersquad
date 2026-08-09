#!/usr/bin/env bash
#
# Claude Code SessionStart hook - dev environment guidance (web only).
#
# pyproject.toml requires Python >= 3.12, but the base Claude Code on the web
# container ships an older default `python` / `python3` (3.11), while a usable
# `python3.12` is present under another name. That mismatch is the one fact a
# contributor (human or AI) cannot know from the repo alone - everything after
# it (build a venv from pyproject, install `.[dev]`, run the CI parity stack)
# is knowledge CONTRIBUTING already carries.
#
# So this hook is a teller, not a doer: it surfaces the interpreter mismatch
# and the exact venv-build command as SessionStart context, then leaves the
# build to the contributor applying CONTRIBUTING "Before you commit". It does
# NOT create the venv. A hook that silently provisions the environment trains
# dependence on the hook and contradicts CONTRIBUTING's venv steps on every
# surface where the hook does not fire (local checkout, other harness, CI
# debugging) - so the build stays applied knowledge, not automation.
#
# Web only: gated on $CLAUDE_CODE_REMOTE so a local contributor's environment
# is never touched. Never blocks session start - any failure exits 0.
#
# Wired via .claude/settings.json.
#
set -uo pipefail
trap 'exit 0' ERR

# Local contributors manage their own environment; only advise inside the
# ephemeral web container.
[ "${CLAUDE_CODE_REMOTE:-}" = "true" ] || exit 0

repo_root="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$repo_root" || exit 0

venv=".venv"
venv_py="$venv/bin/python"

# True if $1 is a python interpreter satisfying pyproject's >=3.12 floor.
_is_py312() {
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null
}

# Best-effort SessionStart context note; never fatal, silent without jq.
_emit() {
    command -v jq >/dev/null 2>&1 || return 0
    jq -n --arg c "$1" \
        '{hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:$c}}' 2>/dev/null || true
}

# Warm path: a usable venv already exists (the contributor built it earlier in
# this container; resume / compact land here). Just point at it.
if [ -x "$venv_py" ] && _is_py312 "$venv_py"; then
    _emit "Dev venv present at .venv ($("$venv_py" --version 2>&1)). Run the CONTRIBUTING 'Before you commit' stack via the .venv/bin/ tools (e.g. .venv/bin/ruff check .)."
    exit 0
fi

# No venv yet. Find a >=3.12 interpreter to name in the guidance. Prefer 3.12
# to match the CI pin (.github/workflows/ci.yml uses python-version "3.12"), so
# a local pass is a CI pass - then any newer 3.x, then the generic names.
py=""
for cand in python3.12 python3.13 python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && _is_py312 "$cand"; then
        py="$cand"
        break
    fi
done

if [ -z "$py" ]; then
    _emit "No Python >=3.12 on PATH; pyproject requires 3.12+. Locate or install a 3.12 interpreter, then build the venv per CONTRIBUTING 'Before you commit' before running the CI stack."
    exit 0
fi

# Only speak when the *default* interpreter is below the 3.12 floor - that
# container mismatch is the one fact the repo cannot supply. When the default
# already satisfies 3.12, building the venv is plain CONTRIBUTING knowledge, so
# the hook stays silent rather than nag.
if _is_py312 python || _is_py312 python3; then
    exit 0
fi

default_ver="$(python --version 2>&1 || python3 --version 2>&1 || echo 'unknown')"
_emit "Container Python note: the default 'python' is $default_ver, below pyproject's 3.12 floor, but '$py' ($("$py" --version 2>&1)) satisfies it. Per CONTRIBUTING 'Before you commit', build the dev venv with that interpreter before running the CI stack: $py -m venv .venv && .venv/bin/pip install -e \".[dev]\". Then invoke the tools as .venv/bin/ruff, .venv/bin/pytest, etc."
exit 0
