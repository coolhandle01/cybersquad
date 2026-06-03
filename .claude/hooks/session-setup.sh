#!/usr/bin/env bash
#
# Claude Code SessionStart hook - dev environment bootstrap (web only).
#
# pyproject.toml requires Python >= 3.12, but the base Claude Code on the web
# container ships an older default `python` / `python3` (3.11). A fresh
# session therefore cannot `pip install -e ".[dev]"` against the system
# interpreter, and the CONTRIBUTING "Before you commit" CI parity stack
# (ruff / ruff format / mypy / pylint / pytest / bandit) is unavailable until
# a 3.12+ venv is built by hand - the exact yak-shave a contributor (human or
# AI) otherwise repeats every session.
#
# This hook builds that venv once, idempotently, and puts it first on PATH for
# the session via $CLAUDE_ENV_FILE, so `python` / `ruff` / `pytest` resolve to
# the 3.12 venv without rediscovering the interpreter problem.
#
# Web only: gated on $CLAUDE_CODE_REMOTE so a local contributor's own
# environment is never touched. Synchronous (no `{"async":true}`) so the deps
# are present before the first tool call - no race. The container caches its
# state after the hook completes, so the slow build runs at most once per
# container; resume / compact SessionStarts hit the warm fast path and just
# re-export PATH.
#
# Wired via .claude/settings.json. Never blocks session start - any failure
# exits 0 and the contributor falls back to the manual CONTRIBUTING venv steps.
#
set -uo pipefail
trap 'exit 0' ERR

# Local contributors manage their own environment; only bootstrap the
# ephemeral web container.
[ "${CLAUDE_CODE_REMOTE:-}" = "true" ] || exit 0

repo_root="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$repo_root" || exit 0

venv=".venv"
venv_py="$venv/bin/python"
venv_bin_abs="$repo_root/$venv/bin"

# True if $1 is a python interpreter satisfying pyproject's >=3.12 floor.
_is_py312() {
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null
}

# Put the venv first on PATH for every subsequent command this session.
_persist_path() {
    [ -n "${CLAUDE_ENV_FILE:-}" ] || return 0
    printf 'export PATH="%s:$PATH"\n' "$venv_bin_abs" >>"$CLAUDE_ENV_FILE"
}

# Best-effort SessionStart context note; never fatal, silent without jq.
_emit() {
    command -v jq >/dev/null 2>&1 || return 0
    jq -n --arg c "$1" \
        '{hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:$c}}' 2>/dev/null || true
}

# Fast path: a usable venv already exists (warm container / resume / compact).
if [ -x "$venv_py" ] && _is_py312 "$venv_py"; then
    _persist_path
    _emit "Dev venv ready at .venv ($("$venv_py" --version 2>&1)); it is first on PATH, so python / ruff / mypy / pylint / pytest / bandit resolve to it. Run the CONTRIBUTING 'Before you commit' stack directly."
    exit 0
fi

# Slow path: find a >=3.12 interpreter and build the venv. Prefer 3.12 to
# match the CI pin (.github/workflows/ci.yml uses python-version "3.12"), so
# a local pass is a CI pass - then fall back to any newer 3.x, then the
# generic names.
py=""
for cand in python3.12 python3.13 python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && _is_py312 "$cand"; then
        py="$cand"
        break
    fi
done

if [ -z "$py" ]; then
    _emit "No Python >=3.12 found on PATH; could not bootstrap the venv. pyproject requires 3.12+ - build it manually per CONTRIBUTING 'Before you commit' before running the CI stack."
    exit 0
fi

"$py" -m venv "$venv" || exit 0
"$venv_py" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
if "$venv_py" -m pip install --quiet -e ".[dev]" >/dev/null 2>&1; then
    _persist_path
    _emit "Bootstrapped .venv with $("$venv_py" --version 2>&1) and installed .[dev]; it is first on PATH. The CONTRIBUTING 'Before you commit' stack (ruff / ruff format / mypy / pylint / pytest / bandit) is ready."
else
    _emit "Created .venv but 'pip install -e .[dev]' failed; install manually per CONTRIBUTING 'Before you commit'."
fi
exit 0
