#!/usr/bin/env bash
# QA helper (break-glass): refresh the locally-installed crewui to the current
# head of its break-glass branch, so new crewui work shows up in this venv
# without re-resolving everything.
#
# Why this is needed: the #166 crewui pin is a git *branch* ref
# (crewui @ git+...@feat/review-gate-ux). pip treats an already-installed build
# as satisfying that ref, so a plain `pip install -e .` will NOT re-fetch the
# branch. This forces *just* crewui to rebuild from the branch head.
#
# Remove this alongside the break-glass pin when crewui is back on a PyPI pin.
#
# Usage (from the repo root):
#   ./scripts/bump-crewui-git-pin.sh            # default branch feat/review-gate-ux
#   ./scripts/bump-crewui-git-pin.sh some-branch
#   PIP=/path/to/venv/bin/pip ./scripts/bump-crewui-git-pin.sh
set -euo pipefail

BRANCH="${1:-feat/review-gate-ux}"
PIP="${PIP:-.venv/bin/pip}"

if [ ! -x "${PIP}" ]; then
  echo "pip not found at '${PIP}'. Run from the repo root, or set PIP=..." >&2
  exit 1
fi

echo ">> refreshing crewui from coolhandle01/crewui@${BRANCH}"
"${PIP}" install --force-reinstall --no-deps \
  "crewui @ git+https://github.com/coolhandle01/crewui@${BRANCH}"

echo ">> now installed:"
"${PIP}" show crewui | grep -E '^(Name|Version)'
