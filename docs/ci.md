# CI

Three jobs run on every push: `lint` (ruff + mypy), `test` (pytest, 90% coverage floor + per-PR diff-cover ratchet), and `sast` (bandit + semgrep). The local commands in the pre-commit checklist in `CLAUDE.md` mirror them exactly - use those.

## Coverage gates

Two gates stack on every PR. Both must pass.

**Absolute floor** - `fail_under = 90` in `[tool.coverage.report]`. The whole-codebase coverage must stay at or above 90%. Catches large regressions; does not catch slow drift (a PR can drop coverage from 93.4% to 90.0% and still pass).

**Per-PR ratchet** - `diff-cover coverage.xml --compare-branch=origin/<base-ref> --fail-under=100`. Every line added or modified by the PR must be covered by tests. Catches slow drift one line at a time. Runs on `pull_request` events only - on `push` events the base ref is not necessarily known and the gate trivially passes. Configured via the "Diff coverage (per-PR ratchet)" step in `.github/workflows/ci.yml`.

To read a diff-cover failure: the step prints `<file> (NN%)` for each touched production file and a list of uncovered line numbers. Add a test that exercises those lines, or move the change behind a `# pragma: no cover` directive if the line is genuinely untestable (rare - prefer a test).

To run the per-PR gate locally before pushing (`diff-cover` is in the `[dev]` extras, so a fresh `pip install -e ".[dev]"` already has it):

```bash
.venv/bin/pytest -m unit --cov --cov-report=xml:coverage.xml
.venv/bin/diff-cover coverage.xml --compare-branch=origin/main --fail-under=100
```

## Notes on fixing findings

### ruff

`ruff check --fix` and `ruff format` resolve most issues automatically.

### mypy

Ensure all public functions have annotated parameters and return types. If a real dep (crewai, pydantic) has incomplete stubs and you need to suppress a false positive, use a targeted `# type: ignore[<code>]` rather than a blanket ignore.

### bandit

Suppress with `# nosec B<code>` (bandit's own directive, *not* `# noqa`). Keep the accompanying `# noqa: S<code>` for ruff - both are needed:

```python
os.getenv("FOO", "/tmp/bar")  # nosec B108  # noqa: S108
```

### GitHub Actions pins

Every action must be pinned to a full-length commit SHA, not a tag. Branch protection enforces this. Add the version as a trailing comment for readability:

```yaml
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4.3.1
```

### upload-artifact v4 and hidden files

`.coverage` and other dotfiles are skipped by default. Set `include-hidden-files: true` on the step.
