---
name: cybersquad-runtime
description: Edit `runtime.py` (or any code that binds pipeline-scoped state - `run_id`, `programme_handle`) with care for the single-pipeline-at-a-time invariant. The binders (`bind_run_id` / `bind_programme`) are the canary for the #128 Flow refactor; do not paper over their bind-conflict raise. Load before editing `runtime.py` or `main.py`.
---

# cybersquad runtime hygiene

`runtime.py` carries pipeline-scoped context every downstream tool reads: `run_id` (set by `main.py`) and `programme_handle` (set by the PM's `Save Selected Programme`). Two module-level strings, set once per process, read by ~5 callers. The contract is small and load-bearing.

## The single-pipeline-at-a-time invariant

`bind_run_id(...)` and `bind_programme(...)` are the only blessed setters. Each raises on a *conflicting* rebind (different value) and no-ops on same-value rebind (so retries and idempotent test setup do not fail).

```python
# correct - production setter
runtime.bind_programme(handle)

# wrong - bypasses the conflict guard
runtime.programme_handle = handle
```

Reads stay on the module attribute (`runtime.programme_handle`, `runtime.run_id`) - the binders enforce write discipline, the reads do not need to change.

## Anti-patterns

- Direct assignment to `runtime.programme_handle` or `runtime.run_id` in production code. Use `bind_programme` / `bind_run_id`. The cybersquad-tool skill carries the matching anti-pattern entry for tool wrappers.
- A new pipeline-scoped singleton at module level *without* a `bind_<name>(...)` setter that mirrors the conflict-detection shape. If the value is set once and read everywhere, it is workspace state and gets a binder.
- Catching the bind-conflict `RuntimeError` to silently overwrite. That `raise` is the canary for the #128 Flow refactor (parallel sub-flows wanting different `(handle, run_id)` pairs). If it fires in earnest, the answer is per-context state (contextvars / `PipelineContext` threaded via the CrewAI input dict), not a swallow.
- Removing the `FIXME #128` from the module docstring. It is the discoverable record of *why* the binders are written as they are.

## Adding a new pipeline-scoped singleton

If the runtime needs to carry another value through the pipeline (e.g. an OOB callback URL when `#77` lands real interactsh infrastructure):

```python
oob_callback: str = ""

def bind_oob_callback(callback: str) -> None:
    """Bind the OOB callback URL for this process.

    Raises ``RuntimeError`` if a different callback is already bound -
    the single-pipeline-at-a-time invariant. Same-value rebind is a
    no-op. See module docstring + #128 for the Flow-era replacement.
    """
    global oob_callback  # noqa: PLW0603 - module-level singleton, documented in module docstring
    if oob_callback and oob_callback != callback:
        raise RuntimeError(
            f"runtime.oob_callback already bound to {oob_callback!r}; "
            f"refusing to rebind to {callback!r}. "
            "Single-pipeline-at-a-time invariant - see #128."
        )
    oob_callback = callback
```

The shape is mechanical - mirror it for every new singleton so the conflict-detection behaviour is uniform.

## Test contract

`tests/fixtures/programme.py` carries:

- `run_dir` - points `runtime.run_dir()` at the test's `tmp_path` and returns the `Path`. Take this instead of patching `runtime.run_dir` at every consumer's import alias.
- `programme_in_workspace` / `dvwa_in_workspace` - stage `programme.json` into the rundir and monkeypatch `runtime.programme_handle`. Composes on top of `run_dir`.

### Tests bypass the binders by design

Production code writes pipeline-scoped state via `bind_programme(...)` / `bind_run_id(...)`. **Tests do not.** Fixtures and individual test cases write `runtime.programme_handle` (and the other singletons) via `monkeypatch.setattr("runtime.programme_handle", ...)` directly.

This is deliberate, not a workaround:

- The bind-conflict guard would fire on the *second* test that wanted a different programme (because the first test bound the value, and the guard does not know test-isolation semantics). `monkeypatch.setattr` writes the module attribute directly, and the auto-reset between tests restores the prior value cleanly.
- The same applies inside a single test that wants to flip the in-flight programme to exercise a "different programme" branch - the guard would refuse the second bind; `monkeypatch.setattr` does not.
- The invariant itself (same-value no-op, conflicting raise) is covered by dedicated tests in `tests/test_runtime.py`. Those tests **do** call `bind_*` because that is what they are pinning.

If you write a new fixture or test that needs to set a runtime singleton, take this shape:

```python
# correct
monkeypatch.setattr("runtime.programme_handle", "acme")

# wrong - the bind-conflict guard will trip the second time this runs
runtime.bind_programme("acme")
```

### Adding tests for a new singleton

If you add a new singleton + binder, add a test class to `tests/test_runtime.py` covering:

- `bind_<name>` sets the attribute when unset
- Same-value rebind is a no-op
- Conflicting rebind raises with the `#128` marker in the message

The marker assertion is load-bearing - it is how grep finds every conflict guard at once when the Flow refactor lands.

## Why this is narrow

The consumer-side rule ("`import runtime`, never `from runtime import run_dir`") that keeps `monkeypatch.setattr("runtime.run_dir", ...)` propagating to every consumer lives in `cybersquad-tool` because it applies to tool authors, not runtime authors. This skill stays focused on the runtime module itself.
