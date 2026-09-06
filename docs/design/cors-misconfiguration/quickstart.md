# Quickstart: validate the CORS Misconfiguration Probe

Prerequisites: dev extras installed (`pip install -e ".[dev]"`) in a Python 3.12 venv.

## Run the probe's tests

```sh
pytest -m unit tests/tools/pentest/test_cors.py -q
```

Expected: all pass, no socket warnings (the unit tier runs with `--disable-socket`).

## What the tests prove (oracles)

- Each variant emits its exact `Origin` header (`https://<canary>` / `null`) with
  `allow_redirects=False` - asserted from captured request args, not a stub's return.
- Reflected origin + `ACAC: true` -> one `HIGH` finding; reflected origin without
  credentials -> one `LOW`; `ACAO: *` -> one `INFORMATIONAL`.
- No `ACAO`, and a *different* reflected origin -> no finding.
- `null_origin` + credentials -> `HIGH`; without -> `LOW`.
- Precedence: an endpoint that elicits a credentialed reflection is reported `HIGH`
  even when a lower-tier signal is also present (one emitted finding, `severity_hint`
  asserted).
- Evidence carries the probed `Origin`, `ACAO`, `ACAC`, and status; LOW/INFORMATIONAL
  findings carry the chain-vector note.

## Full parity (before commit)

```sh
ruff check . && ruff format --check . && mypy . --ignore-missing-imports && pylint . && pytest -m unit -q
```
