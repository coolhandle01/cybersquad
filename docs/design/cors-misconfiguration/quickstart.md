# Quickstart: CORS Misconfiguration Probe

Prerequisites: dev extras installed (`pip install -e ".[dev]"`) in a Python 3.12 venv.

## Run the probe's tests

```sh
pytest -m unit tests/tools/pentest/test_cors.py -q
```

Expected: all pass, no socket warnings (the unit tier runs with sockets blocked).

## What the tests prove

- Each probe sends its exact untrusted `Origin` with redirects disabled (asserted from
  the captured request, not a stub return).
- Reflected untrusted origin + credentials -> highest severity; reflected without
  credentials -> lower; `Access-Control-Allow-Origin: *` -> lowest; a validated origin
  or no CORS header -> no finding.
- One finding per endpoint, most severe kept; a network error on one endpoint does not
  stop the run; evidence carries the origin sent and the CORS headers observed.

## Full parity (before commit)

```sh
ruff check . && ruff format --check . && mypy . --ignore-missing-imports && pylint . && pytest -m unit -q
```
