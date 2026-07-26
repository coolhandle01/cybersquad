# Testing

All tests are marked `@pytest.mark.unit` and must run without network access, real API credentials, or external binaries. Use `monkeypatch` and `unittest.mock` to isolate.

```bash
H1_API_USERNAME=test H1_API_TOKEN=test pytest -m unit
```

Tests that reload modules for config isolation use `importlib.reload()` - this is the correct pattern for testing env-var-backed dataclasses.

Coverage gates stack: an **absolute floor** of 90% (whole-codebase, set via `fail_under = 90` in `pyproject.toml`) catches large regressions, and a **per-PR ratchet** (`diff-cover` with `--fail-under=100` against the base branch) catches slow drift one line at a time - every line added or modified by a PR must be covered by tests. See `docs/ci.md` for how to read a diff-cover failure and how to run the per-PR gate locally before pushing. Every new public function in `tools/` needs a test. Every bug fix needs a regression test.

## Layout

Tests mirror the source tree:

- `tests/tools/test_<module>.py` for files at the `tools/` top level (`h1_api.py`, `html.py`, `http.py`, ...).
- `tests/tools/pentest/test_<probe>.py` for `tools/pentest/<probe>.py`.
- `tests/tools/cloud/test_<module>.py` for `tools/cloud/`.
- `tests/tools/recon/test_<module>.py` for `tools/recon/`.
- `tests/squad/<agent>/test_<surface>.py` for per-agent tests (tools, args_schemas, ...).
- `tests/test_<name>.py` at the root for project-level files that don't live under `tools/` or `squad/` (`config.py`, `models/`, `runtime.py`, `tasks.py`).

Pytest is configured for `--import-mode=importlib`, so subdirs do not require `__init__.py`. Test files may share basenames across subdirs (e.g. `tests/squad/programme_manager/test_tools.py` and `tests/squad/disclosure_coordinator/test_tools.py`).

## Shared fixtures

`tests/conftest.py` provides fixtures for all tests. Use them instead of defining local equivalents.

The `cybersquad-test-fixtures` skill at `.claude/skills/cybersquad-test-fixtures/SKILL.md` covers the same material in a form Claude Code can load on demand when editing test files. The reference below is the same information in human-readable prose.

## Args-schema contract tests

Per-agent contract tests under `tests/squad/<agent>/test_args_schemas.py` parametrise over `MEMBER.schemas` and call the shared assertions in `tests/squad/_contract_assertions.py`:

- `assert_tool_wires_explicit_schema(member, tool_name)` - the live tool's `args_schema` is the class named in the registry.
- `assert_field_descriptions_present(tool_name, schema_cls)` - every field on every schema carries a non-empty `Field(description=...)`.
- `assert_closed_world_mapping(member)` - every private-prefixed args_schema class on `MEMBER.tools` is in `MEMBER.schemas`, and every mapping entry resolves to a registered tool.

`MEMBER.schemas` (a `dict[str, type[BaseModel]]` on the `SquadMember` constant) is the canonical per-agent tool-name -> args_schema registry. Adding a new typed tool means adding both the tool to `MEMBER.tools` and the schema to `MEMBER.schemas` in the same agent's `__init__.py`; the closed-world test refuses the PR otherwise. Agent-specific accept / reject parametrize tables (StrEnum payload rejection, hostname-shape rejection, etc.) stay in each per-agent file.

`tests/squad/_contract_assertions.py` is intentionally not a `test_*.py` module - pytest does not collect it. It is imported by each per-agent test file.

### `make_response`

Factory for `MagicMock` objects shaped like `requests.Response`. Accepts `status`, `body`, `headers`, `cookies`, and `json`. Use this for any generic HTTP response mock. Tool-specific response builders that carry extra logic (e.g. cookie-jar inspection, POST body reflection) can stay local to their test file.

```python
# correct - uses shared fixture
def test_no_finding(self, make_response: Callable[..., MagicMock]) -> None:
    with patch("requests.get", return_value=make_response(body="<html>ok</html>")):
        pass  # assertions go here

# wrong - duplicates the fixture locally
def _resp(body="", status=200):
    r = MagicMock()
    r.text = body
    r.status_code = status
    return r
```

### Model fixtures

`programme`, `endpoint`, `recon_result`, `raw_finding_high/low/oos`, `verified_vuln`, `disclosure_report` - canonical model instances. Use `model_copy(update={...})` to derive variants.

### `clean_response_body`

An HTML body verified at fixture-setup time to contain none of the strings any pentest probe treats as a positive match. Use it for "no finding" cases to avoid false negatives caused by accidental marker collisions.

## Mocking network and binaries

Tests must mock all network and binary calls. Patch `socket.create_connection` at the module path where it is imported (e.g. `tools.cloud.databases.redis.socket.create_connection`), not at the top-level `socket` module.
