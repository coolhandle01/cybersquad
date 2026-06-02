---
name: cybersquad-test-fixtures
description: Use the shared pytest fixtures in tests/fixtures/ instead of redefining local equivalents when writing or editing cybersquad tests. Covers make_response, the canonical model fixtures, clean_response_body, and the domain URL fixtures. Load before editing any file under tests/.
---

# cybersquad test fixtures

`tests/fixtures/` is the source of truth, grouped by concern. The top-level `tests/conftest.py` does the env seeding and pulls the fixture modules in via `pytest_plugins` (see [pytest docs](https://docs.pytest.org/en/stable/how-to/fixtures.html#use-fixtures-from-other-projects)); no other indirection is needed at the test-author side - fixtures resolve by name across the whole suite.

Use these fixtures rather than redefining local equivalents - duplicates drift, hide accidental marker collisions, and make canonical-model refactors painful.

## Layout

| Module | Holds |
|---|---|
| `tests/fixtures/domains.py` | `target_url`, `bystander_url`, `callback_url`, `target_apex`, `target_sld`, `make_html_page` |
| `tests/fixtures/programme.py` | `scope_item_*`, `programme`, `programme_in_workspace`, `dvwa_programme`, `dvwa_in_workspace`, `run_dir`; helper `stage_models_json(run_dir, name, model_or_list)` (stage a model / list as `<run_dir>/<name>` for a tool to read back - imported, not a fixture) |
| `tests/fixtures/recon.py` | `endpoint`, `recon_result`, `make_s3_hostname` / `s3_hostname`, `make_azure_blob_hostname` / `azure_blob_hostname`, `azure_sas_endpoint` |
| `tests/fixtures/findings.py` | `raw_finding_high` / `raw_finding_low` / `raw_finding_oos`, `verified_vuln`, `disclosure_report`, `attack_tree`, `attack_forest`; helpers `draft_report_kwargs(**overrides)` / `assess_finding_kwargs(**overrides)` (canonical `Draft Vulnerability Report` / `Assess Raw Finding` kwargs - the inner `Authored*` shape is at `["authored"]`; imported, not fixtures) |
| `tests/fixtures/responses.py` | `make_response`, `clean_response_body` |
| `tests/fixtures/tools.py` | `invoke_tool`, `reload_module` |

When adding a new fixture, put it in the matching module rather than re-opening `conftest.py` - that's the single rule that keeps the catalogue navigable.

## Catalogue

| Fixture | What it provides |
|---|---|
| `make_response` | Factory for `MagicMock` shaped like `requests.Response`. Accepts `status`, `body`, `headers`, `cookies`, `json`. |
| `make_html_page` | Factory for minimal HTML pages with `<script>` tags. Default: one script at `{target_url}/app.js`. |
| `target_url` | `https://victim.example.com` - in-scope target. **Single knob**: every in-scope fixture derives from this via `target_apex`. Flip `target_url` and `scope_item_url`, `scope_item_wildcard`, `programme`, `endpoint`, `recon_result`, `attack_tree` all follow. |
| `target_apex` | Apex domain parsed out of `target_url` (e.g. `example.com`). The derivation point every in-scope fixture builds against - use it when authoring a new in-scope fixture rather than embedding a literal. |
| `bystander_url` | `https://bystander.example.org` - out-of-scope; use whenever a test exercises the scope guard. |
| `callback_url` | `https://callback.cybersquad.com` - OOB receiver placeholder. |
| `run_dir` | Points `runtime.run_dir()` at the test's `tmp_path` and returns the `Path`. Take this instead of patching `runtime.run_dir` at every consumer's import alias (`tools.workspace.runtime.run_dir` / `tools.triage_tools.runtime.run_dir` / etc) - every consumer `import runtime` so the single setattr propagates everywhere. Tests that need a *non-existent* rundir (to exercise `mkdir` behaviour or the missing-dir branch) stay on an explicit `monkeypatch.setattr("runtime.run_dir", ...)` since the fixture always returns an existing path. |
| `programme` | A `Programme` model. In-scope: `https://<target_apex>` and `*.<target_apex>`. |
| `programme_in_workspace` | `programme` staged into the test's rundir as `<run_dir>/programme.json`, with `runtime.programme_handle` monkeypatched. Composes on top of `run_dir`. Tests that need `current_programme()` to work end-to-end take this fixture instead of patching the loader at every import site. |
| `dvwa_programme` | A `Programme` shaped like Damn Vulnerable Web Application on `http://localhost` / `http://127.0.0.1`. Use for BDD scenarios and integration work that point at a real runnable target (the usual deployment is a local Docker container). |
| `dvwa_in_workspace` | DVWA staged into the rundir - same shape as `programme_in_workspace` but the in-flight programme is DVWA. Composes on top of `run_dir`. |
| `endpoint` | An `Endpoint` model at `https://api.<target_apex>`. |
| `recon_result` | A `AttackGraph` combining `programme` and `endpoint`. |
| `target_sld` | Second-level-domain prefix of `target_apex` (`example` from `example.com`). The basis for cloud bucket / account names, which cannot embed the apex's dot. |
| `make_s3_hostname` / `s3_hostname` | Factory + canonical value for in-scope-themed S3 hostnames (`example-assets.s3.us-east-1.amazonaws.com`). Pair shape: factory when a test needs variants, single value for the common case. |
| `make_azure_blob_hostname` / `azure_blob_hostname` | Same pair shape, for Azure Blob hostnames (`examplestorage.blob.core.windows.net`). |
| `azure_sas_endpoint` | An `Endpoint` whose URL carries embedded Azure SAS-token query parameters - the canonical positive case for `check_azure_sas_tokens`. |
| `raw_finding_high` / `raw_finding_low` / `raw_finding_oos` | `RawFinding` instances at each severity / scope tier. |
| `verified_vuln` | A `VerifiedVulnerability` model. |
| `disclosure_report` | A `DisclosureReport` derived from `verified_vuln`. |
| `attack_tree` / `attack_forest` | The VR's research artefact the PT consumes. |
| `clean_response_body` | An HTML body verified at setup time to contain no pentest probe marker - use for "no finding" cases. |
| `invoke_tool` | Invoke a `@cyber_tool` wrapper through its args_schema (CrewAI's production path). Tests that exercise the `Target*` scope guard take this instead of `.func(...)` so the `AfterValidator` actually fires. |
| `reload_module` | Wraps `importlib.reload` so tests can pick up env-var changes on module-level singletons. |

## Authoring a new in-scope fixture

Derive from `target_apex`, never embed the apex literal:

```python
# correct
@pytest.fixture()
def my_admin_endpoint(target_apex: str) -> Endpoint:
    return Endpoint(url=f"https://admin.{target_apex}", status_code=200, ...)

# wrong - hardcoded apex won't follow when target_url changes
@pytest.fixture()
def my_admin_endpoint() -> Endpoint:
    return Endpoint(url="https://admin.example.com", status_code=200, ...)
```

The chain `target_url -> target_apex -> in-scope fixtures` is the single knob for retargeting the suite (e.g. flipping to DVWA on localhost would adjust `target_url` and the dependent fixtures follow). A new fixture that hardcodes `example.com` breaks that property and gets caught at review.

## Derive variants with `model_copy`

Do not reconstruct a fixture model from scratch:

```python
# correct
out_of_scope = programme.model_copy(update={"in_scope": []})

# wrong - duplicates every other field
out_of_scope = Programme(handle=programme.handle, name=programme.name, ...)
```

## Use the domain fixtures

```python
# correct - intent is readable at the call site
def test_drops_out_of_scope(make_response, bystander_url):
    ...

# wrong - opaque hostname, no indication of role
def test_drops_out_of_scope(make_response):
    url = "https://malicious.invalid"
```

## Tool-specific response builders

A local response builder that carries extra logic can stay local. Two specific keepers:

- `_resp` in `test_cookies.py` - cookie-jar inspection via `raw.headers.getlist` for multiple Set-Cookie headers.
- `_post_resp` in `test_csrf.py` - generic in shape but kept for POST-context naming convenience at the call site (16 usages mocking `requests.post` return values).

Otherwise the rule is: if the local helper is just constructing a generic mock response, replace it with `make_response`.

## Args-schema contract tests

Per-agent `tests/squad/<agent>/test_args_schemas.py` files parametrise over `MEMBER.schemas` and call the shared assertions in `tests/squad/_contract_assertions.py` (`assert_tool_wires_explicit_schema`, `assert_field_descriptions_present`, `assert_closed_world_mapping`). The helper module is intentionally not a `test_*.py` so pytest does not collect it; it is imported by each per-agent file. Agent-specific accept / reject cases (StrEnum payload rejection, hostname-shape rejection, wording pins like `Submit Report`'s irreversibility description) stay in the per-agent file.

When those case tables outgrow the file-size bar - the Penetration Tester is the first - split along the seam the imports already draw: the generic contract loop (needs `MEMBER` + the shared assertions) stays in `test_args_schemas.py`, and the accept / reject cases (need the individual `_XArgs` schema classes) move to a sibling `test_args_schema_cases.py`. The two import sets are disjoint, so nothing is duplicated across the split. Keep the autouse `programme_in_workspace` seeding fixture (the one the typed-target `AfterValidator`s need) in the cases file only - the contract-loop assertions never call `model_validate`, so they do not need it.

When adding a new typed tool, add the schema to `MEMBER.schemas` in the agent's `__init__.py` alongside `tools`; the closed-world test refuses the PR if the registry and the mapping disagree.
