---
name: cybersquad-tests
description: The cybersquad test-observability doctrine - observe don't just execute, the paper-tiger taxonomy, mutation-audit practice, when to split a test file - plus the shared-fixture catalogue (make_response, the canonical model fixtures, clean_response_body, the domain URLs). Load before writing, editing, or reviewing any file under tests/.
---

# cybersquad tests

This skill carries two things: the **test-observability doctrine** - how to write a test that *watches* behaviour rather than merely runs it - and the **shared-fixture catalogue** it is applied with. The doctrine comes first because it governs every test and every review; the catalogue follows.

## Observe, don't just execute

Coverage asks *did this line run?* The question that decides whether a test is worth anything is *would anyone notice if it were wrong?* A cybersquad suite can sit near 100% branch coverage and still stay green against a deliberately broken implementation - running is not observing. A mutation pass over four modules found kill-rates as low as 42% behind full coverage; the fixes added no production code, only the assertions that were missing.

- **Name the plausible wrong implementations first.** Each becomes an assertion. If you can't say how the test reddens against a wrong impl, that is the assertion you are missing.
- **Assert what was *done*, not what your stub *returned*.** Pin the outbound call (URL, params, `timeout`, `allow_redirects`), the emitted finding's fields, the persisted artefact - not the constant you handed back. Drive the real seam with `invoke_tool` rather than `.func(...)`, which skips the `args_schema` scope validator.
- **Never stub the subject.** Stub collaborators only. Mocking the exact function under test and asserting its own return value specifies nothing.
- **Test both directions of a decision.** A guard proved only to *reject* stays green when it rejects everything - safe and useless at once. Assert the *accept* path and the value that survives it, not just the refusal. The scope guard (`tools/recon/scope.py`) scored highest in the repo and still hid this: `filter_in_scope` was tested both ways, but the single-target guard `_require_endpoint_in_scope` (behind `TargetEndpoint`) was proved only to *reject* an out-of-scope endpoint, never to *admit* an in-scope one - so a mutant that read `host_of(None)` and rejected everything survived.
- **Assert *outside* the double.** An `assert` inside a mock `side_effect` is swallowed wherever production catches broadly (a probe's `except Exception`), and the failure then surfaces on some later unrelated line. Capture into a closure dict, return normally, assert after the call.
- **`==` for invariants, `in` for a genuinely distinctive token.** When the claim is exhaustive - these rows, this evidence slice, this rendered block - assert `==`. A single-character `in` check is a coincidence waiting to pass.
- **Three axes, not one point.** Happy, sad (refuses / errors / handles empty and `None`), adversarial (malformed or hostile - and injection-shaped for the LLM-facing free-text fields `cybersquad-models` flags).
- **Contract is what lands in the run directory, or renders something that does.** `main.py` configures a console-only `RichHandler` with no `FileHandler`, so every `logger.*` call in `tools/` evaporates when the terminal closes - a log line is not a contract and its mutants are equivalent. A rendered metrics block *is* contract, because it renders `RunMetrics`, which persists. Check where the output lands before you assert on it.

## The paper-tiger taxonomy

Named ways a test goes green for the wrong reason. The mutation you can't kill is the assertion you forgot to write. Anchored to modules rather than line numbers, which rot.

| Mode | The mutation that survives it |
|---|---|
| **Stub the subject** | The `@tool` wrapper tests in `tests/squad/penetration_tester/test_tools.py` patch the checker with an arg-ignoring constant and assert `result == constant`. Drop or swap an argument - still green. |
| **Bypass the real wiring** | Same file: `.func(...)` calls the wrapper directly, skipping the `TargetEndpoints` scope validator - the security boundary. Detach the guard - undetected. |
| **Missing direction** | A two-way guard tested one way only. A validator proved to reject but never to accept passes even when it rejects everything. |
| **Absence of observable** | Assert a few substrings, not the whole artefact. Checking three substrings of a rendered block lets an input/output row transpose survive. |
| **Wrong-reason green** | The assertion passes via a path unrelated to the claim - `"https" in evidence` to prove a variant is named, when the template always contains `https://`. |
| **Coincidental token** | A token incidentally always present - `"b" in evidence` where "b" hides inside *ambiguous* or *baseline*. |
| **Lenient `or`** | `"Mako" in e or "FreeMarker" in e` stops pinning which label the probe actually produced. |
| **`in`, not `==`** | Insertion checked, removal not: asserts a marker was added but not that the raw run it replaces was removed. |
| **Constant-fixture blindness** | The double is too constant to notice - a truthy response mock, an arg-discarding `sleep` lambda. A renamed attribute or a wrong backoff delay goes unseen. |

The hunt looked hard for pure tautologies and for missing adversarial coverage on LLM-facing fields and did **not** find them in force - the domain layer already does the hard axis well. The gaps above are narrow and worth fixing precisely.

## Mutation testing - the audit signal

Coverage is a floor the gate already enforces; mutation is the *observation* axis, the one number a suite cannot earn by visiting lines. Run it as a **periodic, per-module audit - never a merge gate.**

- **How.** `mutmut` (3.7) against the **deterministic unit layer only** (`-m "unit and not bdd and not integration"` - the BDD layer hits a real LLM and would flap). Scope with a temporary, untracked `setup.cfg` `[mutmut]` block: a broad `source_paths` (so the copied `mutants/` tree can import the package) and `only_mutate` set to the target module. Remove the `setup.cfg` and the `mutants/` tree before committing - neither is ever staged.
- **Point it by criticality, not score.** The worst defect found was on the *highest*-scoring module. Rank a security decision, a scope filter, or an irreversible side effect ahead of a formatter, whatever the percentages read.
- **Prove a mutant equivalent; do not assert it.** The reason has to be an argument from the code: *"`json.dumps` defaults to `ensure_ascii=True`, so the payload is ASCII by construction and the `encoding=` mutants cannot change a byte"* is a proof. *"only reachable on a missing key"* is not, unless you state why every reachable value behaves identically.
- **Equivalence is per-*site*, not per-mutation-*shape*.** The same mutant can be killable at one site and equivalent at another, decided by the reachable input set. The string-wrap on `lstrip("*.")` is killable in `cert_transparency` (a certificate SAN name can lead with an uppercase letter) and equivalent in the scope guard (its identifiers never do). Re-earn the proof at each site.
- **100% kill is not "exhaustively observed".** A kill-rate is bounded by the mutator's operators, which are directional: `mutmut` mutates an integer to `n+1` only and *wraps* string literals rather than shrinking them - so `text[:1000]` has a `[:1001]` mutant and no `[:999]`, and `lstrip("*.")` has no charset-shrink mutant at all. Read a clean module as *nothing the mutator knew how to ask survived*, and still write the boundary test on the side the tool cannot reach - as regression protection, not a survivor closed.
- **A per-module pass is blind to its siblings.** Fixing the module you point `mutmut` at says nothing about sibling suites that share its fixture or its anti-pattern. Hardening the cloud probes left the identical stub-the-subject pattern live one directory over and left `make_response` truthy for the roughly two dozen other files that use it. After a module scores clean, grep the anti-pattern across its siblings - the score will not.

**The keystone.** `make_response` (`tests/fixtures/responses.py`) returns a bare `MagicMock` and never wires `raise_for_status`, so `resp.raise_for_status()` is a no-op under test and every HTTP status guard is an unobserved sad path across the roughly two dozen test files that use it. Until it is made status-aware (tracked on #232), a test that needs the error path must wire `raise_for_status.side_effect` by hand and cannot rely on `status=` alone.

## Splitting a large test file

Past roughly 500 lines a test module stops being navigable. Split it, but only ever as a **pure move**: a `refactor(test)` that relocates tests and changes none of them, in its own PR with nothing semantic in the diff.

Split along a **seam that already exists**, never an arbitrary line count:

- **By the source's functional units** - one public function / probe family per file, mirroring how the source groups them; the existing per-class structure (`TestCheckAdminPanels`, ...) is usually the seam. The args-schema contract-tests split (below) is the worked instance: the generic contract loop and the per-case schema classes need different imports, so nothing duplicates across the cut.
- **Into a per-scope package** when a whole area grows - the `tests/squad/<member>/` layout, with shared helpers hoisted into `tests/fixtures/` rather than copied.

A split is correct only if it is **invariant-preserving**. Identical before and after: the collected-test count (`pytest --collect-only -q`), the coverage percentage, and - where the area has been mutation-audited - the kill-rate. If any of the three moves, the "move" changed behaviour and is not a move. Put the before/after collected count in the PR body so review is a thirty-second diff. Never bundle a split into a feature or model change - a relocation hidden inside a semantic PR is unreviewable.

## Shared fixtures

`tests/fixtures/` is the source of truth, grouped by concern. The top-level `tests/conftest.py` does the env seeding and pulls the fixture modules in via `pytest_plugins` (see [pytest docs](https://docs.pytest.org/en/stable/how-to/fixtures.html#use-fixtures-from-other-projects)); no other indirection is needed at the test-author side - fixtures resolve by name across the whole suite.

Use these fixtures rather than redefining local equivalents - duplicates drift, hide accidental marker collisions, and make canonical-model refactors painful.

## Layout

| Module | Holds |
|---|---|
| `tests/fixtures/domains.py` | `target_url`, `bystander_url`, `callback_url`, `target_apex`, `target_sld`, `make_html_page` |
| `tests/fixtures/programme.py` | `scope_item_*`, `programme`, `programme_in_workspace`, `dvwa_programme`, `dvwa_in_workspace`, `run_dir`; staging helpers (imported, not fixtures): `stage_models_json(run_dir, name, model_or_list)` writes a JSON **array** (`findings.json` / `verified.json`), `stage_model_json(run_dir, name, model)` writes a single **object** (`recon.json` / `attack_graph.json`) |
| `tests/fixtures/recon.py` | `endpoint`, `recon_result`, `make_s3_hostname` / `s3_hostname`, `make_azure_blob_hostname` / `azure_blob_hostname`, `azure_sas_endpoint` |
| `tests/fixtures/findings.py` | `raw_finding_high` / `raw_finding_low` / `raw_finding_oos`, `verified_vuln`, `disclosure_report`, `attack_tree`, `attack_forest`; helpers `draft_report_kwargs(**overrides)` / `assess_finding_kwargs(**overrides)` (canonical `Draft Vulnerability Report` / `Assess Raw Finding` kwargs - the inner `Authored*` shape is at `["authored"]`; imported, not fixtures) |
| `tests/fixtures/responses.py` | `make_response`, `clean_response_body` |
| `tests/fixtures/tools.py` | `invoke_tool`, `reload_module` |
| `tests/fixtures/task_output.py` | `make_task_output` |

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
| `make_task_output` | Factory for a real `crewai.TaskOutput` (leading positional `raw`; `description` / `agent` required by the model carry placeholders). The unit-test surface for *task guardrails*, whose signature is `(TaskOutput) -> (bool, Any)` - hands the guardrail the real type rather than a `MagicMock`. Pair with `run_dir` / `programme_in_workspace` when the guardrail validates a workspace artefact (e.g. `validate_select_output`). |

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
