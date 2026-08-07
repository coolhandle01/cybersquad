---
name: cybersquad-tests
description: The cybersquad test-observability doctrine - observe don't just execute, the paper-tiger taxonomy, mutation-audit practice, when to split a test file - plus the shared-fixture catalogue (make_response, the canonical model fixtures, clean_response_body, the domain URLs). Load before writing, editing, or reviewing any file under tests/.
---

# cybersquad tests

This skill carries two things: the **test-observability doctrine** - how to write a test that *watches* behaviour rather than merely runs it - and the **shared-fixture catalogue** it is applied with. The doctrine comes first because it governs every test and every review; the catalogue follows.

## Observe, don't just execute

Coverage asks *did this line run?* The question that decides whether a test is worth anything is *would anyone notice if it were wrong?* A suite can sit near 100% branch coverage and still stay green against a deliberately broken implementation - running is not observing. Where observation is thin, mutation testing exposes it as a kill-rate far below the coverage number, and closing that gap means adding the assertions that were missing, not touching the code.

- **Name the plausible wrong implementations first.** Each becomes an assertion. If you can't say how the test reddens against a wrong impl, that is the assertion you are missing.
- **Assert what was *done*, not what your stub *returned*.** Pin the outbound call (URL, params, `timeout`, `allow_redirects`), the emitted finding's fields, the persisted artefact - not the constant you handed back.
- **Drive the real seam - which seam depends on the layer.** For a `@cyber_tool` wrapper the seam is `invoke_tool` (so the `args_schema` scope validator fires), never `.func(...)` which skips it. For a low-level client *below* the wrapper layer - an HTTP client, a parser - there is no wrapper and no validator, so the direct call *is* the production seam: call it directly, and drive parsers directly so a degrade branch surfaces as a return value instead of being swallowed by a caller's `except`.
- **Never stub the subject.** Stub collaborators only. Mocking the exact function under test and asserting its own return value specifies nothing.
- **Test both directions of a decision.** A guard proved only to *reject* stays green when it rejects everything - safe and useless at once. Assert the *accept* path and the value that survives it, not just the refusal. This hides most easily on a security boundary, where the rejection cases get careful attention and nothing checks that a legitimate host still gets through - a scope guard mutated to admit nothing is fail-safe and useless at once, and every rejection test still passes.
- **Assert *outside* the double.** An `assert` inside a mock `side_effect` is swallowed wherever production catches broadly (a probe's `except Exception`), and the failure then surfaces on some later unrelated line. Capture into a closure dict, return normally, assert after the call.
- **`==` for invariants, `in` for a genuinely distinctive token.** When the claim is exhaustive - these rows, this evidence slice, this rendered block - assert `==`. A single-character `in` check is a coincidence waiting to pass.
- **Three axes, not one point.** Happy, sad (refuses / errors / handles empty and `None`), adversarial (malformed or hostile - and injection-shaped for the LLM-facing free-text fields `cybersquad-models` flags).
- **Contract is what lands in the run directory, or renders something that does.** `main.py` configures a console-only `RichHandler` with no `FileHandler`, so every `logger.*` call in `tools/` evaporates when the terminal closes - a log line is not a contract and its mutants are equivalent. A rendered metrics block *is* contract, because it renders `RunMetrics`, which persists. One carve-out worth stating, because it is easy to mis-file as equivalent: an internal value whose *effect* is promised - a cache namespace that guarantees two endpoints never collide, an idempotent write - is a contract even though the value itself is never persisted or rendered. Assert the *effect* (the collision does not happen; the repeat call is served from cache), not the literal. Check where the output lands, or what behaviour is promised, before you assert on it.

## The paper-tiger taxonomy

Named ways a test goes green for the wrong reason. The mutation you can't kill is the assertion you forgot to write. Anchored to modules rather than line numbers, which rot.

| Mode | The mutation that survives it |
|---|---|
| **Stub the subject** | Patch the function under test with a constant that ignores its arguments, then assert that constant came back. Drop or swap an argument - still green, because nothing observed the arguments. |
| **Bypass the real wiring** | Reach the subject by its private path (`.func(...)`) instead of the validated production seam (`invoke_tool` / `args_schema`), so the scope validator never fires. Detach the guard entirely - undetected. |
| **Missing direction** | A two-way guard tested one way only. A validator proved to reject but never to accept passes even when it rejects everything. |
| **Absence of observable** | Assert a few substrings, not the whole artefact. Checking three substrings of a rendered block lets an input/output row transpose survive. |
| **Wrong-reason green** | The assertion passes via a path unrelated to the claim - `"https" in evidence` to prove a variant is named, when the template always contains `https://`. |
| **Coincidental token** | A token incidentally always present - `"b" in evidence` where "b" hides inside *ambiguous* or *baseline*. |
| **Lenient `or`** | `"Mako" in e or "FreeMarker" in e` stops pinning which label the probe actually produced. |
| **`in`, not `==`** | Insertion checked, removal not: asserts a marker was added but not that the raw run it replaces was removed. |
| **Constant-fixture blindness** | The double is too constant to notice - a truthy response mock, an arg-discarding `sleep` lambda. A renamed attribute or a wrong backoff delay goes unseen. |

Two more worth checking for, easy to miss because they read as thorough: a pure tautology (an assertion that cannot fail against any implementation), and a missing adversarial case on an LLM-facing free-text field.

## Mutation testing - the audit signal

Coverage is a floor the gate already enforces; mutation is the *observation* axis, the one number a suite cannot earn by visiting lines. Run it as a **periodic, per-module audit - never a merge gate.**

- **How to run it.** `mutmut` 3.7 against the **deterministic unit layer only** - the BDD layer hits a real LLM and would flap. Drop a temporary, untracked `setup.cfg` beside the run (remove it and the generated `mutants/` tree before committing - neither is ever staged):

  ```ini
  [mutmut]
  # multi-value keys are newline-indented lists, NOT space-separated - see below
  source_paths =
      tools
      models
      config.py
      runtime.py
  only_mutate = tools/<module>.py
  # pin selection to THIS module's test file (see "Attribute the kill")
  pytest_add_cli_args_test_selection = tests/.../test_<module>.py
  pytest_add_cli_args =
      -m
      unit and not bdd and not integration
  ```

  Two format traps, both of which fail by *under-reporting* - the exact defect this doctrine exists to catch, so measure the config twice:
  - **`source_paths` must be a newline-indented list, not space-separated.** `source_paths = tools models ...` on one line is read as a single path `tools models ...`, which does not exist, so `mutmut` copies *nothing* into the `mutants/` tree and every mutant dies on `BadTestExecutionCommandsException` (an import error, not a real kill). Newline-indented, each entry copies. The set stays broad on purpose: the copied tree has to import the whole flat-layout package even though `only_mutate` narrows what gets mutated. For a wrapper under `squad/<member>/`, add `squad` to the list or the copied tree can't import the member package.
  - **`-m` and its marker expression go on separate lines.** `pytest_add_cli_args = -m "unit and not bdd and not integration"` passes the whole quoted string as *one* argv element, which pytest rejects as an unknown marker path. Split so `-m` and the expression reach pytest as two argv elements. Same rule for any flag-plus-value pair.

  Read survivors with a results-then-show loop: `mutmut results` lists every mutant's status, `mutmut results | grep survived` is the worklist, and `mutmut show <id>` prints a mutant's diff so you can judge kill-vs-equivalent. A run that reports *every* mutant killed at suspiciously high speed is the tell for the copy-failure above - confirm the `mutants/` tree actually holds your package before you trust a clean board.
- **`mutmut` skips decorated functions - so audit the validator, not the wrapper.** A `@cyber_tool` / `@pentest_tool` wrapper is a decorated function; `mutmut` does not mutate its body, so pointing `only_mutate` at the wrapper module scores an empty or trivial board that means nothing. The observable logic a wrapper carries lives in the `args_schema`'s `AfterValidator` (the scope guard) and the models it returns - point `only_mutate` at *those* modules, and drive them through `invoke_tool` so the validator is on the real path.
- **Attribute the kill.** Pin selection to the module's *own* test file, not the whole unit layer. With selection across the layer, a mutant killed by a *sibling* suite still counts - inflating this module's apparent score and hiding whether these tests did the work. And to trust a claimed before -> after delta, re-run the baseline against the pre-change test file; the endpoint alone does not prove the gain.
- **Point it by criticality, not score.** The worst defect is often on the *highest*-scoring module - a suite that looks thorough gets less scrutiny. Rank a security decision, a scope filter, or an irreversible side effect ahead of a formatter, whatever the percentages read.
- **Prove a mutant equivalent; do not assert it.** The reason has to be an argument from the code: *"`json.dumps` defaults to `ensure_ascii=True`, so the payload is ASCII by construction and the `encoding=` mutants cannot change a byte"* is a proof. *"only reachable on a missing key"* is not, unless you state why every reachable value behaves identically.
- **Equivalence is per-*site*, not per-mutation-*shape*.** The same mutant can be killable at one site and equivalent at another, decided by the reachable input set. The string-wrap on `lstrip("*.")` is killable in `cert_transparency` (a certificate SAN name can lead with an uppercase letter) and equivalent in the scope guard (its identifiers never do). Re-earn the proof at each site.
- **100% kill is not "exhaustively observed".** A kill-rate is bounded by the mutator's operators, which are directional: `mutmut` mutates an integer to `n+1` only and *wraps* string literals rather than shrinking them - so `text[:1000]` has a `[:1001]` mutant and no `[:999]`, and `lstrip("*.")` has no charset-shrink mutant at all. Read a clean module as *nothing the mutator knew how to ask survived*, and still write the boundary test on the side the tool cannot reach - as regression protection, not a survivor closed.
- **A per-module pass is blind to its siblings.** Fixing the module you point `mutmut` at says nothing about the sibling suites that share its fixture or its anti-pattern: a truthy shared response fixture stays truthy everywhere, and an identical stub-the-subject shortcut stays live one directory over. After a module scores clean, grep the anti-pattern across its siblings; the score will not.

## The recon / HTTP-client shape

Most modules below the wrapper layer share one shape - build a `requests` call, parse the JSON, cache the result - and their highest-value assertions are the same, so reach for these first:

- **Pin the outbound call** through `call_args`: the exact URL, the *full* params dict (not a subset), `timeout`, and any auth header. This is where the request-shape mutants live. Asserting a URL against the module's own `_URL` constant is a real pin, not a tautology - `mutmut` does not mutate module-level constants, so the assertion still kills the in-function mutants that drop or swap the argument.
- **Drive the parser directly** with real and degenerate inputs (missing key, empty list, wrong type), so a degrade branch returns a value you can assert rather than raising into a caller that swallows it.
- **Assert the cache's effect**: a repeat query is served with no second call (`call_count`), and two distinct queries return their own results without colliding.

The survivor profile is nearly identical across these clients, so the second one goes faster than the first.

## Splitting a large test file

Past roughly 500 lines a test module stops being navigable. Split it, but only ever as a **pure move**: a `refactor(test)` that relocates tests and changes none of them, in its own PR with nothing semantic in the diff.

Split along a **seam that already exists**, never an arbitrary line count:

- **By the source's functional units** - one public function / probe family per file, mirroring how the source groups them; the existing per-class structure (`TestCheckAdminPanels`, ...) is usually the seam. The args-schema contract-tests split (below) is the worked instance: the generic contract loop and the per-case schema classes need different imports, so nothing duplicates across the cut.
- **Into a per-scope package** when a whole area grows - the `tests/squad/<member>/` layout, with shared helpers hoisted into `tests/fixtures/` rather than copied.

A split is correct only if it is **invariant-preserving**. Identical before and after: the collected-test count (`pytest --collect-only -q`), the coverage percentage, and - where the area has been mutation-audited - the kill-rate. If any of the three moves, the "move" changed behaviour and is not a move. Put the before/after collected count in the PR body so review is a thirty-second diff. Never bundle a split into a feature or model change - a relocation hidden inside a semantic PR is unreviewable.

## Shared fixtures

`tests/fixtures/` is the source of truth, grouped by concern. The top-level `tests/conftest.py` does the env seeding and pulls the fixture modules in via `pytest_plugins` (see [pytest docs](https://docs.pytest.org/en/stable/how-to/fixtures.html#use-fixtures-from-other-projects)); no other indirection is needed at the test-author side - fixtures resolve by name across the whole suite.

Use these fixtures rather than redefining local equivalents - duplicates drift, hide accidental marker collisions, and make canonical-model refactors painful. Migrating a *generic* local response builder to `make_response` while you harden a file is a sanctioned exception to the minimal-diff rule - do it in the same PR; a builder that carries real extra logic (see "Tool-specific response builders" below) stays.

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
