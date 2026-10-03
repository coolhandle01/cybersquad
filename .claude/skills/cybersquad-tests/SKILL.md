---
name: cybersquad-tests
description: The cybersquad test-observability doctrine - observe don't just execute, the paper-tiger taxonomy, mutation-audit practice, when to split a test file - plus the shared-fixture catalogue (make_response, the canonical model fixtures, clean_response_body, the domain URLs). Load before writing, editing, or reviewing any file under tests/.
---

# cybersquad tests

This skill carries the **test-observability doctrine** - how to write a test that *watches* behaviour rather than merely runs it. It governs every test and every review, so it loads whenever a test file is touched. The **shared-fixture catalogue** it is applied with - which fixtures exist, what each provides, the in-scope derivation rule - is a lookup layer an author reaches for mid-write, not something a reviewer needs, so it lives one hop away in [`references/fixtures.md`](references/fixtures.md) and loads on demand.

## Test-first, then one turn further: observe the red

The discipline underneath everything here is **red -> green -> refactor**, test-first, one behaviour at a time: write the failing test that names the behaviour, watch it fail *for the right reason* (an assertion, not an import error), write the minimum code to pass, then refactor with the bar green. The test is the spec, written first so the design is shaped by how the code is *used*. "See it fail before you make it pass" is the whole game - a test that has never failed proves nothing.

cybersquad runs a **richer** loop than the bare cycle, because a probe's contract is *observation*, not merely execution: a green test can run a line without watching what it did. Three intensifications of the red step, each a section below:

- **Red, mechanised.** "A test that never failed proves nothing" is a promise you can *verify* after the fact: `mutmut` breaks the code a hundred ways and checks the suite reddens. A kill-rate far below coverage is the batch of reds the suite never wrote - the red step applied to a suite that is already green. (See *Mutation testing*.)
- **Refactor, in service of observation.** The refactor step is not only tidy-up. A decorated `check_X` body `mutmut` cannot see is lifted into an undecorated `_impl` it can - the whole-body lift - so the control flow becomes *observable*, taking an honest board from a paper-tiger ~100% down to a real ~70-75%. Refactor to make the behaviour watchable, then write the reds the lift exposes. (See *Mutation testing* on the `_impl` lift.)
- **Red, at review time.** The sharpest red is not a missing assertion but a wrong feature: after "is the behaviour observed?" comes "is the observed behaviour what the feature *promises*?" A green test can faithfully pin a broken feature. When it does, the deliverable is a red test named for the intended behaviour - the red step used as a bug report - and then you make the feature work. (See *The green test that ratifies a bug*.)

So the loop for a probe under audit: **`mutmut` to find the unobserved behaviour -> refactor to observe it and write the reds that carry the board to ~70-75% -> ask whether the now-pinned behaviour is *correct* -> if not, a red test and a fix -> the feature documented.** Green that skipped the red only proved the code does what it does.

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

## The green test that ratifies a bug

The taxonomy above is green-for-the-wrong-reason. There is a worse failure it does not cover, because it is green for the *right* reason: a test that observes the code faithfully, kills its mutants, reads as thorough - and pins behaviour that is *wrong*. The test is correct about what the code does; the code does the wrong thing; the test locks the defect in as the spec. Mutation testing cannot catch this - a ratifying test has no missing assertion to expose. Only the face-value pass catches it: after "is the behaviour observed?" comes "is the observed behaviour *what the feature promises*?"

When that second question answers no, the deliverable is a **red test named for the intended behaviour** - a failing repro that reports the feature does not work - plus the defect, **never** a green test that encodes the broken behaviour as correct. A refactor whose board is green but never once tried to make the feature fail is not finished; it has only proved the code does what it does. Hunt for the input on which the feature *should* produce a result and does not, and write the test that goes red on it - a limitation you narrate is a green test's excuse; a limitation you prove with a red test is a defect that gets fixed.

Worked example - the ssrf loopback oracle. The probe ships `localhost-ipv4` / `localhost-ipv6` payloads advertised as exposing "internal services, Redis, admin panels", but confirmation (`_confirms_ssrf`) recognises only AWS-IMDS bodies, so a loopback probe that genuinely reaches an internal service returns no finding - the advertised feature cannot fire. The suite carried a green `test_only_reachable_targets_confirm` that *ratified* this (loopback -> no finding, asserted as correct). The honest artefact is the inverse: inject `127.0.0.1`, return a realistic internal-service body, assert a finding - a test that goes red and names the defect, so it becomes a fix (a non-IMDS confirmation signal) rather than a footnote in a review.

## Mutation testing - the audit signal

Coverage is a floor the gate already enforces; mutation is the *observation* axis, the one number a suite cannot earn by visiting lines. Run it as a **periodic, per-module audit - never a merge gate.**

- **How to run it.** `mutmut` against the **deterministic unit layer only** - the BDD layer hits a real LLM and would flap. The version is owned by the `dev` extra in `pyproject.toml`, not restated here - `pip install -e ".[dev]"` brings it, and the `setup.cfg` keys below assume the major that extra pins (bump the pin and re-check these keys against that release's docs). Drop a temporary, untracked `setup.cfg` beside the run (remove it and the generated `mutants/` tree before committing - neither is ever staged):

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
- **The algorithm belongs in an undecorated `_impl`, so `mutmut` can see it - by construction, not as a rescue.** This is the testing face of the seam-not-a-home rule in `cybersquad-tool`: a tool built framework-at-the-edge already has its logic in a plain `_impl` that `mutmut` mutates and a test drives directly through the public entry, so the board is honest from the first run. The skip bites only when logic is instead fused into a decorated body - a `check_X` probe under `@owasp` carrying the endpoint/param loop, dedup, `adaptive_sleep`, the `>=500` gate, the `break`/`continue`. Then `mutmut` mutates only whatever leaves were pulled out and reports a green number that has measured nothing about the control flow - a paper tiger one level up, worst on the *highest*-scoring module because the number looks finished. The honest cost of finding this late, as a cautionary tale rather than a path to emulate: on `check_reflected_xss` a leaf-only extraction scored 19 mutants at 100%, and moving the whole body into `_reflected_xss_impl` exposed 87 mutants at ~52%, surfacing loop-abort (`continue`->`break`), dedup-collapse (`key`->`None`), and request-shape mutants the leaf board never generated. If you are retrofitting such a probe, the corrective is the whole-body lift (`cybersquad-tool` frames it as design-debt paydown); the number that matters is the one after the lift. **Corollary - assert finding shape through the public seam.** A test that pins an extracted assembler at its *direct* call cannot observe the orchestrator passing a wrong argument *into* it. Drive the emitted finding through the public `check_X` and assert its fields with `==` / a distinctive `Parameter: q` - never a bare `in` token that a canary prefix carrying a stray `q` satisfies coincidentally (that live paper tiger is what this corollary was written from).
- **The reference shows the *method*, not the control flow - re-derive per probe.** A worked example (the xss whole-body lift) teaches the shape of the fix, not the shape of *your* loop. Before templating its tests, read your probe's own body: which gates it has (`>=500`, paramless), where it dedups, `break`-vs-`continue`, and *how many* `adaptive_sleep` placements and *on which paths* (one probe throttles on the miss only, another on both request sites, a tiered probe skips the sleep on a hit-and-break path). Copy the test *idioms*; re-derive the *cases* from the code - templating a sibling's control flow literally writes tests that pass against the wrong shape.
- **Each repeated or tiered safety decision is its own contract.** When a probe makes the same safety call on more than one path (a throttle after the baseline request *and* after the polluted one) or emits different severities with precedence (a `_classify` returning HIGH before MEDIUM; a MEDIUM suppressed once a CRITICAL fires), do not test it once. Each throttle site gets its own call/effect assertion; each tier gets a public-seam test on the emitted severity; and the *ordering itself is a contract* - assert through the seam that the highest tier wins when several could fire, so a reorder mutant reddens. The highest-value orchestration mutant often lives here (e.g. a tier that `break`s before its throttle - the `break`-removal is only caught by a "does not sleep on this path" test).
- **Observing a backoff/throttle as an effect: spy the real function.** The effect carve-out says assert the *effect*, not the call; the concrete idiom for a rate-limit backoff is to *spy* the real `adaptive_sleep` rather than replace it - `patch("tools.pentest.<probe>.adaptive_sleep", wraps=adaptive_sleep)` (the root `conftest` autouse-patches `time.sleep`, so the real backoff logic runs instantly), drive the trigger (a `429`), and assert the effect propagates: `spy.call_args_list[1].args[0] == spy.call_args_list[0].args[0] * 2` - the next request goes out on the *doubled* delay. A plain `Mock` with `call_count` observes only *that* it throttled, not *that the delay doubled*; the safety contract lives in the value, not the call.
- **Attribute the kill.** Pin selection to the module's *own* test file, not the whole unit layer. With selection across the layer, a mutant killed by a *sibling* suite still counts - inflating this module's apparent score and hiding whether these tests did the work. And to trust a claimed before -> after delta, re-run the baseline against the pre-change test file; the endpoint alone does not prove the gain.
- **Point it by criticality, not score.** The worst defect is often on the *highest*-scoring module - a suite that looks thorough gets less scrutiny. Rank a security decision, a scope filter, or an irreversible side effect ahead of a formatter, whatever the percentages read.
- **Prove a mutant equivalent; do not assert it.** The reason has to be an argument from the code: *"`json.dumps` defaults to `ensure_ascii=True`, so the payload is ASCII by construction and the `encoding=` mutants cannot change a byte"* is a proof. *"only reachable on a missing key"* is not, unless you state why every reachable value behaves identically.
- **Equivalence is per-*site*, not per-mutation-*shape*.** The same mutant can be killable at one site and equivalent at another, decided by the reachable input set. The string-wrap on `lstrip("*.")` is killable in `cert_transparency` (a certificate SAN name can lead with an uppercase letter) and equivalent in the scope guard (its identifiers never do). Re-earn the proof at each site.
- **100% kill is not "exhaustively observed".** A kill-rate is bounded by the mutator's operators, which are directional: `mutmut` mutates an integer to `n+1` only and *wraps* string literals rather than shrinking them - so `text[:1000]` has a `[:1001]` mutant and no `[:999]`, and `lstrip("*.")` has no charset-shrink mutant at all. Read a clean module as *nothing the mutator knew how to ask survived*, and still write the boundary test on the side the tool cannot reach - as regression protection, not a survivor closed.
- **A per-module pass is blind to its siblings.** Fixing the module you point `mutmut` at says nothing about the sibling suites that share its fixture or its anti-pattern: a truthy shared response fixture stays truthy everywhere, and an identical stub-the-subject shortcut stays live one directory over. After a module scores clean, grep the anti-pattern across its siblings; the score will not.

## The recon / HTTP-client shape

Most modules below the wrapper layer share one shape - build a `requests` call, parse the JSON, cache the result - and their highest-value assertions are the same, so reach for these first:

- **Pin the outbound call** through `call_args`: the exact URL, the *full* params dict (not a subset), `timeout`, and any auth header. This is where the request-shape mutants live. Asserting a URL against the module's own `_URL` constant is a real pin, not a tautology - `mutmut` does not mutate module-level constants, so the assertion still kills the in-function mutants that drop or swap the argument.
  - **But `tools/http.get`/`post` default `timeout=None` to `config.recon.http_timeout`** - so `timeout=None` and dropped-`timeout` mutants are *equivalent* (the outbound request is byte-identical); prove them, do not chase them. `allow_redirects` has no such default, so *its* drop/`None`/flip mutants **are** killable via `call_args` - pin it explicitly. This one asymmetry accounts for most of the surviving request-shape mutants across the probe suite.
- **Drive the parser directly** with real and degenerate inputs (missing key, empty list, wrong type), so a degrade branch returns a value you can assert rather than raising into a caller that swallows it.
- **Assert the cache's effect**: a repeat query is served with no second call (`call_count`), and two distinct queries return their own results without colliding.

The survivor profile is nearly identical across these clients, so the second one goes faster than the first.

## Splitting a large test file

Past roughly 500 lines a test module stops being navigable. Split it, but only ever as a **pure move**: a `refactor(test)` that relocates tests and changes none of them, in its own PR with nothing semantic in the diff.

Split along a **seam that already exists**, never an arbitrary line count:

- **By the source's functional units** - one public function / probe family per file, mirroring how the source groups them; the existing per-class structure (`TestCheckAdminPanels`, ...) is usually the seam. The args-schema contract-tests split (see [`references/fixtures.md`](references/fixtures.md)) is the worked instance: the generic contract loop and the per-case schema classes need different imports, so nothing duplicates across the cut.
- **Into a per-scope package** when a whole area grows - the `tests/squad/<member>/` layout, with shared helpers hoisted into `tests/fixtures/` rather than copied.

A split is correct only if it is **invariant-preserving**. Identical before and after: the collected-test count (`pytest --collect-only -q`), the coverage percentage, and - where the area has been mutation-audited - the kill-rate. If any of the three moves, the "move" changed behaviour and is not a move. Put the before/after collected count in the PR body so review is a thirty-second diff. Never bundle a split into a feature or model change - a relocation hidden inside a semantic PR is unreviewable.

## Shared fixtures

The shared-fixture catalogue - the `tests/fixtures/` layout, the per-fixture reference table (`make_response`, the canonical model fixtures, `clean_response_body`, the domain URLs), the in-scope derivation rule, the `model_copy` variant pattern, the response-builder keepers, and the args-schema contract-test structure - is in [`references/fixtures.md`](references/fixtures.md). Read it when you are mid-write and need a fixture's shape or name; a reviewer confirming a test *observes* rarely needs it, which is why it is a separate load rather than carried here.

The one rule worth stating up front, because it governs the diff you write rather than a lookup you make: use the shared fixtures rather than redefining local equivalents - duplicates drift, hide accidental marker collisions, and make canonical-model refactors painful. Migrating a *generic* local response builder to `make_response` while you harden a file is a sanctioned exception to the minimal-diff rule; a builder that carries real extra logic stays.
