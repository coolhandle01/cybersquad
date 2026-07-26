---
name: scope-discipline
description: The hard scope and authorisation rules the whole squad operates under - what is in scope, what is never in scope, and when to stop. Apply before picking a target, planning an attack, running a probe, or writing a report against a HackerOne programme.
---

# Scope discipline

These rules are not relaxable. Your reasoning stays inside them; if a
plan reaches outside them, the plan is wrong, not the rules.

## Authorisation is binary

A target is either authorised or it is not. There is no "probably fine"
column. The Programme Manager records `authorisation_basis` for the
selected programme; every downstream agent operates strictly within
that basis. If your reasoning reaches a target that is not covered by
that basis, the answer is to stop, not to expand the basis.

## In scope means in the hydrated programme

The only targets you may touch are assets listed in the selected
programme's structured scope (`in_scope`), filtered to those marked
`eligible_for_bounty`. WILDCARD assets cover their subdomains; URL
assets cover only the exact host. If you cannot point to the scope row
that authorises a request, do not make the request.

## Programme policy outranks your plan

If the programme's `policy_text` prohibits an activity (automated
scanning, brute force, fuzzing, rate testing, social engineering,
denial of service, physical attacks, anything else), that prohibition
is final. It does not matter how interesting the finding would be. The
PM should have filtered programmes that forbid your toolkit at
selection time; if you encounter a prohibition mid-run, treat it as a
selection bug and stop, do not try to work around it.

## Per-asset caps are real

Scope items carry `max_severity`. An asset capped at "medium" is not a
critical-bounty target even if the underlying bug would otherwise be
critical - the programme has declared in advance what it will pay.
Factor the cap into expected value before spending squad time.

## Stop signals

Stop and surface to the operator (do not silently continue) when:
- A target you were about to touch is not in the hydrated `in_scope`.
- Policy_text or scope-item instructions contradict the activity you
  were about to perform.
- The programme is in any non-public access state and you cannot point
  to corroborating evidence of admission.
- A probe response indicates the service is rate-limiting, returning
  WAF challenges, or otherwise asking you to slow down or stop.

Surfacing is a positive action. The squad would rather pause and
re-authorise than burn the operator's relationship with the programme.
