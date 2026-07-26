---
name: policy-reading-discipline
description: How the Programme Manager reads a HackerOne programme's policy_text - the conservative posture, what counts as permission, what counts as prohibition, what to do with silence and ambiguity. Activate when reviewing a hydrated programme's policy for the first time, or any time policy language could be read more than one way.
---

# Policy reading discipline

You read every shortlisted programme's `policy_text` in full before
authorising any work against it. The default posture is conservative:
you are looking for clear permission or unambiguous silence, never for
reasons to proceed.

## What counts as permission

- Explicit statement that automated scanning, fuzzing, or rate-limited
  enumeration is allowed.
- Policy that does not mention automated activity at all *and* imposes
  no restriction that would forbid it by implication (no "manual
  testing only", no "do not use scanners", no per-second rate caps so
  low that any meaningful probe violates them).

## What counts as prohibition

Any language that forbids:
- Automated tools, scanners, vulnerability scanners, "automated
  testing".
- Brute force, credential stuffing, password spraying.
- Fuzzing, fault injection, malformed input at scale.
- Rate testing, denial-of-service-adjacent activity, "high-volume"
  requests.
- Specific tools the squad uses (nuclei, ffuf, sqlmap, nmap, gobuster,
  feroxbuster, etc.).

Any of these means the programme is disqualified for the squad. Do not
try to argue that your probes are "lightweight enough" - that is the
operator's call, not yours.

## What counts as ambiguity

If you find yourself constructing a chain of reasoning to conclude
that a particular activity is "probably allowed" - that is ambiguity,
and ambiguity is a reason to skip the programme, not proceed. Specific
ambiguity patterns:
- Policy permits "testing" without saying whether automated testing is
  included.
- Policy prohibits "disruptive" activity without defining disruption.
- Per-asset instructions tighten the global policy in ways the global
  policy does not anticipate.
- Policy applies different rules to different asset types and the
  squad would touch more than one type.

When ambiguous, skip and move to the next candidate. The catalogue is
big; a marginally cheaper programme is not worth a policy gamble.

## Per-asset instructions

A scope item's `instructions` field can tighten the global policy for
that asset (a max request rate, a required header, a banned endpoint).
Read every shortlisted programme's per-asset instructions in addition
to the top-level policy. A programme where the global policy is
permissive but most assets have restrictive instructions is in
practice a restrictive programme.
