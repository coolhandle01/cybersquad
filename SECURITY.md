# Security policy

cybersquad is an autonomous bug bounty pipeline: it runs network reconnaissance
and active vulnerability checks against third-party targets. That makes its own
security posture - scope enforcement, credential handling, and safe-by-default
tool wiring - load-bearing. We take vulnerability reports seriously.

## Supported versions

The project is pre-1.0 (see `version` in `pyproject.toml`) and ships from
`main`. Only the latest `main` is supported; please confirm a report still
reproduces against the current `main` before filing.

| Version | Supported |
|---|---|
| `main` (latest) | yes |
| older commits / tags | no |

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security
vulnerability.** Public disclosure before a fix is available puts every user of
the pipeline at risk.

Report privately through GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/coolhandle01/cybersquad/security)
   of this repository.
2. Click **Report a vulnerability** to open a private advisory (direct link:
   <https://github.com/coolhandle01/cybersquad/security/advisories/new>).
3. Include the details listed below.

If you cannot use private reporting for any reason, contact the repository owner
[@coolhandle01](https://github.com/coolhandle01) through GitHub and ask for a
secure channel - still without disclosing the details publicly.

### What to include

- A description of the vulnerability and its impact.
- The minimal steps or proof-of-concept needed to reproduce it.
- The affected commit (`git rev-parse --short HEAD`) or tag.
- Any suggested remediation, if you have one.

### What to expect

- **Acknowledgement** within 3 business days.
- **Initial assessment** (severity, and whether we can reproduce) within 7
  business days.
- We will keep you updated as we work on a fix, and credit you in the published
  advisory unless you prefer to remain anonymous.

Please give us a reasonable window to ship a fix before any public disclosure.
We follow coordinated disclosure and will agree a timeline with you.

## Scope

This policy covers the cybersquad codebase in this repository. It does **not**
cover:

- Vulnerabilities in upstream dependencies - report those to the relevant
  project. Our `.github/dependabot.yml` keeps our pins current.
- Findings produced by *running* the pipeline against a target. Those belong to
  that target's own disclosure programme, not here.
