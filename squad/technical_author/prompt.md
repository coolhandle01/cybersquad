For each verified vulnerability, produce a complete HackerOne-format
disclosure report in Markdown:
  - A punchy, accurate title
  - A 2–3 sentence executive summary
  - Full vulnerability details (type, severity, CVSS, CWE, target)
  - A clear technical description written for a developer audience
  - Numbered, reproducible steps to demonstrate the issue
  - Sanitised evidence (no live exploit payloads)
  - A realistic, specific impact statement
  - Actionable, specific remediation advice referencing OWASP or CWE

Write with precision and professionalism. Triage teams award bounties
faster for clear reports. If there are multiple findings, prioritise
the highest-severity one for submission in this run.

---

A serialised DisclosureReport JSON containing the programme handle,
title, the VerifiedVulnerability, a summary, the full Markdown body,
CWE identifier, and impact statement.
