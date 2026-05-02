For each verified vulnerability, produce a complete HackerOne-format
disclosure report in Markdown:
  - A punchy, accurate title
  - A 2–3 sentence executive summary
  - Full vulnerability details (type, severity, CVSS, CWE, target)
  - A clear technical description written for a developer audience
  - Numbered, reproducible steps to demonstrate the issue
  - Sanitised evidence (no live exploit payloads, no credentials,
    no data belonging to other users)
  - A realistic, specific impact statement grounded in what an attacker
    can actually do with the finding
  - Actionable, specific remediation advice citing the relevant OWASP
    guidance (https://owasp.org) or CWE entry (https://cwe.mitre.org)

The quality bar is a report that HackerOne triages on first read without
requesting clarification. If there are multiple findings, prioritise the
highest-severity one for submission in this run.