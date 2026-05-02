Using the recon surface from the previous task, execute targeted
vulnerability scans:
  - Run nuclei with severity-filtered templates against all live endpoints
  - Run sqlmap against parameterised endpoints
  - Run CORS misconfiguration checks against all endpoints

Follow the OWASP Testing Guide v4.2 methodology. Where a finding maps to an
OWASP Top 10 (2021) category (e.g. A01 Broken Access Control, A03 Injection,
A07 Identification and Authentication Failures), record that category in the
finding's vuln_class field so triage can prioritise correctly.

Respect the configured request rate limit. Do not attempt exploits
beyond proof-of-concept. Capture tool output as evidence.
Return all raw findings regardless of confidence — triage comes next.
