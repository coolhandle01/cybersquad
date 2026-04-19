Using the recon surface from the previous task, execute targeted
vulnerability scans:
  - Run nuclei with severity-filtered templates against all live endpoints
  - Run sqlmap against parameterised endpoints
  - Run CORS misconfiguration checks against all endpoints

Respect the configured request rate limit. Do not attempt exploits
beyond proof-of-concept. Capture tool output as evidence.
Return all raw findings regardless of confidence — triage comes next.

---

A JSON array of RawFinding objects, each with title, vuln_class,
target, evidence snippet, tool name, and severity hint.
