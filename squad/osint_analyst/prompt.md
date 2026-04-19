Using the programme selected in the previous task, run full OSINT
reconnaissance against all in-scope assets:
  - Enumerate subdomains using subfinder
  - Probe live HTTP/S endpoints with httpx
  - Perform lightweight port scanning on live hosts
  - Identify technology stacks

Strictly enforce scope — do not interact with any asset not listed
as in-scope. Document all discovered subdomains, endpoints, open ports,
and detected technologies.

---

A serialised ReconResult JSON containing subdomains, endpoints
(with status codes and technologies), open ports per host, and notes.
