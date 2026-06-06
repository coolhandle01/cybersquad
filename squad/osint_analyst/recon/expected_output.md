A short Markdown briefing (roughly 8-15 lines) for the Vulnerability
Researcher, followed by the relative filename of the canonical recon
artefact written to the run directory (i.e. ``recon.json``).

The briefing must call out:

  - The HIGH-priority hosts with one-line rationale each (role + tech +
    why the budget goes here)
  - Top detected technologies and the hostnames they appear on -
    especially WordPress / Spring / Apache / Joomla / Drupal versions,
    since any version unlocks CVE research for the Vulnerability Researcher
  - Subdomains worth a closer look that ended up MEDIUM but not HIGH
    (e.g. staging, dev, internal) and why they did not earn HIGH
  - Open ports that hint at running services (6379 Redis, 9200
    Elasticsearch, 5984 CouchDB, 27017 MongoDB, 3306/5432 DB, 2082/2083
    cPanel, 10000 Webmin, ...) - which annotated host they belong to
  - High-signal passive findings already collected (TLS issues, DNS
    misconfigurations) - flag the high-signal ones, do not enumerate
    them all
  - Any hosts you deliberately marked SKIP and the reason

The full inventory and every authored insight live in ``recon.json`` -
the Vulnerability Researcher and Penetration Tester use List Subdomains
/ List Endpoints / List Open Ports and Read Run File to drill into it
on demand. The briefing tells them where to look first.

Return the briefing followed on a separate line by the filename string
(no prefix, no surrounding path - just ``recon.json``).
