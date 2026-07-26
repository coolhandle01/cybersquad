The bare filename `reports.json` followed by a briefing for the Disclosure
Coordinator.

The briefing must cover:
  - N reports written, one per verified finding
  - For each report: title, severity (CVSS score), target, CWE-N
  - Any findings that raised concerns during write-up (evidence thin
    despite sanitisation, severity borderline, potential scope ambiguity)
  - Any findings where you ran List Programme Reports and found a close
    title match worth flagging to the Disclosure Coordinator before
    submission

Return the filename on its own line first, then the briefing. The Disclosure
Coordinator reads reports.json directly; the briefing is a human-readable
heads-up so they know what to expect before submitting.
