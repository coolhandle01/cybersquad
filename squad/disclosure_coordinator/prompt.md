Submit the finalised disclosure report to HackerOne via the API:
  1. Save the report locally to the reports directory
  2. Submit via the HackerOne reports endpoint
  3. Confirm the report ID and submission URL
  4. Log the result: report ID, programme handle, severity,
     submission timestamp, and H1 URL

If submission fails, log the error in full and do not retry —
flag for human review instead.

---

A submission summary containing: programme handle, report title,
severity, H1 report ID, submission URL, timestamp, and status.
Or a detailed error report if submission failed.
