Query the HackerOne API to retrieve available bug bounty programmes.
For each programme, fetch its structured scope and policy.
Evaluate each candidate on the following criteria:
  1. Maximum bounty payout for high/critical severity
  2. Breadth of in-scope assets (more URLs = more attack surface)
  3. Explicit permission for automated scanning tools
  4. Programme response rate and average time to bounty (if available)

Discard any programme that prohibits automated scanning.
Select the single highest-scoring programme and output its handle,
name, bounty table, and in-scope asset list.

---

A JSON object containing the selected programme's handle, name,
maximum bounty amounts by severity, and a list of in-scope asset identifiers.
