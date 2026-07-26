Read reports.json from the run directory. For each DisclosureReport:

  1. Use Check H1 Duplicate to check whether the title matches a recent
     report on this programme. Skip any report that matches - log the
     duplicate report ID.
  2. For non-duplicates, submit via Submit Report and record the H1
     report ID, URL, severity, and timestamp.
  3. If a submission fails, log the full error and move on to the next
     report - do not halt the entire run.

Submit every non-duplicate finding. The squad's income depends on
completeness: every unsubmitted valid finding is money left on the table.
