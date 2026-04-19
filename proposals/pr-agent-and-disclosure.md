# Proposal: Public Relations Agent + Disclosure Coordination

## Problem

The squad currently discloses silently. There is no mechanism to leverage
successful disclosures for reputation, audience-building, or revenue — all of
which feed back into programme selection quality and operator trust.

Separately, the DisclosureCoordinator has no structured hand-off protocol: it
submits and considers its job done, with no tracking of patch timelines,
coordinated-disclosure windows, or public announcement triggers.

---

## Proposed additions

### 1. DisclosureCoordinator — extended responsibilities

Extend (not replace) the existing agent with:

- **Patch-tracking loop** — after submission, poll H1 API for report state
  transitions (`triaged` → `resolved`). Store state in a lightweight JSON
  sidecar alongside the report file.
- **Disclosure window management** — record submission date, programme's stated
  disclosure window (default 90 days), and whether the programme permits public
  disclosure at all. Surface a `disclosure_eligible: bool` flag when the window
  expires or the programme explicitly grants disclosure.
- **Structured hand-off** — when `disclosure_eligible=True`, emit a
  `DisclosureAnnouncement` model (see below) and pass it to the PR Agent as
  context.

```python
# models.py addition
@dataclass
class DisclosureAnnouncement:
    programme_handle: str
    vuln_title: str
    cve_id: str | None          # if assigned
    patch_date: date
    bounty_awarded: int | None  # USD, if permitted to disclose
    writeup_url: str | None     # link to full technical write-up if published
    one_liner: str              # ≤ 280 chars, human-readable summary
```

**Constraint:** `DisclosureAnnouncement` must only be emitted after all of:
- Programme policy explicitly permits public disclosure, OR 90-day window elapsed
- Patch confirmed resolved in H1 (`state == "resolved"`)
- Operator approval checkpoint passed (uses the same `ApprovalGate` mechanism)

---

### 2. PublicRelationsAgent — new squad member

**Role:** tweet about resolved disclosures in a way that builds the squad's
reputation and, over time, audience.

**Revenue model:** a public track record of quality disclosures:
- Attracts higher-paying programmes to engage the squad directly
- Drives followers who share write-ups (social proof → more H1 upvotes)
- Potential sponsored content from security tooling vendors (longer-term)

**Tools:**

| Tool | Purpose |
|---|---|
| `post_tweet_tool` | Posts to X/Twitter via API v2. Requires `TWITTER_BEARER_TOKEN`, `TWITTER_ACCESS_TOKEN`, `TWITTER_ACCESS_SECRET`. |
| `draft_tweet_tool` | Generates tweet text from `DisclosureAnnouncement` without posting — for dry-run / review. |
| `get_tweet_metrics_tool` | Fetches impressions, likes, retweets for previously posted tweets. Feeds into future programme selection scoring. |

**Tweet strategy constraints (baked into prompt):**
- Never tweet before `disclosure_eligible=True` on the `DisclosureAnnouncement`
- Never include reproduction steps, payloads, or PoC links
- Always include CVE ID if assigned
- Tag the programme if they have a public X handle (field on `Programme` model)
- Keep technical detail high, hype low — target a security-practitioner audience

**Example tweet format:**
```
Resolved: Stored XSS in [programme] search endpoint — CVSS 7.4
Patch shipped 2025-03-14. Report accepted in 4 days.
CVE-2025-XXXXX #BugBounty #XSS
```

---

## Pipeline position

```
... → TechnicalAuthor → [submission-approval] → DisclosureCoordinator
        → [disclosure-approval] → PublicRelationsAgent
```

The PR agent sits at the end, gated by a third `ApprovalGate` checkpoint
(`disclosure-approval`). This gate is separate from `submission-approval` —
the operator may approve submission but want to review the tweet draft before
it goes live.

---

## New config fields

```
TWITTER_BEARER_TOKEN=
TWITTER_ACCESS_TOKEN=
TWITTER_ACCESS_SECRET=
DISCLOSURE_WINDOW_DAYS=90   # default coordinated-disclosure window
PR_AGENT_ENABLED=true       # set false to skip PR agent entirely
```

---

## Implementation order

1. Add `DisclosureAnnouncement` to `models.py`
2. Extend `DisclosureCoordinator` with patch-tracking and eligibility logic
3. Add `disclosure-approval` checkpoint to `CHECKPOINT_INDICES` in `tasks.py`
4. Implement `tools/twitter_tools.py` with the three tools above
5. Create `squad/public_relations_agent/` with prompt and agent definition
6. Wire into `tasks.py` and `agents.py`
7. Add unit tests: tweet drafting, eligibility gate, metrics retrieval

---

## Open questions

- Should `get_tweet_metrics_tool` feed back into programme scoring in a future
  iteration? (e.g., high-engagement disclosures up-weight similar programme
  types in the Programme Manager's scoring)
- Should the PR agent operate on a schedule (poll for newly eligible
  disclosures) rather than as a pipeline step? If the squad runs multiple
  programmes in parallel this becomes important.
