"""
flow.py — BountyFlow: the campaign loop that drives the Bounty Squad.

The Flow orchestrates the Crew across four Scrum-style phases per campaign:

  select_programme — Programme Manager picks the next eligible target.
  campaign_kickoff — Squad reviews history and agrees a sprint plan; human approves.
  standup          — Full crew hunts: recon → scan → triage → write → submit.
                     Loops until the token budget or submission cap is reached.
  campaign_review  — Stakeholder-facing sprint review; bounties reported; human gates.
  campaign_retro   — Team-internal lessons-learned debrief; hold-off date set.

After retro the Flow loops back to select_programme with a new target, running
indefinitely until interrupted.  CampaignState persists across phases so a
restart resumes the current campaign rather than starting from scratch.

Stop conditions (evaluated at the start of each standup):
  - Token budget for this sprint exhausted
  - Maximum submissions for this programme reached
"""

from __future__ import annotations

import logging
from datetime import date, datetime

from crewai.flow import listen, router, start
from crewai.flow.flow import Flow, FlowState
from pydantic import Field

from config import config
from models import CampaignMeta, SubmissionStatus
from tools.h1_api import h1
from tools.ledger import (
    list_campaigns,
    list_submissions,
    update_submission,
    write_campaign,
    write_kickoff,
    write_retro,
    write_review,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Flow state — survives restarts via FlowPersistence
# ---------------------------------------------------------------------------


class CampaignState(FlowState):
    # Current target
    handle: str = ""
    campaign_date: str = ""

    # Cross-campaign tracking
    attempted_handles: list[str] = Field(default_factory=list)

    # Sprint counters (reset each select_programme)
    sprint_tokens: int = 0
    sprint_submissions: int = 0

    # Cumulative totals
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_submissions: int = 0

    # Stop-condition config (populated at kickoff from programme bounty table)
    token_budget_per_sprint: int = Field(default_factory=lambda: 500_000)
    max_submissions_per_sprint: int = Field(default_factory=lambda: 5)


# ---------------------------------------------------------------------------
# The Flow
# ---------------------------------------------------------------------------


class BountyFlow(Flow[CampaignState]):
    """Continuous campaign loop: select → kickoff → standup → review → retro → select → …"""

    # ── Phase 1: Select programme ─────────────────────────────────────────

    @start()
    def select_programme(self) -> str:
        """
        Programme Manager picks the next eligible target.

        Excludes recently-attempted programmes and those still within their
        do_not_revisit_before hold.  Initialises campaign.json on disk.
        """
        logger.info("=== SELECT PROGRAMME ===")

        from crew import build_crew

        crew = build_crew(phase="select_programme")

        result = crew.kickoff(
            inputs={
                "phase": "select_programme",
                "exclude_handles": self.state.attempted_handles,
            }
        )

        self.state.handle = self._extract_handle(result)
        self.state.campaign_date = date.today().isoformat()
        self.state.sprint_tokens = 0
        self.state.sprint_submissions = 0

        meta = CampaignMeta(
            handle=self.state.handle,
            campaign_date=self.state.campaign_date,
            phase="select_programme",
        )
        write_campaign(meta, config.reports_dir)

        logger.info(
            "Target selected: %s  campaign: %s", self.state.handle, self.state.campaign_date
        )
        return "campaign_kickoff"

    # ── Phase 2: Kickoff ──────────────────────────────────────────────────

    @listen("campaign_kickoff")
    def campaign_kickoff(self) -> None:
        """
        Squad reviews history and agrees on a plan for the sprint.

        Programme Manager briefs the team with reviews and retros from the
        last three campaigns on this programme.  human_input=True on the PM
        task gates progress so the operator can approve the plan or redirect
        the squad before hunting begins.
        Output: kickoff.md
        """
        logger.info("=== KICKOFF  %s / %s ===", self.state.handle, self.state.campaign_date)

        previous_context = self._build_previous_context(self.state.handle)

        from crew import build_crew

        crew = build_crew(phase="campaign_kickoff")

        result = crew.kickoff(
            inputs={
                "phase": "campaign_kickoff",
                "programme_handle": self.state.handle,
                "campaign_date": self.state.campaign_date,
                "previous_context": previous_context,
            }
        )

        self._update_counters(result)

        write_kickoff(
            str(getattr(result, "raw", "")) or self._generate_kickoff_stub(),
            config.reports_dir,
            self.state.handle,
            self.state.campaign_date,
        )

        meta = CampaignMeta(
            handle=self.state.handle,
            campaign_date=self.state.campaign_date,
            phase="kickoff",
            total_tokens=self.state.total_tokens,
            cost_usd=self.state.total_cost_usd,
        )
        write_campaign(meta, config.reports_dir)

        logger.info("Kickoff complete — squad is briefed and ready")

    # ── Phase 3: Standup (hunt loop) ──────────────────────────────────────

    @listen(campaign_kickoff)
    def standup(self) -> None:
        """
        Full crew hunt: OSINT → scan → triage → write → submit.

        Bounded by token budget and max-submissions-per-sprint stop conditions.
        TechnicalAuthor task has human_input=True so the operator can review
        each report draft before it is submitted.
        Writes each submission to submissions/<report_id>.json.
        """
        logger.info("=== STANDUP  %s / %s ===", self.state.handle, self.state.campaign_date)

        if self._over_budget():
            logger.info("Token budget exhausted — skipping standup")
            return

        from crew import build_crew

        crew = build_crew(phase="standup")

        result = crew.kickoff(
            inputs={
                "phase": "standup",
                "programme_handle": self.state.handle,
                "campaign_date": self.state.campaign_date,
                "previous_context": self._build_previous_context(self.state.handle),
                "max_submissions": self.state.max_submissions_per_sprint,
            }
        )

        self._update_counters(result)

        meta = CampaignMeta(
            handle=self.state.handle,
            campaign_date=self.state.campaign_date,
            phase="standup",
            total_tokens=self.state.total_tokens,
            cost_usd=self.state.total_cost_usd,
        )
        write_campaign(meta, config.reports_dir)

    # ── Router: keep hunting or move to review ────────────────────────────

    @router(standup)
    def assess(self) -> str:
        """
        After each standup: continue hunting or move to sprint review?

        Loops back to standup while submissions are below the cap and the token
        budget is not exhausted.  Routes to campaign_review when done.
        """
        if (
            self.state.sprint_submissions < self.state.max_submissions_per_sprint
            and not self._over_budget()
        ):
            logger.info("Still within budget — continuing standup")
            return "standup"

        logger.info("Sprint complete — moving to review")
        return "campaign_review"

    # ── Phase 4: Sprint review (stakeholder-facing) ───────────────────────

    @listen("campaign_review")
    def campaign_review(self) -> None:
        """
        Stakeholder sprint review: cost, submissions, and bounties earned.

        Polls H1 for the latest report statuses, produces review.md, then
        gates on human_input=True so the operator can acknowledge results and
        leave feedback before the retrospective.
        Output: review.md
        """
        logger.info("=== REVIEW  %s / %s ===", self.state.handle, self.state.campaign_date)

        self._poll_and_update_submissions()

        subs = list_submissions(config.reports_dir, self.state.handle, self.state.campaign_date)
        total_bounty = sum(s.bounty_awarded_usd or 0.0 for s in subs)
        submissions_text = (
            "\n".join(
                f"- #{s.h1_report_id} **{s.title}** ({s.severity}) — {s.status}"
                + (
                    f" — ${s.bounty_awarded_usd:.2f}"
                    if s.bounty_awarded_usd
                    else " — bounty pending"
                )
                for s in subs
            )
            or "_No submissions this sprint._"
        )

        from crew import build_crew

        crew = build_crew(phase="campaign_review")

        result = crew.kickoff(
            inputs={
                "phase": "campaign_review",
                "programme_handle": self.state.handle,
                "campaign_date": self.state.campaign_date,
                "submissions": submissions_text,
                "total_cost_usd": f"{self.state.total_cost_usd:.4f}",
                "total_tokens": f"{self.state.total_tokens:,}",
                "total_bounty_usd": f"{total_bounty:.2f}",
            }
        )

        self._update_counters(result)

        write_review(
            str(getattr(result, "raw", "")) or self._generate_review_stub(),
            config.reports_dir,
            self.state.handle,
            self.state.campaign_date,
        )

        meta = CampaignMeta(
            handle=self.state.handle,
            campaign_date=self.state.campaign_date,
            phase="review",
            total_tokens=self.state.total_tokens,
            cost_usd=self.state.total_cost_usd,
        )
        write_campaign(meta, config.reports_dir)

        logger.info("Review complete — moving to retro")

    # ── Phase 5: Retrospective (team-internal) ────────────────────────────

    @listen(campaign_review)
    def campaign_retro(self) -> None:
        """
        Team-internal debrief: lessons learned and surface notes.

        No human gate — the squad records what they learned for the next time
        this programme is targeted.  Sets do_not_revisit_before and marks the
        campaign complete.
        Output: retro.md
        """
        logger.info("=== RETRO  %s / %s ===", self.state.handle, self.state.campaign_date)

        subs = list_submissions(config.reports_dir, self.state.handle, self.state.campaign_date)
        submissions_text = (
            "\n".join(
                f"- #{s.h1_report_id} **{s.title}** ({s.severity}) — {s.status}"
                + (
                    f" — ${s.bounty_awarded_usd:.2f}"
                    if s.bounty_awarded_usd
                    else " — bounty pending"
                )
                for s in subs
            )
            or "_No submissions this sprint._"
        )

        from crew import build_crew

        crew = build_crew(phase="campaign_retro")

        result = crew.kickoff(
            inputs={
                "phase": "campaign_retro",
                "programme_handle": self.state.handle,
                "campaign_date": self.state.campaign_date,
                "submissions": submissions_text,
                "previous_context": self._build_previous_context(self.state.handle),
            }
        )

        self._update_counters(result)

        write_retro(
            str(getattr(result, "raw", "")) or self._generate_retro_stub(),
            config.reports_dir,
            self.state.handle,
            self.state.campaign_date,
        )

        self.state.attempted_handles.append(self.state.handle)

        revisit_after = config.scan.revisit_hold_days
        meta = CampaignMeta(
            handle=self.state.handle,
            campaign_date=self.state.campaign_date,
            phase="complete",
            completed_at=datetime.utcnow(),
            total_tokens=self.state.total_tokens,
            cost_usd=self.state.total_cost_usd,
            do_not_revisit_before=date.today().__class__.fromordinal(
                date.today().toordinal() + revisit_after
            ),
        )
        write_campaign(meta, config.reports_dir)

        logger.info(
            "Retro complete. Submissions this campaign: %d  Total cost: $%.4f",
            self.state.sprint_submissions,
            self.state.total_cost_usd,
        )

    # ── Loop back ─────────────────────────────────────────────────────────

    @router(campaign_retro)
    def next_campaign(self) -> str:
        """Reset sprint counters and loop back to programme selection."""
        self.state.handle = ""
        self.state.campaign_date = ""
        self.state.sprint_tokens = 0
        self.state.sprint_submissions = 0
        return "select_programme"

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _build_previous_context(self, handle: str) -> str:
        """Assemble review notes, retro notes, and stats from prior campaigns."""
        if not handle:
            return ""
        campaigns = list_campaigns(config.reports_dir, handle)
        if not campaigns:
            return ""

        parts: list[str] = []
        for campaign in campaigns[:3]:  # last 3 campaigns
            from tools.ledger import read_retro, read_review

            review = read_review(config.reports_dir, handle, campaign.campaign_date)
            retro = read_retro(config.reports_dir, handle, campaign.campaign_date)
            subs = list_submissions(config.reports_dir, handle, campaign.campaign_date)
            section = (
                f"## Campaign {campaign.campaign_date}\n"
                f"Submissions: {len(subs)}  Cost: ${campaign.cost_usd:.4f}\n"
            )
            if review:
                section += f"\n### Review\n{review}\n"
            if retro:
                section += f"\n### Retro\n{retro}\n"
            parts.append(section)
        return "\n\n".join(parts)

    def _over_budget(self) -> bool:
        return self.state.sprint_tokens >= self.state.token_budget_per_sprint

    def _update_counters(self, result: object) -> None:
        """Extract token usage from CrewOutput and update state."""
        try:
            usage = getattr(result, "token_usage", None)
            tokens = getattr(usage, "total_tokens", 0) if usage else 0
        except Exception:
            tokens = 0
        self.state.sprint_tokens += tokens
        self.state.total_tokens += tokens
        from tools.metrics import estimate_cost

        self.state.total_cost_usd += estimate_cost(config.llm.model, tokens, 0)

    def _poll_and_update_submissions(self) -> None:
        """Poll H1 for current status of all submissions in this campaign."""
        subs = list_submissions(config.reports_dir, self.state.handle, self.state.campaign_date)
        if not subs:
            return
        try:
            live = {r["id"]: r for r in h1.list_reports(programme_handle=self.state.handle)}
        except Exception as exc:
            logger.warning("Could not poll H1 for report status: %s", exc)
            return

        for sub in subs:
            raw = live.get(sub.h1_report_id)
            if not raw:
                continue
            attrs = raw.get("attributes", {})
            state_str = attrs.get("state", "")
            status_map = {
                "new": SubmissionStatus.SUBMITTED,
                "triaged": SubmissionStatus.TRIAGED,
                "resolved": SubmissionStatus.RESOLVED,
                "duplicate": SubmissionStatus.DUPLICATE,
                "not-applicable": SubmissionStatus.NOT_APPLICABLE,
                "informative": SubmissionStatus.INFORMATIVE,
            }
            new_status = status_map.get(state_str, sub.status)
            bounty = attrs.get("bounty_amount")
            update_submission(
                config.reports_dir,
                self.state.handle,
                self.state.campaign_date,
                sub.h1_report_id,
                status=new_status,
                bounty_awarded_usd=float(bounty) if bounty else sub.bounty_awarded_usd,
                bounty_updated_at=datetime.utcnow() if bounty else sub.bounty_updated_at,
            )

    def _extract_handle(self, result: object) -> str:
        """Extract programme handle from crew output. TODO: structured output."""
        raw = str(getattr(result, "raw", result))
        return raw.strip().split()[0] if raw.strip() else "unknown"

    def _generate_kickoff_stub(self) -> str:
        """Minimal kickoff.md until the crew kickoff task is wired in."""
        lines = [
            f"# Kickoff — {self.state.handle} / {self.state.campaign_date}",
            "",
            "## Sprint plan",
            "",
            "_To be populated by the Programme Manager at kickoff._",
        ]
        return "\n".join(lines)

    def _generate_review_stub(self) -> str:
        """Minimal review.md until the crew review task is wired in."""
        subs = list_submissions(config.reports_dir, self.state.handle, self.state.campaign_date)
        total_bounty = sum(s.bounty_awarded_usd or 0.0 for s in subs)
        lines = [
            f"# Sprint Review — {self.state.handle} / {self.state.campaign_date}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Submissions | {len(subs)} |",
            f"| Tokens spent | {self.state.total_tokens:,} |",
            f"| Estimated cost | ${self.state.total_cost_usd:.4f} |",
            f"| Bounties awarded | ${total_bounty:.2f} |",
            "",
            "## Submissions",
        ]
        for s in subs:
            bounty = f"${s.bounty_awarded_usd:.2f}" if s.bounty_awarded_usd else "pending"
            lines.append(
                f"- [{s.h1_report_id}]({s.h1_url}) **{s.title}**"
                f" — {s.severity} — {s.status} {bounty}"
            )
        lines += ["", "## Feedback", "", "_Operator feedback to be recorded here._"]
        return "\n".join(lines)

    def _generate_retro_stub(self) -> str:
        """Minimal retro.md until the crew retro task is wired in."""
        subs = list_submissions(config.reports_dir, self.state.handle, self.state.campaign_date)
        lines = [
            f"# Retro — {self.state.handle} / {self.state.campaign_date}",
            "",
            f"**Submissions:** {len(subs)}",
            f"**Tokens spent:** {self.state.total_tokens:,}",
            f"**Estimated cost:** ${self.state.total_cost_usd:.4f}",
            "",
            "## Submissions",
        ]
        for s in subs:
            bounty = f"${s.bounty_awarded_usd:.2f}" if s.bounty_awarded_usd else "pending"
            lines.append(f"- [{s.h1_report_id}]({s.h1_url}) {s.title} — {s.status} {bounty}")
        lines += ["", "## Notes", "", "_To be completed by squad._"]
        return "\n".join(lines)
