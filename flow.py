"""
flow.py — BountyFlow: the campaign loop that drives the Bounty Squad.

The Flow orchestrates the Crew across three recurring phases:

  kickoff  — Programme Manager selects a target and briefs the squad.
  standup  — The full crew hunts: recon → scan → triage → write → submit.
  retro    — Squad debriefs, writes campaign files, updates submission status.

After retro the Flow loops back to kickoff with a new target, running
indefinitely until interrupted.  CampaignState persists across phases so a
restart resumes the current campaign rather than starting from scratch.

Stop conditions (evaluated at the start of each standup):
  - Token budget for this sprint exhausted
  - Maximum submissions for this programme reached
  - do_not_revisit_before not yet elapsed (skips programme entirely)
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
    write_retro,
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

    # Sprint counters (reset each standup)
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
    """Continuous campaign loop: kickoff → standup → retro → kickoff → …"""

    # ── Phase 1: Kickoff ──────────────────────────────────────────────────

    @start()
    def select_programme(self) -> str:
        """
        Programme Manager selects the next eligible target and briefs the squad.

        Reads previous campaign files so the squad knows what was already found,
        what the attack surface looked like, and what was submitted last time.
        """
        logger.info("=== KICKOFF ===")

        # Build context from previous campaigns for this handle (if revisiting)
        previous_context = self._build_previous_context(self.state.handle)

        # Import here to avoid circular deps at module level
        from crew import build_crew

        crew = build_crew()

        # TODO: update Programme Manager prompt to accept:
        #   - exclude_handles: programmes to skip this round
        #   - previous_context: retro notes and surface from last campaign
        result = crew.kickoff(
            inputs={
                "phase": "kickoff",
                "exclude_handles": self.state.attempted_handles,
                "previous_context": previous_context,
            }
        )

        # Extract selected programme handle from crew output
        # TODO: make Programme Manager emit structured output with handle
        self.state.handle = self._extract_handle(result)
        self.state.campaign_date = date.today().isoformat()
        self.state.sprint_tokens = 0
        self.state.sprint_submissions = 0

        # Initialise campaign.json on disk
        meta = CampaignMeta(
            handle=self.state.handle,
            campaign_date=self.state.campaign_date,
            phase="kickoff",
        )
        write_campaign(meta, config.reports_dir)

        logger.info(
            "Target selected: %s  campaign: %s", self.state.handle, self.state.campaign_date
        )
        return "standup"

    # ── Phase 2: Standup (the hunt) ───────────────────────────────────────

    @listen("select_programme")
    def standup(self) -> None:
        """
        Full crew hunt: OSINT → scan → triage → write → submit.

        Bounded by token budget and max-submissions-per-sprint stop conditions.
        Writes each submission to disk as submissions/<report_id>.json.
        """
        logger.info("=== STANDUP  %s / %s ===", self.state.handle, self.state.campaign_date)

        if self._over_budget():
            logger.info("Token budget exhausted — skipping standup, going to retro")
            return

        from crew import build_crew

        crew = build_crew()

        # Read previous context for this programme
        previous_context = self._build_previous_context(self.state.handle)

        # TODO: parameterise crew phases so only the hunting agents run here
        result = crew.kickoff(
            inputs={
                "phase": "standup",
                "programme_handle": self.state.handle,
                "campaign_date": self.state.campaign_date,
                "previous_context": previous_context,
                "max_submissions": self.state.max_submissions_per_sprint,
            }
        )

        # TODO: extract structured SubmissionResult list from crew output
        # For now, update counters from result metadata
        self._update_counters(result)

        # Update campaign.json phase
        meta = CampaignMeta(
            handle=self.state.handle,
            campaign_date=self.state.campaign_date,
            phase="standup",
            total_tokens=self.state.total_tokens,
            cost_usd=self.state.total_cost_usd,
        )
        write_campaign(meta, config.reports_dir)

    # ── Router: decide whether to keep hunting or wrap up ─────────────────

    @router(standup)
    def assess(self) -> str:
        """
        After standup: keep hunting the same programme or move to retro?

        Continues hunting if we haven't hit the submission cap and we're still
        within budget.  Otherwise triggers retro.
        """
        if (
            self.state.sprint_submissions < self.state.max_submissions_per_sprint
            and not self._over_budget()
        ):
            logger.info("Still within budget — continuing standup")
            return "standup"

        logger.info("Sprint complete — moving to retro")
        return "retro"

    # ── Phase 3: Retro ────────────────────────────────────────────────────

    @listen("retro")
    def retro(self) -> None:
        """
        Squad debrief: poll H1 for status updates, write retro.md and
        findings.json, set do_not_revisit_before, loop back to kickoff.
        """
        logger.info("=== RETRO  %s / %s ===", self.state.handle, self.state.campaign_date)

        # Poll H1 for current status of all submissions from this campaign
        self._poll_and_update_submissions()

        # Run a lightweight retro crew pass to produce retro.md
        # TODO: wire in a Programme Manager retro task that reads findings and
        #       produces a markdown debrief
        retro_content = self._generate_retro_stub()
        write_retro(retro_content, config.reports_dir, self.state.handle, self.state.campaign_date)

        # Mark programme as attempted; set revisit hold-off
        self.state.attempted_handles.append(self.state.handle)

        # Finalise campaign.json
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

    # Loop back after retro
    @router(retro)
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
        """Assemble retro notes and surface data from prior campaigns."""
        if not handle:
            return ""
        campaigns = list_campaigns(config.reports_dir, handle)
        if not campaigns:
            return ""

        parts: list[str] = []
        for campaign in campaigns[:3]:  # last 3 campaigns
            from tools.ledger import read_retro

            retro = read_retro(config.reports_dir, handle, campaign.campaign_date)
            subs = list_submissions(config.reports_dir, handle, campaign.campaign_date)
            parts.append(
                f"## Campaign {campaign.campaign_date}\n"
                f"Submissions: {len(subs)}  Cost: ${campaign.cost_usd:.4f}\n"
                + (f"\n{retro}" if retro else "")
            )
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
        # Placeholder — Programme Manager prompt update will make this reliable
        return raw.strip().split()[0] if raw.strip() else "unknown"

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
