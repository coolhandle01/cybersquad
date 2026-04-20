"""tests/test_flow.py — unit tests for BountyFlow helper methods."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from flow import BountyFlow, CampaignState
from models import CampaignMeta, Severity, SubmissionRecord, SubmissionStatus

pytestmark = pytest.mark.unit


@pytest.fixture()
def flow() -> BountyFlow:
    f = BountyFlow()
    f.state.handle = "acme-corp"
    f.state.campaign_date = "2026-04-20"
    f.state.total_tokens = 1000
    f.state.total_cost_usd = 0.05
    return f


def _sub(report_id: str = "1234") -> SubmissionRecord:
    return SubmissionRecord(
        h1_report_id=report_id,
        h1_url=f"https://hackerone.com/reports/{report_id}",
        programme_handle="acme-corp",
        campaign_date="2026-04-20",
        title="XSS in login",
        vuln_class="xss",
        severity=Severity.HIGH,
    )


# ---------------------------------------------------------------------------
# _over_budget
# ---------------------------------------------------------------------------


class TestOverBudget:
    def test_under_budget(self, flow: BountyFlow) -> None:
        flow.state.sprint_tokens = 100
        flow.state.token_budget_per_sprint = 500_000
        assert flow._over_budget() is False

    def test_exactly_at_limit(self, flow: BountyFlow) -> None:
        flow.state.sprint_tokens = 500_000
        flow.state.token_budget_per_sprint = 500_000
        assert flow._over_budget() is True

    def test_over_limit(self, flow: BountyFlow) -> None:
        flow.state.sprint_tokens = 600_000
        flow.state.token_budget_per_sprint = 500_000
        assert flow._over_budget() is True


# ---------------------------------------------------------------------------
# _extract_handle
# ---------------------------------------------------------------------------


class TestExtractHandle:
    def test_extracts_first_word(self, flow: BountyFlow) -> None:
        result = MagicMock()
        result.raw = "acme-corp Some other text"
        assert flow._extract_handle(result) == "acme-corp"

    def test_single_word(self, flow: BountyFlow) -> None:
        result = MagicMock()
        result.raw = "beta-org"
        assert flow._extract_handle(result) == "beta-org"

    def test_empty_raw_returns_unknown(self, flow: BountyFlow) -> None:
        result = MagicMock()
        result.raw = "   "
        assert flow._extract_handle(result) == "unknown"

    def test_no_raw_attribute_falls_back_to_str(self, flow: BountyFlow) -> None:
        result = "gamma-corp something"
        assert flow._extract_handle(result) == "gamma-corp"


# ---------------------------------------------------------------------------
# _generate_retro_stub
# ---------------------------------------------------------------------------


class TestGenerateRetroStub:
    def test_contains_handle_and_date(self, flow: BountyFlow) -> None:
        with patch("flow.list_submissions", return_value=[]):
            content = flow._generate_retro_stub()
        assert "acme-corp" in content
        assert "2026-04-20" in content

    def test_lists_submissions(self, flow: BountyFlow) -> None:
        subs = [_sub("1001"), _sub("1002")]
        with patch("flow.list_submissions", return_value=subs):
            content = flow._generate_retro_stub()
        assert "1001" in content
        assert "1002" in content

    def test_bounty_pending_when_none(self, flow: BountyFlow) -> None:
        with patch("flow.list_submissions", return_value=[_sub()]):
            content = flow._generate_retro_stub()
        assert "pending" in content

    def test_bounty_shown_when_set(self, flow: BountyFlow) -> None:
        sub = _sub()
        sub = sub.model_copy(update={"bounty_awarded_usd": 750.0})
        with patch("flow.list_submissions", return_value=[sub]):
            content = flow._generate_retro_stub()
        assert "$750.00" in content


# ---------------------------------------------------------------------------
# _build_previous_context
# ---------------------------------------------------------------------------


class TestBuildPreviousContext:
    def test_empty_handle_returns_empty(self, flow: BountyFlow) -> None:
        assert flow._build_previous_context("") == ""

    def test_no_campaigns_returns_empty(self, flow: BountyFlow) -> None:
        with patch("flow.list_campaigns", return_value=[]):
            assert flow._build_previous_context("acme-corp") == ""

    def test_includes_campaign_date_and_submissions(self, flow: BountyFlow) -> None:
        meta = CampaignMeta(handle="acme-corp", campaign_date="2026-04-01", cost_usd=0.10)
        with (
            patch("flow.list_campaigns", return_value=[meta]),
            patch("tools.ledger.read_retro", return_value=None),
            patch("tools.ledger.read_review", return_value=None),
            patch("flow.list_submissions", return_value=[_sub()]),
        ):
            ctx = flow._build_previous_context("acme-corp")
        assert "2026-04-01" in ctx
        assert "Submissions: 1" in ctx

    def test_includes_retro_when_present(self, flow: BountyFlow) -> None:
        meta = CampaignMeta(handle="acme-corp", campaign_date="2026-04-01")
        with (
            patch("flow.list_campaigns", return_value=[meta]),
            patch("tools.ledger.read_retro", return_value="# Retro notes"),
            patch("tools.ledger.read_review", return_value=None),
            patch("flow.list_submissions", return_value=[]),
        ):
            ctx = flow._build_previous_context("acme-corp")
        assert "Retro notes" in ctx

    def test_includes_review_when_present(self, flow: BountyFlow) -> None:
        meta = CampaignMeta(handle="acme-corp", campaign_date="2026-04-01")
        with (
            patch("flow.list_campaigns", return_value=[meta]),
            patch("tools.ledger.read_retro", return_value=None),
            patch("tools.ledger.read_review", return_value="# Review notes"),
            patch("flow.list_submissions", return_value=[]),
        ):
            ctx = flow._build_previous_context("acme-corp")
        assert "Review notes" in ctx

    def test_caps_at_three_campaigns(self, flow: BountyFlow) -> None:
        metas = [
            CampaignMeta(handle="acme-corp", campaign_date=f"2026-0{i}-01") for i in range(1, 6)
        ]
        with (
            patch("flow.list_campaigns", return_value=metas),
            patch("tools.ledger.read_retro", return_value=None),
            patch("tools.ledger.read_review", return_value=None),
            patch("flow.list_submissions", return_value=[]),
        ):
            ctx = flow._build_previous_context("acme-corp")
        # Only first 3 campaigns should appear
        assert "2026-01-01" in ctx
        assert "2026-02-01" in ctx
        assert "2026-03-01" in ctx
        assert "2026-04-01" not in ctx


# ---------------------------------------------------------------------------
# _update_counters
# ---------------------------------------------------------------------------


class TestUpdateCounters:
    def test_tokens_added_to_state(self, flow: BountyFlow) -> None:
        usage = MagicMock()
        usage.total_tokens = 200
        result = MagicMock()
        result.token_usage = usage

        with patch("tools.metrics.estimate_cost", return_value=0.01):
            flow._update_counters(result)

        assert flow.state.sprint_tokens == 200
        assert flow.state.total_tokens == 1200  # was 1000

    def test_missing_token_usage_adds_zero(self, flow: BountyFlow) -> None:
        result = MagicMock(spec=[])  # no token_usage attribute

        with patch("tools.metrics.estimate_cost", return_value=0.0):
            flow._update_counters(result)

        assert flow.state.sprint_tokens == 0

    def test_cost_accumulated(self, flow: BountyFlow) -> None:
        usage = MagicMock()
        usage.total_tokens = 0
        result = MagicMock()
        result.token_usage = usage

        with patch("tools.metrics.estimate_cost", return_value=0.05):
            flow._update_counters(result)

        assert abs(flow.state.total_cost_usd - 0.10) < 1e-9


# ---------------------------------------------------------------------------
# _poll_and_update_submissions
# ---------------------------------------------------------------------------


class TestPollAndUpdateSubmissions:
    def test_no_submissions_skips_poll(self, flow: BountyFlow) -> None:
        with (
            patch("flow.list_submissions", return_value=[]),
            patch("flow.h1") as mock_h1,
        ):
            flow._poll_and_update_submissions()
            mock_h1.list_reports.assert_not_called()

    def test_updates_status_from_h1(self, flow: BountyFlow) -> None:
        sub = _sub("1234")
        live = {
            "1234": {
                "id": "1234",
                "attributes": {"state": "triaged", "bounty_amount": None},
            }
        }
        with (
            patch("flow.list_submissions", return_value=[sub]),
            patch("flow.h1") as mock_h1,
            patch("flow.update_submission") as mock_update,
        ):
            mock_h1.list_reports.return_value = list(live.values())
            # Patch the dict comprehension — h1 returns list of dicts with "id"
            # The real code does: {r["id"]: r for r in h1.list_reports(...)}
            flow._poll_and_update_submissions()
            mock_update.assert_called_once()
            kwargs = mock_update.call_args
            assert kwargs.kwargs.get("status") == SubmissionStatus.TRIAGED

    def test_h1_error_logged_gracefully(self, flow: BountyFlow) -> None:
        with (
            patch("flow.list_submissions", return_value=[_sub()]),
            patch("flow.h1") as mock_h1,
            patch("flow.update_submission") as mock_update,
        ):
            mock_h1.list_reports.side_effect = RuntimeError("network error")
            flow._poll_and_update_submissions()  # should not raise
            mock_update.assert_not_called()

    def test_unknown_h1_report_skipped(self, flow: BountyFlow) -> None:
        sub = _sub("9999")
        with (
            patch("flow.list_submissions", return_value=[sub]),
            patch("flow.h1") as mock_h1,
            patch("flow.update_submission") as mock_update,
        ):
            mock_h1.list_reports.return_value = []
            flow._poll_and_update_submissions()
            mock_update.assert_not_called()


# ---------------------------------------------------------------------------
# _generate_kickoff_stub
# ---------------------------------------------------------------------------


class TestGenerateKickoffStub:
    def test_contains_handle_and_date(self, flow: BountyFlow) -> None:
        content = flow._generate_kickoff_stub()
        assert "acme-corp" in content
        assert "2026-04-20" in content

    def test_contains_sprint_plan_placeholder(self, flow: BountyFlow) -> None:
        assert "Sprint plan" in flow._generate_kickoff_stub()


# ---------------------------------------------------------------------------
# _generate_review_stub
# ---------------------------------------------------------------------------


class TestGenerateReviewStub:
    def test_contains_handle_and_date(self, flow: BountyFlow) -> None:
        with patch("flow.list_submissions", return_value=[]):
            content = flow._generate_review_stub()
        assert "acme-corp" in content
        assert "2026-04-20" in content

    def test_shows_cost_and_token_totals(self, flow: BountyFlow) -> None:
        with patch("flow.list_submissions", return_value=[]):
            content = flow._generate_review_stub()
        assert "1,000" in content  # total_tokens formatted
        assert "$0.05" in content  # total_cost_usd

    def test_sums_bounties(self, flow: BountyFlow) -> None:
        subs = [
            _sub("1001").model_copy(update={"bounty_awarded_usd": 300.0}),
            _sub("1002").model_copy(update={"bounty_awarded_usd": 200.0}),
        ]
        with patch("flow.list_submissions", return_value=subs):
            content = flow._generate_review_stub()
        assert "$500.00" in content  # total bounty

    def test_pending_shown_when_no_bounty(self, flow: BountyFlow) -> None:
        with patch("flow.list_submissions", return_value=[_sub()]):
            content = flow._generate_review_stub()
        assert "pending" in content

    def test_contains_feedback_section(self, flow: BountyFlow) -> None:
        with patch("flow.list_submissions", return_value=[]):
            content = flow._generate_review_stub()
        assert "Feedback" in content


# ---------------------------------------------------------------------------
# CampaignState defaults
# ---------------------------------------------------------------------------


class TestCampaignState:
    def test_default_budgets(self) -> None:
        state = CampaignState()
        assert state.token_budget_per_sprint == 500_000
        assert state.max_submissions_per_sprint == 5

    def test_empty_strings_for_handle_and_date(self) -> None:
        state = CampaignState()
        assert state.handle == ""
        assert state.campaign_date == ""
