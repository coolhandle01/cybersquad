"""tests/test_ledger.py — unit tests for the campaign filesystem ledger."""

from __future__ import annotations

from pathlib import Path

import pytest

from models import (
    CampaignMeta,
    FindingRecord,
    Severity,
    SubmissionRecord,
    SubmissionStatus,
)
from tools.ledger import (
    campaign_dir,
    latest_campaign,
    list_campaigns,
    list_programmes,
    list_submissions,
    read_campaign,
    read_findings,
    read_kickoff,
    read_retro,
    read_review,
    read_submission,
    update_submission,
    write_campaign,
    write_findings,
    write_kickoff,
    write_retro,
    write_review,
    write_submission,
)

pytestmark = pytest.mark.unit


@pytest.fixture()
def data_dir(tmp_path: Path) -> str:
    return str(tmp_path)


def _meta(handle: str = "acme-corp", campaign_date: str = "2026-04-20") -> CampaignMeta:
    return CampaignMeta(handle=handle, campaign_date=campaign_date)


def _submission(
    report_id: str = "1234",
    handle: str = "acme-corp",
    campaign_date: str = "2026-04-20",
) -> SubmissionRecord:
    return SubmissionRecord(
        h1_report_id=report_id,
        h1_url=f"https://hackerone.com/reports/{report_id}",
        programme_handle=handle,
        campaign_date=campaign_date,
        title="SQL injection in login",
        vuln_class="sqli",
        severity=Severity.HIGH,
    )


def _finding() -> FindingRecord:
    return FindingRecord(
        title="Information disclosure via debug endpoint",
        vuln_class="info_disclosure",
        target="https://api.acme.com/debug",
        severity=Severity.LOW,
        reason_not_submitted="below min severity",
    )


# ---------------------------------------------------------------------------
# campaign_dir helper
# ---------------------------------------------------------------------------


class TestCampaignDir:
    def test_returns_correct_path(self, data_dir: str) -> None:
        p = campaign_dir(data_dir, "acme-corp", "2026-04-20")
        assert p == Path(data_dir) / "programs" / "acme-corp" / "campaigns" / "2026-04-20"


# ---------------------------------------------------------------------------
# CampaignMeta
# ---------------------------------------------------------------------------


class TestCampaignIO:
    def test_write_then_read(self, data_dir: str) -> None:
        meta = _meta()
        write_campaign(meta, data_dir)
        loaded = read_campaign(data_dir, "acme-corp", "2026-04-20")
        assert loaded is not None
        assert loaded.handle == "acme-corp"
        assert loaded.phase == "kickoff"

    def test_read_missing_returns_none(self, data_dir: str) -> None:
        assert read_campaign(data_dir, "no-such", "2026-01-01") is None

    def test_write_creates_parent_dirs(self, data_dir: str) -> None:
        write_campaign(_meta(), data_dir)
        expected = (
            Path(data_dir) / "programs" / "acme-corp" / "campaigns" / "2026-04-20" / "campaign.json"
        )
        assert expected.exists()

    def test_latest_campaign_returns_newest(self, data_dir: str) -> None:
        write_campaign(_meta("acme-corp", "2026-04-01"), data_dir)
        write_campaign(_meta("acme-corp", "2026-04-20"), data_dir)
        latest = latest_campaign(data_dir, "acme-corp")
        assert latest is not None
        assert latest.campaign_date == "2026-04-20"

    def test_latest_campaign_missing_programme(self, data_dir: str) -> None:
        assert latest_campaign(data_dir, "ghost") is None

    def test_list_campaigns_newest_first(self, data_dir: str) -> None:
        for d in ("2026-04-01", "2026-04-10", "2026-04-20"):
            write_campaign(_meta("acme-corp", d), data_dir)
        campaigns = list_campaigns(data_dir, "acme-corp")
        dates = [c.campaign_date for c in campaigns]
        assert dates == ["2026-04-20", "2026-04-10", "2026-04-01"]

    def test_list_programmes(self, data_dir: str) -> None:
        write_campaign(_meta("acme-corp"), data_dir)
        write_campaign(_meta("beta-corp"), data_dir)
        handles = list_programmes(data_dir)
        assert "acme-corp" in handles
        assert "beta-corp" in handles


# ---------------------------------------------------------------------------
# SubmissionRecord
# ---------------------------------------------------------------------------


class TestSubmissionIO:
    def test_write_then_read(self, data_dir: str) -> None:
        rec = _submission()
        write_submission(rec, data_dir)
        loaded = read_submission(data_dir, "acme-corp", "2026-04-20", "1234")
        assert loaded is not None
        assert loaded.h1_report_id == "1234"
        assert loaded.vuln_class == "sqli"

    def test_read_missing_returns_none(self, data_dir: str) -> None:
        assert read_submission(data_dir, "acme-corp", "2026-04-20", "9999") is None

    def test_list_submissions(self, data_dir: str) -> None:
        write_submission(_submission("1001"), data_dir)
        write_submission(_submission("1002"), data_dir)
        subs = list_submissions(data_dir, "acme-corp", "2026-04-20")
        assert len(subs) == 2
        ids = {s.h1_report_id for s in subs}
        assert ids == {"1001", "1002"}

    def test_update_submission_patches_fields(self, data_dir: str) -> None:
        write_submission(_submission(), data_dir)
        updated = update_submission(
            data_dir,
            "acme-corp",
            "2026-04-20",
            "1234",
            status=SubmissionStatus.TRIAGED,
            bounty_awarded_usd=500.0,
        )
        assert updated is not None
        assert updated.status == SubmissionStatus.TRIAGED
        assert updated.bounty_awarded_usd == 500.0
        # Verify persisted
        reloaded = read_submission(data_dir, "acme-corp", "2026-04-20", "1234")
        assert reloaded is not None
        assert reloaded.bounty_awarded_usd == 500.0

    def test_update_missing_returns_none(self, data_dir: str) -> None:
        result = update_submission(
            data_dir, "acme-corp", "2026-04-20", "9999", status=SubmissionStatus.TRIAGED
        )
        assert result is None


# ---------------------------------------------------------------------------
# FindingRecord list
# ---------------------------------------------------------------------------


class TestFindingsIO:
    def test_write_then_read(self, data_dir: str) -> None:
        findings = [_finding(), _finding()]
        write_findings(findings, data_dir, "acme-corp", "2026-04-20")
        loaded = read_findings(data_dir, "acme-corp", "2026-04-20")
        assert len(loaded) == 2
        assert loaded[0].vuln_class == "info_disclosure"

    def test_read_missing_returns_empty(self, data_dir: str) -> None:
        assert read_findings(data_dir, "acme-corp", "2026-04-20") == []

    def test_write_empty_list(self, data_dir: str) -> None:
        write_findings([], data_dir, "acme-corp", "2026-04-20")
        assert read_findings(data_dir, "acme-corp", "2026-04-20") == []


# ---------------------------------------------------------------------------
# retro.md
# ---------------------------------------------------------------------------


class TestRetroIO:
    def test_write_then_read(self, data_dir: str) -> None:
        write_retro("# Retro\n\nAll good.", data_dir, "acme-corp", "2026-04-20")
        content = read_retro(data_dir, "acme-corp", "2026-04-20")
        assert content == "# Retro\n\nAll good."

    def test_read_missing_returns_none(self, data_dir: str) -> None:
        assert read_retro(data_dir, "acme-corp", "2026-04-20") is None


# ---------------------------------------------------------------------------
# kickoff.md
# ---------------------------------------------------------------------------


class TestKickoffIO:
    def test_write_then_read(self, data_dir: str) -> None:
        write_kickoff("# Kickoff\n\nReady.", data_dir, "acme-corp", "2026-04-20")
        content = read_kickoff(data_dir, "acme-corp", "2026-04-20")
        assert content == "# Kickoff\n\nReady."

    def test_read_missing_returns_none(self, data_dir: str) -> None:
        assert read_kickoff(data_dir, "acme-corp", "2026-04-20") is None


# ---------------------------------------------------------------------------
# review.md
# ---------------------------------------------------------------------------


class TestReviewIO:
    def test_write_then_read(self, data_dir: str) -> None:
        write_review("# Review\n\n$500 earned.", data_dir, "acme-corp", "2026-04-20")
        content = read_review(data_dir, "acme-corp", "2026-04-20")
        assert content == "# Review\n\n$500 earned."

    def test_read_missing_returns_none(self, data_dir: str) -> None:
        assert read_review(data_dir, "acme-corp", "2026-04-20") is None
