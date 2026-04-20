"""
tools/ledger.py — Filesystem I/O for the campaign data structure.

Layout under DATA_DIR:
    programs/<handle>/campaigns/<YYYY-MM-DD>/campaign.json
    programs/<handle>/campaigns/<YYYY-MM-DD>/findings.json
    programs/<handle>/campaigns/<YYYY-MM-DD>/retro.md
    programs/<handle>/campaigns/<YYYY-MM-DD>/submissions/<report_id>.json
    programs/<handle>/campaigns/<YYYY-MM-DD>/logs/
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from models import CampaignMeta, FindingRecord, SubmissionRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def campaign_dir(data_dir: str, handle: str, campaign_date: str) -> Path:
    return Path(data_dir) / "programs" / handle / "campaigns" / campaign_date


def submissions_dir(data_dir: str, handle: str, campaign_date: str) -> Path:
    return campaign_dir(data_dir, handle, campaign_date) / "submissions"


def logs_dir(data_dir: str, handle: str, campaign_date: str) -> Path:
    return campaign_dir(data_dir, handle, campaign_date) / "logs"


# ---------------------------------------------------------------------------
# CampaignMeta (campaign.json)
# ---------------------------------------------------------------------------


def write_campaign(meta: CampaignMeta, data_dir: str) -> Path:
    """Write or overwrite campaign.json for this campaign."""
    path = campaign_dir(data_dir, meta.handle, meta.campaign_date) / "campaign.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(meta.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    logger.debug("Wrote campaign meta → %s", path)
    return path


def read_campaign(data_dir: str, handle: str, campaign_date: str) -> CampaignMeta | None:
    """Load campaign.json; returns None if it doesn't exist."""
    path = campaign_dir(data_dir, handle, campaign_date) / "campaign.json"
    if not path.exists():
        return None
    return CampaignMeta.model_validate_json(path.read_text(encoding="utf-8"))


def latest_campaign(data_dir: str, handle: str) -> CampaignMeta | None:
    """Return the most recent campaign for a programme, or None."""
    base = Path(data_dir) / "programs" / handle / "campaigns"
    if not base.exists():
        return None
    dates = sorted(
        (d.name for d in base.iterdir() if d.is_dir() and (d / "campaign.json").exists()),
        reverse=True,
    )
    if not dates:
        return None
    return read_campaign(data_dir, handle, dates[0])


def list_campaigns(data_dir: str, handle: str) -> list[CampaignMeta]:
    """Return all campaigns for a programme, newest first."""
    base = Path(data_dir) / "programs" / handle / "campaigns"
    if not base.exists():
        return []
    campaigns = []
    for d in sorted(base.iterdir(), reverse=True):
        if d.is_dir():
            meta = read_campaign(data_dir, handle, d.name)
            if meta:
                campaigns.append(meta)
    return campaigns


def list_programmes(data_dir: str) -> list[str]:
    """Return all programme handles that have at least one campaign."""
    base = Path(data_dir) / "programs"
    if not base.exists():
        return []
    return sorted(d.name for d in base.iterdir() if d.is_dir())


# ---------------------------------------------------------------------------
# SubmissionRecord (submissions/<report_id>.json)
# ---------------------------------------------------------------------------


def write_submission(record: SubmissionRecord, data_dir: str) -> Path:
    """Write a submission record; creates the submissions/ directory if needed."""
    path = (
        submissions_dir(data_dir, record.programme_handle, record.campaign_date)
        / f"{record.h1_report_id}.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    logger.debug("Wrote submission %s → %s", record.h1_report_id, path)
    return path


def read_submission(
    data_dir: str, handle: str, campaign_date: str, report_id: str
) -> SubmissionRecord | None:
    path = submissions_dir(data_dir, handle, campaign_date) / f"{report_id}.json"
    if not path.exists():
        return None
    return SubmissionRecord.model_validate_json(path.read_text(encoding="utf-8"))


def list_submissions(data_dir: str, handle: str, campaign_date: str) -> list[SubmissionRecord]:
    """Return all submission records for a campaign."""
    sdir = submissions_dir(data_dir, handle, campaign_date)
    if not sdir.exists():
        return []
    records = []
    for path in sorted(sdir.glob("*.json")):
        try:
            records.append(SubmissionRecord.model_validate_json(path.read_text(encoding="utf-8")))
        except Exception:
            logger.warning("Could not parse submission file %s", path)
    return records


def update_submission(
    data_dir: str,
    handle: str,
    campaign_date: str,
    report_id: str,
    **updates: object,
) -> SubmissionRecord | None:
    """Patch fields on an existing submission record and write it back."""
    record = read_submission(data_dir, handle, campaign_date, report_id)
    if record is None:
        logger.warning("Submission %s not found — cannot update", report_id)
        return None
    updated = record.model_copy(update=updates)
    write_submission(updated, data_dir)
    return updated


# ---------------------------------------------------------------------------
# FindingRecord list (findings.json)
# ---------------------------------------------------------------------------


def write_findings(
    findings: list[FindingRecord], data_dir: str, handle: str, campaign_date: str
) -> Path:
    """Write the full findings list for a campaign (overwrites)."""
    path = campaign_dir(data_dir, handle, campaign_date) / "findings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [f.model_dump(mode="json") for f in findings]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.debug("Wrote %d findings → %s", len(findings), path)
    return path


def read_findings(data_dir: str, handle: str, campaign_date: str) -> list[FindingRecord]:
    path = campaign_dir(data_dir, handle, campaign_date) / "findings.json"
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [FindingRecord.model_validate(item) for item in raw]


# ---------------------------------------------------------------------------
# retro.md
# ---------------------------------------------------------------------------


def write_retro(content: str, data_dir: str, handle: str, campaign_date: str) -> Path:
    """Write the retro markdown file for a campaign."""
    path = campaign_dir(data_dir, handle, campaign_date) / "retro.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    logger.debug("Wrote retro.md → %s", path)
    return path


def read_retro(data_dir: str, handle: str, campaign_date: str) -> str | None:
    path = campaign_dir(data_dir, handle, campaign_date) / "retro.md"
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Log helpers
# ---------------------------------------------------------------------------


def open_log(data_dir: str, handle: str, campaign_date: str, name: str) -> Path:
    """Return a path inside logs/ ready for writing; creates directory."""
    ldir = logs_dir(data_dir, handle, campaign_date)
    ldir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%H%M%S")
    return ldir / f"{ts}-{name}"
