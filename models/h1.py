"""
models.h1 - HackerOne API shapes.

The Programme Manager, Technical Author, and Disclosure Coordinator exchange
these types directly with the H1 API via tools/h1_api.py:
  - ScopeType enumerates H1's asset_type field;
  - ScopeItem is one in/out-of-scope entry;
  - ProgrammePreview is the /hackers/programs list-endpoint shape;
  - Programme is the hydrated detail shape;
  - DisclosureReport is the POST /reports payload (Technical Author -> Disclosure Coordinator);
  - SubmissionStatus enumerates H1's report state taxonomy;
  - SubmissionResult is the outcome of POSTing a report to /reports;
  - ProgrammeReportSummary is the compact slice returned by List Programme Reports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from models.finding import VerifiedVulnerability
from models.nvd import Severity


class ScopeType(StrEnum):
    URL = "url"
    WILDCARD = "wildcard"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    DOWNLOADABLE_EXECUTABLES = "downloadable_executables"
    GOOGLE_PLAY_APP_ID = "google_play_app_id"
    APPLE_STORE_APP_ID = "apple_store_app_id"
    WINDOWS_APP_STORE_APP_ID = "windows_app_store_app_id"
    OTHER_APK = "other_apk"
    OTHER_IPA = "other_ipa"
    TESTFLIGHT = "testflight"
    OTHER = "other"


class SubmissionState(StrEnum):
    """H1 ``filter[submission_state]`` value for the /hackers/programs list endpoint.

    Covers the three documented values the filter accepts. ``Programme.
    submission_state`` stays ``str | None`` (rather than typed as this
    StrEnum) because the programme detail endpoint may emit additional
    values for invitation-only or legacy programmes - the full enum is
    not pinned against a captured response (FIXME #43). This StrEnum is
    deliberately scoped to the filter-input direction only.
    """

    OPEN = "open"
    DISABLED = "disabled"
    PAUSED = "paused"


class ScopeItem(BaseModel):
    """A single in-scope or out-of-scope asset."""

    asset_identifier: str
    asset_type: ScopeType
    eligible_for_bounty: bool = True
    instruction: str | None = None
    max_severity: Severity | None = None


class ProgrammePreview(BaseModel):
    """A lightweight programme summary from the H1 /hackers/programs list endpoint.

    Returned by browse_programmes_tool so the Programme Manager can survey the
    full accessible catalog without paying the per-programme detail-fetch cost
    that Programme hydration incurs. The PM picks shortlisted handles from the
    preview list and hydrates each one with hydrate_programme_tool.

    Only `handle` is required - the list endpoint's payload shape is not pinned
    against a captured response, so any individual attribute may be absent for
    a given programme.
    """

    handle: str
    name: str | None = None
    offers_bounties: bool | None = None
    submission_state: str | None = None
    state: str | None = None
    bookmarked: bool | None = None


class Programme(BaseModel):
    """A HackerOne bug bounty programme selected by the Programme Manager."""

    handle: str
    name: str
    url: str
    bounty_table: dict[Severity, int]
    in_scope: list[ScopeItem]
    out_of_scope: list[ScopeItem]
    offers_bounties: bool = True
    accepts_new_reports: bool = True
    response_efficiency_pct: float | None = None
    avg_time_to_bounty_days: float | None = None
    avg_time_to_first_response_days: float | None = None
    total_bounties_paid_usd: int | None = None
    triage_active: bool | None = None
    last_updated_at: datetime | None = None
    # HackerOne's access-state attribute. "public_mode" denotes publicly
    # listed, openly accessible programmes; "private_mode" denotes
    # invitation-only access. H1 may emit other values for variants of
    # invitation-only programmes - the full enum has not been verified
    # against a captured /hackers/programs response (see #43). The field
    # is surfaced verbatim so the Programme Manager treats any value other
    # than "public_mode" as non-public rather than relying on a Python-side
    # categorisation that might miss a value H1 emits.
    state: str | None = None
    policy_text: str = ""
    priority_score: float = 0.0
    selected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DisclosureReport(BaseModel):
    """A complete, submission-ready vulnerability report in H1 format.

    Every field maps directly onto the POST /reports payload built in
    tools/h1_api.H1Client.submit_report - title -> attributes.title,
    body_markdown -> attributes.vulnerability_information, weakness_id ->
    attributes.weakness_id, programme_handle -> relationships.program.data.id,
    and so on. The class IS the wire shape, not an intermediate.
    """

    programme_handle: str
    title: str
    vulnerability: VerifiedVulnerability
    summary: str
    body_markdown: str
    weakness_id: int | None = None
    structured_scope_id: str | None = None
    impact_statement: str
    attachments: list[str] = Field(default_factory=list)
    authored_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SubmissionStatus(StrEnum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    INFORMATIVE = "informative"


class SubmissionResult(BaseModel):
    """Result of a HackerOne report submission."""

    report_id: str | None = None
    status: SubmissionStatus = SubmissionStatus.PENDING
    h1_url: str | None = None
    submitted_at: datetime | None = None
    error: str | None = None


class ProgrammeReportSummary(BaseModel):
    """Compact summary of one HackerOne report listed against a programme.

    Lives in models.h1 rather than models.finding because the shape mirrors
    H1's /reports listing payload (every field is verbatim from the API)
    and the consumer is the Technical Author's List Programme Reports tool
    which already speaks h1-shape.
    """

    report_id: str | None = None
    title: str | None = None
    severity: str | None = None
    state: str | None = None
