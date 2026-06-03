"""
models/insight.py - typed shapes for the OSINT Analyst's recon curation
and finalisation pipeline.

The OA's curation layer - its *judgements* about the asset graph, not OAM
asset types (those live in ``models/asset/``):

* the host-classification enums (``HostRole`` / ``HostPriority``),
* the per-host annotation the agent authors (``HostInsight``) and its
  machine-actionable score half (``HostScore``),
* the host-keyed port map the Penetration Tester reads (``OpenPortsMap``),
* the ``Annotate Host`` return shape (``HostAnnotation``),
* the quality-gate validation report (``InsightValidationIssue`` /
  ``InsightValidationReport``) the OA's ``Annotate Host`` tool produces,
* and the ``ReconFinalisationError`` ``finalise_recon`` raises when the
  sweep + per-host insights cannot be consolidated into ``recon.json``.

Lives in models/ rather than tools/ because these are typed contracts the
OA wrapper functions return / raise - the kind of shape consumers import to
type-check against rather than to invoke. The data (sweep loaders, insight
persistence, scope guards) stays in ``tools/recon_insights.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from models.asset import VulnProperty
from models.primitives import FQDN


class HostRole(StrEnum):
    """The role a host plays in the programme's attack surface.

    Drives priority decisions downstream: an ``ADMIN`` host with a known
    framework is a higher-value pentest target than a ``CDN`` host that
    serves static assets.
    """

    ADMIN = "admin"  # admin / control-plane UIs
    API = "api"  # REST / GraphQL / SOAP endpoints
    AUTH = "auth"  # SSO, OAuth, login, password reset
    APP = "app"  # main user-facing application
    CDN = "cdn"  # static asset delivery, edge caches
    STATIC = "static"  # purely static content (marketing, blog, docs)
    MAIL = "mail"  # SMTP / IMAP / MX hosts
    INFRA = "infra"  # name servers, monitoring, IaaS
    DEV = "dev"  # dev / staging / beta surfaces
    UNKNOWN = "unknown"


class HostPriority(StrEnum):
    """The OSINT Analyst's curation signal for downstream agents.

    The Penetration Tester biases probe budget toward ``HIGH`` hosts; the
    Vulnerability Researcher prioritises CVE / report-history research for
    them. ``SKIP`` is a hard signal not to probe (third-party-managed, known
    decoy, etc.)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SKIP = "skip"


class HostInsight(BaseModel):
    """One OSINT Analyst-authored annotation for a single host.

    The sweep produces ``subdomains`` / ``endpoints`` / ``open_ports`` /
    ``technologies`` as raw inventory; ``HostInsight`` is the agent's
    curation layer that tells downstream agents WHERE to look first and
    WHY.
    """

    hostname: FQDN
    role: HostRole
    priority: HostPriority
    notes: str  # agent-authored, >= 30 chars
    detected_tech: list[str] = Field(default_factory=list)  # ideally with versions
    # OAM ``VulnProperty`` annotations hung off this host (FQDN asset) - the
    # known vulnerabilities the OA / VR attributed to it from its detected
    # tech. Additive and default-empty.
    vulns: list[VulnProperty] = Field(default_factory=list)
    annotated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HostScore(BaseModel):
    """The OSINT Analyst's scoring of one host - the score/priority half of
    ``HostInsight``, split out from the prose.

    Pure machine-actionable curation: WHERE a host sits in the attack
    surface (``role``) and how hard downstream agents should lean on it
    (``priority``). The WHY - the agent's prose rationale - lives beside it
    as ``notes.md`` rather than shoehorned into this data shape, so the PT
    can filter on ``priority`` / ``role`` without parsing free text.

    Materialised per host at ``assets/<fqdn>/host.json`` - the typed header
    of that host's OAM-asset directory. Maps toward amass's FQDN asset,
    with role / priority as ``SimpleProperty`` values when #45 lands.
    """

    hostname: FQDN
    role: HostRole
    priority: HostPriority
    annotated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OpenPortsMap(BaseModel):
    """The recon-derived port map keyed by host.

    Lives as its own model rather than ``dict[FQDN, list[int]]`` so the
    Penetration Tester sees a documented shape it can pattern-match on
    when deciding which port-specific probes to run.
    """

    hosts: dict[FQDN, list[int]] = Field(default_factory=dict)


class InsightValidationIssue(BaseModel):
    """One issue produced by validate_insight."""

    section: str
    severity: str  # "error" (blocks finalise) or "warning" (advisory)
    message: str


class InsightValidationReport(BaseModel):
    """Result of validating one insight."""

    ok: bool
    issues: list[InsightValidationIssue] = Field(default_factory=list)


class HostAnnotation(BaseModel):
    """Return shape of the Annotate Host tool.

    ``path`` is the workspace-relative location of the persisted insight
    (e.g. ``assets/api.example.com/insight.json``); ``validation`` is the
    quality-gate report for the insight that was just authored.
    """

    path: str
    validation: InsightValidationReport


class ReconFinalisationError(RuntimeError):
    """Raised when finalise_recon cannot consolidate the sweep + insights."""


__all__ = [
    "HostAnnotation",
    "HostInsight",
    "HostPriority",
    "HostRole",
    "HostScore",
    "InsightValidationIssue",
    "InsightValidationReport",
    "OpenPortsMap",
    "ReconFinalisationError",
]
