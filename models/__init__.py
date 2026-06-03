"""
models - Pydantic data models shared across the entire pipeline.

Each model represents a discrete artefact that agents pass to one another.
The package is split into per-domain modules; this ``__init__`` is the
public re-export surface so ``from models import X`` continues to work
across every consumer.

| Module | Contents |
|---|---|
| ``models.primitives`` | ``FQDN``, ``HttpUrl``, ``IpAddr``, ``Cidr``, ``Email``, ``IPType`` |
| ``models.finding`` | ``RawFinding``, ``VerifiedVulnerability``, ``RawFindingSummary`` |
| ``models.asset`` | assets ``Endpoint``, ``EndpointPage``, ``IpEnrichment``, |
|                  | ``Service``, ``Product``, ``ProductRelease``, ``Url``, |
|                  | ``TLSCertificate``, ``LlmEndpoint``; properties |
|                  | ``DNSRecordProperty``, ``SimpleProperty``, ``SourceProperty``, |
|                  | ``VulnProperty``; |
|                  | relations ``RelationType``, ``RRHeader``, ``Relation`` |
| ``models.asset.network`` | ``AsnRecord``, ``Contact``, ``ContactRole``, |
|                          | ``RdapRecord`` |
| ``models.asset.registration`` | ``DomainRecord``, ``IPNetRecord``, ``AutnumRecord`` |
| ``models.workspace`` | ``RunFile``, ``RunFileContent`` |
| ``models.nvd`` | ``CVE``, ``CvssVector``, ``Severity`` |
| ``models.mitre`` | ``CWE`` |
| ``models.owasp`` | ``OWASPEntry`` |
| ``models.dns`` | ``PtrRecord``, ``TakeoverCandidate`` |
| ``models.insight`` | ``HostRole``, ``HostPriority``, ``HostInsight``, ``HostScore``, |
|                    | ``OpenPortsMap``, ``HostAnnotation``, ``InsightValidationIssue``, |
|                    | ``InsightValidationReport``, ``ReconFinalisationError`` |
| ``models.metrics`` | ``RunMetrics`` |
| ``models.scanner`` | ``NmapMode``, ``NmapBanner``, ``NmapScripts``, ``NmapService``, |
|                    | ``NmapHostResult``, ``NmapScanResult``, ``HttpxMode`` |
| ``models.h1`` | HackerOne shapes incl. ``ProgrammeReportSummary`` |
| ``models.attack`` | ``AttackGraph``, ``AttackForest``, ``AttackTree``, |
|                   | ``AttackForestValidationIssue``, ``AttackForestValidationReport``, |
|                   | ``AttackForestFinalisationError`` |
| ``models.triage`` | ``AuthoredAssessment``, ``SeverityDecision`` |
| ``models.report`` | ``AuthoredDraft`` |

The per-domain modules import only from layers below them in the
dependency graph: primitives -> finding -> h1 -> asset. No module imports
from this ``__init__`` to avoid the partially-initialised-package gotcha
that the pre-split layout had to dance around.
"""

from __future__ import annotations

from models.asset import (
    AsnRecord,
    AutnumRecord,
    AutonomousSystem,
    Contact,
    ContactRecord,
    ContactRole,
    DNSRecordProperty,
    DomainRecord,
    Endpoint,
    EndpointPage,
    Identifier,
    IPAddress,
    IpEnrichment,
    IPNetRecord,
    LlmEndpoint,
    Location,
    Netblock,
    Organization,
    Person,
    Phone,
    Product,
    ProductRelease,
    RdapRecord,
    RegistrantBundle,
    Relation,
    RelationType,
    RRHeader,
    Service,
    SimpleProperty,
    SourceProperty,
    TLSCertificate,
    Url,
    VulnProperty,
)
from models.attack import (
    AttackForest,
    AttackForestFinalisationError,
    AttackForestValidationIssue,
    AttackForestValidationReport,
    AttackGraph,
    AttackTree,
)
from models.dns import PtrRecord, TakeoverCandidate
from models.finding import RawFinding, RawFindingSummary, VerifiedVulnerability
from models.h1 import ProgrammeReportSummary
from models.insight import (
    HostAnnotation,
    HostInsight,
    HostPriority,
    HostRole,
    HostScore,
    InsightValidationIssue,
    InsightValidationReport,
    OpenPortsMap,
    ReconFinalisationError,
)
from models.metrics import RunMetrics
from models.mitre import CWE
from models.nvd import CVE, CvssVector, Severity
from models.owasp import OWASPEntry
from models.primitives import FQDN, Cidr, Email, HttpUrl, IpAddr, IPType
from models.report import AuthoredDraft
from models.scanner import (
    HttpxMode,
    NmapBanner,
    NmapHostResult,
    NmapMode,
    NmapScanResult,
    NmapScripts,
    NmapService,
)
from models.triage import AuthoredAssessment, SeverityDecision
from models.workspace import RunFile, RunFileContent

__all__ = [
    "CVE",
    "CWE",
    "FQDN",
    "AsnRecord",
    "AttackForest",
    "AttackForestFinalisationError",
    "AttackForestValidationIssue",
    "AttackForestValidationReport",
    "AttackGraph",
    "AttackTree",
    "AuthoredAssessment",
    "AuthoredDraft",
    "AutnumRecord",
    "AutonomousSystem",
    "Cidr",
    "Contact",
    "ContactRecord",
    "ContactRole",
    "CvssVector",
    "DNSRecordProperty",
    "DomainRecord",
    "Email",
    "Endpoint",
    "EndpointPage",
    "HostAnnotation",
    "HostInsight",
    "HostPriority",
    "HostRole",
    "HostScore",
    "HttpUrl",
    "HttpxMode",
    "IPAddress",
    "IPNetRecord",
    "IPType",
    "Identifier",
    "InsightValidationIssue",
    "InsightValidationReport",
    "IpAddr",
    "IpEnrichment",
    "LlmEndpoint",
    "Location",
    "Netblock",
    "NmapBanner",
    "NmapHostResult",
    "NmapMode",
    "NmapScanResult",
    "NmapScripts",
    "NmapService",
    "OWASPEntry",
    "OpenPortsMap",
    "Organization",
    "Person",
    "Phone",
    "Product",
    "ProductRelease",
    "ProgrammeReportSummary",
    "PtrRecord",
    "RRHeader",
    "RawFinding",
    "RawFindingSummary",
    "RdapRecord",
    "ReconFinalisationError",
    "RegistrantBundle",
    "Relation",
    "RelationType",
    "RunFile",
    "RunFileContent",
    "RunMetrics",
    "Service",
    "Severity",
    "SeverityDecision",
    "SimpleProperty",
    "SourceProperty",
    "TLSCertificate",
    "TakeoverCandidate",
    "Url",
    "VerifiedVulnerability",
    "VulnProperty",
]
