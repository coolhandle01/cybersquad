"""
models.asset - the recon-output / OAM inventory shapes (OSINT Analyst -> PT).

The OAM asset shapes the OSINT Analyst's sweep emits and the PT consumes:
endpoints discovered, the ``Service`` / ``Product`` / ``ProductRelease`` /
``TLSCertificate`` assets, the ``IpEnrichment`` subgraph, and the registrant shapes in
``network``, plus the ``VulnProperty`` annotations hung off them and the
LLM-backed endpoint marker.

Two things deliberately live *outside* this package because they are not OAM
asset types: the OA's *curation* shapes (``HostInsight`` / ``HostScore`` /
``HostRole`` / ``HostPriority`` / ``OpenPortsMap``) in ``models.insight``,
and the bundle that wraps the lot - ``AttackGraph`` - in ``models.attack``
with its ``AttackTree`` / ``AttackForest`` siblings.

Promoted from a single ``models/asset.py`` to a package as the OAM asset
layer grew. One module per cohesive OAM-asset concern; this ``__init__`` is
the public re-export surface, so ``from models.asset import X`` (and the
``from models import X`` re-export in ``models/__init__``) keep working
across every consumer unchanged.

FQDN-typed fields compose the ``FQDN`` primitive so mis-shaped hostnames
reject upstream of any downstream consumer rather than silently flowing
through the scope filter.

| Module | Contents |
|---|---|
| ``models.asset.property`` | ``DNSRecordProperty``, ``SimpleProperty``, |
|                           | ``SourceProperty``, ``VulnProperty`` |
| ``models.asset.relation`` | ``RelationType``, ``RRHeader``, ``Relation`` |
| ``models.asset.endpoint`` | ``Endpoint``, ``EndpointPage``, ``LlmEndpoint`` |
| ``models.asset.url`` | ``Url`` |
| ``models.asset.service`` | ``Service``, ``Product``, ``ProductRelease`` |
| ``models.asset.certificate`` | ``TLSCertificate`` |
| ``models.asset.network`` | ``IPAddress``, ``AutonomousSystem``, ``Netblock`` (+ legacy |
|                          | ``AsnRecord`` / ``Contact`` / ``ContactRole`` / ``RdapRecord``) |
| ``models.asset.registration`` | ``DomainRecord``, ``IPNetRecord``, ``AutnumRecord`` |
| ``models.asset.org`` | ``Organization`` |
| ``models.asset.contact`` | ``ContactRecord``, ``Phone``, ``Location`` |
| ``models.asset.people`` | ``Person`` |
| ``models.asset.identifier`` | ``Identifier`` |
| ``models.asset.ip`` | ``IpEnrichment``, ``RegistrantBundle`` (recon subgraph bundles) |

The intra-package import order is strictly layered: ``relation`` is a leaf
(primitives
only); ``property`` builds on ``relation`` (``DNSRecordProperty`` reuses
``RRHeader``); the per-asset modules build on ``property`` / ``relation``;
``endpoint`` / ``service`` / ``ip`` build on those. No cycles, so no
``model_rebuild`` is needed.
"""

from __future__ import annotations

from models.asset.certificate import TLSCertificate
from models.asset.contact import ContactRecord, Location, Phone
from models.asset.endpoint import Endpoint, EndpointPage, LlmEndpoint
from models.asset.identifier import Identifier
from models.asset.ip import IpEnrichment, RegistrantBundle
from models.asset.network import (
    AsnRecord,
    AutonomousSystem,
    Contact,
    ContactRole,
    IPAddress,
    Netblock,
    RdapRecord,
)
from models.asset.org import Organization
from models.asset.people import Person
from models.asset.property import (
    DNSRecordProperty,
    SimpleProperty,
    SourceProperty,
    VulnProperty,
)
from models.asset.registration import AutnumRecord, DomainRecord, IPNetRecord
from models.asset.relation import Relation, RelationType, RRHeader
from models.asset.service import Product, ProductRelease, Service
from models.asset.url import Url

__all__ = [
    "AsnRecord",
    "AutnumRecord",
    "AutonomousSystem",
    "Contact",
    "ContactRecord",
    "ContactRole",
    "DNSRecordProperty",
    "DomainRecord",
    "Endpoint",
    "EndpointPage",
    "IPAddress",
    "IPNetRecord",
    "Identifier",
    "IpEnrichment",
    "LlmEndpoint",
    "Location",
    "Netblock",
    "Organization",
    "Person",
    "Phone",
    "Product",
    "ProductRelease",
    "RRHeader",
    "RdapRecord",
    "RegistrantBundle",
    "Relation",
    "RelationType",
    "Service",
    "SimpleProperty",
    "SourceProperty",
    "TLSCertificate",
    "Url",
    "VulnProperty",
]
