"""
models.attack.graph - the OSINT Analyst's recon-output bundle.

The Sheyner-style attack graph: everything the OA *describes* about a
programme's attack surface, composing the OAM asset shapes from
``models.asset``. Not itself an OAM asset - the bundle that wraps them, the
root of the OA -> VR -> PT handoff.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from models.asset import DNSRecordProperty, Endpoint, IpEnrichment, Relation, TLSCertificate
from models.finding import RawFinding
from models.h1 import Programme
from models.insight import HostInsight
from models.primitives import FQDN


class AttackGraph(BaseModel):
    """Everything the OSINT Analyst found about a programme's attack surface."""

    programme: Programme
    subdomains: list[FQDN] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    open_ports: dict[FQDN, list[int]] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)
    notes: str = ""
    # Findings collected passively during recon (TLS issues, DNS misconfigs, etc.)
    # Available to all downstream agents without requiring a separate pentest pass.
    passive_findings: list[RawFinding] = Field(default_factory=list)
    # hostname -> ordered list of public hop IPs from traceroute.
    # Useful for identifying origin IPs behind CDNs/WAFs (CDN bypass vector).
    network_hops: dict[FQDN, list[str]] = Field(default_factory=dict)
    # Per-host curation the OSINT Analyst authors via Annotate Host. Empty on
    # the OA's internal attack_graph.json; populated on the final recon.json.
    host_insights: list[HostInsight] = Field(default_factory=list)
    # IP-rooted enrichment: the faithful OAM subgraph composed from the
    # in-scope hosts' A records - IPAddress / Netblock / AutonomousSystem nodes,
    # the AutnumRecord / IPNetRecord registry records, the registrant
    # Organization / Identifier assets, and their Relation edges (Cymru ASN +
    # RDAP registrant + dnsx PTR). Empty when the enrichment pass did not run.
    ip_enrichment: IpEnrichment = Field(default_factory=IpEnrichment)
    # Forward-DNS records (A / CNAME) resolved for the in-scope hosts, as OAM
    # DNSRecordProperty entries - the record content hung off each host's FQDN
    # node. The property side of DNS; the relation edges to the answer assets
    # are in ``relations`` below. Empty when the resolve pass did not run.
    dns_records: list[DNSRecordProperty] = Field(default_factory=list)
    # OAM relation edges the sweep produced - currently the DNS edges
    # (``BasicDNSRelation``: FQDN -> IP for an A record, FQDN -> target for a
    # CNAME) from forward resolution. The per-host relations.json the
    # enrichment tools write (nmap port / product_used edges) is the other
    # source; #45 unions both into the graph DB.
    relations: list[Relation] = Field(default_factory=list)
    # Leaf TLS certificates observed during the httpx WEB_INVENTORY pass,
    # lifted off the endpoints by ``run_recon`` - one per HTTPS endpoint
    # that presented a cert. The cybersquad equivalent of amass's
    # TLSCertificate asset nodes; the per-host copy lives at
    # ``assets/<fqdn>/tls.json``. Populated OA-side, read by the PT/VR
    # (additive: empty when the WEB_INVENTORY pass did not run).
    tls_certificates: list[TLSCertificate] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
