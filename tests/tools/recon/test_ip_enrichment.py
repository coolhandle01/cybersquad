"""tests/tools/recon/test_ip_enrichment.py - unit tests for the IP-rooted
enrichment composer (tools/recon/ip_enrichment.py).

The composer orchestrates the lookups (Cymru ASN, dnsx PTR, RDAP) through the
decomposition producers into an ``IpEnrichment`` bundle. The lookups are mocked
so the test asserts composition, not the lookups' own behaviour (those live in
the per-source test modules).
"""

from __future__ import annotations

import pytest

from models.asset.network import AsnRecord, RdapRecord
from models.dns import PtrRecord
from tools.recon.ip_enrichment import compose_ip_enrichment

pytestmark = pytest.mark.unit


def _patch_lookups(monkeypatch, *, asn=None, ptr=None, rdap_ip=None, rdap_asn=None):
    monkeypatch.setattr("tools.recon.ip_enrichment.lookup_asn", lambda ips: list(asn or []))
    monkeypatch.setattr("tools.recon.ip_enrichment.resolve_ptr", lambda ips: list(ptr or []))
    monkeypatch.setattr("tools.recon.ip_enrichment.lookup_rdap_for_ip", lambda ip: rdap_ip)
    monkeypatch.setattr("tools.recon.ip_enrichment.lookup_rdap_for_asn", lambda asn: rdap_asn)


class TestComposeIpEnrichment:
    def test_empty_input(self):
        bundle = compose_ip_enrichment([])
        assert bundle.ip_addresses == []
        assert bundle.relations == []

    def test_composes_full_subgraph(self, monkeypatch):
        _patch_lookups(
            monkeypatch,
            asn=[
                AsnRecord(
                    ip="8.8.8.8",
                    asn=15169,
                    prefix="8.8.8.0/24",
                    country="US",
                    organisation="GOOGLE, US",
                )
            ],
            ptr=[PtrRecord(ip="8.8.8.8", hostnames=["dns.google"])],
            rdap_ip=RdapRecord(
                query="8.8.8.8", handle="NET-8-8-8-0-1", registrant_organisation="Google LLC"
            ),
            rdap_asn=RdapRecord(
                query="AS15169", handle="AS15169", registrant_organisation="Google LLC"
            ),
        )
        bundle = compose_ip_enrichment(["8.8.8.8"])

        assert [a.address for a in bundle.ip_addresses] == ["8.8.8.8"]
        assert [n.cidr for n in bundle.netblocks] == ["8.8.8.0/24"]
        assert [s.number for s in bundle.autonomous_systems] == [15169]
        assert [a.number for a in bundle.autnum_records] == [15169]
        # The IPNetRecord's cidr was correlated from the Cymru netblock.
        assert [n.cidr for n in bundle.ipnet_records] == ["8.8.8.0/24"]
        assert [o.name for o in bundle.organizations] == ["Google LLC"]
        labels = {r.label for r in bundle.relations}
        assert {"contains", "announces", "ptr_record", "registrant_org", "managed_by"} <= labels

    def test_with_rdap_false_skips_registrant(self, monkeypatch):
        _patch_lookups(
            monkeypatch,
            asn=[
                AsnRecord(
                    ip="8.8.8.8",
                    asn=15169,
                    prefix="8.8.8.0/24",
                    country="US",
                    organisation="GOOGLE, US",
                )
            ],
        )
        bundle = compose_ip_enrichment(["8.8.8.8"], with_rdap=False)
        # Routing spine still built; registrant layer skipped (no RDAP fetches).
        assert [a.address for a in bundle.ip_addresses] == ["8.8.8.8"]
        assert bundle.autnum_records == []
        assert bundle.ipnet_records == []
        assert bundle.organizations == []
