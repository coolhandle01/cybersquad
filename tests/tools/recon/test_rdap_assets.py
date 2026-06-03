"""tests/tools/recon/test_rdap_assets.py - unit tests for the RDAP -> OAM
registration subgraph decomposition (tools/recon/rdap_assets.py).
"""

from __future__ import annotations

import pytest

from models import RelationType
from models.asset.network import Contact, ContactRole, RdapRecord
from tools.recon.rdap_assets import registrant_assets_from_rdap

pytestmark = pytest.mark.unit


class TestRegistrantAssetsFromRdap:
    def test_full_asn_record(self):
        g = registrant_assets_from_rdap(
            [
                RdapRecord(
                    query="AS15169",
                    handle="AS15169",
                    registrant_organisation="Google LLC",
                    contacts=[Contact(role=ContactRole.ABUSE, email="abuse@google.com")],
                )
            ],
            ip_to_cidr={},
        )
        assert [a.number for a in g.autnum_records] == [15169]
        assert g.ipnet_records == []
        assert [o.name for o in g.organizations] == ["Google LLC"]
        assert [i.id for i in g.identifiers] == ["abuse@google.com"]

        labels = {r.label for r in g.relations}
        assert labels == {"registrant_org", "managed_by", "abuse_email"}
        managed_by = next(r for r in g.relations if r.label == "managed_by")
        assert managed_by.relation_type == RelationType.SIMPLE
        assert managed_by.from_key == "AS15169"
        assert managed_by.to_key == "Google LLC"
        abuse = next(r for r in g.relations if r.label == "abuse_email")
        assert abuse.from_key == "Google LLC"  # anchored on the org
        assert abuse.to_key == "abuse@google.com"

    def test_ip_record_correlates_cidr_from_netblock(self):
        g = registrant_assets_from_rdap(
            [
                RdapRecord(
                    query="8.8.8.8",
                    handle="NET-8-8-8-0-1",
                    registrant_organisation="Google LLC",
                )
            ],
            ip_to_cidr={"8.8.8.8": "8.8.8.0/24"},
        )
        # The IPNetRecord's cidr came from the Cymru netblock, not RDAP.
        assert [n.cidr for n in g.ipnet_records] == ["8.8.8.0/24"]
        assert g.ipnet_records[0].handle == "NET-8-8-8-0-1"
        assert g.autnum_records == []
        registrant = next(r for r in g.relations if r.label == "registrant_org")
        assert registrant.from_key == "NET-8-8-8-0-1"
        assert registrant.to_key == "Google LLC"
        # No managed_by edge for an IP-block record (that is an AS -> Org edge).
        assert not any(r.label == "managed_by" for r in g.relations)

    def test_ip_record_skipped_when_no_netblock(self):
        # An IPNetRecord needs a cidr; with no netblock for the IP, skip it.
        g = registrant_assets_from_rdap(
            [RdapRecord(query="203.0.113.7", handle="NET-X", registrant_organisation="Acme")],
            ip_to_cidr={},
        )
        assert g.ipnet_records == []
        assert g.organizations == []
        assert g.relations == []

    def test_no_org_anchors_email_on_record(self):
        g = registrant_assets_from_rdap(
            [
                RdapRecord(
                    query="AS64500",
                    handle="",
                    contacts=[Contact(role=ContactRole.ABUSE, email="noc@example.net")],
                )
            ],
            ip_to_cidr={},
        )
        assert g.organizations == []
        abuse = next(r for r in g.relations if r.label == "abuse_email")
        assert abuse.from_key == "AS64500"  # no org, no handle -> the AS key

    def test_dedupes_org_and_records(self):
        rec = RdapRecord(query="AS15169", handle="AS15169", registrant_organisation="Google LLC")
        g = registrant_assets_from_rdap([rec, rec], ip_to_cidr={})
        assert len(g.autnum_records) == 1
        assert len(g.organizations) == 1

    def test_empty(self):
        g = registrant_assets_from_rdap([], {})
        assert g.organizations == []
        assert g.autnum_records == []
        assert g.ipnet_records == []
        assert g.identifiers == []
        assert g.relations == []
