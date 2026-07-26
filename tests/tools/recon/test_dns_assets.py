"""tests/tools/recon/test_dns_assets.py - unit tests for the dnsx -> OAM
subgraph decomposition (tools/recon/dns_assets.py).
"""

from __future__ import annotations

import pytest

from models import RelationType
from tools.recon.dns_assets import dns_assets_from_dnsx
from tools.recon.dnsx import DNSRecord

pytestmark = pytest.mark.unit


class TestDnsAssetsFromDnsx:
    def test_a_record_becomes_property_and_relation(self, target_apex):
        assets = dns_assets_from_dnsx(
            [DNSRecord(hostname=f"api.{target_apex}", a_records=["8.8.8.8"], cname=[], ttl=300)]
        )
        # property: the record content hung off the FQDN node.
        assert len(assets.records) == 1
        prop = assets.records[0]
        assert prop.property_name == f"api.{target_apex}"
        assert prop.header.rr_type == 1  # A
        assert prop.header.rr_class == 1  # IN
        assert prop.header.ttl == 300  # dnsx's reported response TTL
        assert prop.data == "8.8.8.8"
        # relation: the BasicDNSRelation edge FQDN -> IP.
        assert len(assets.relations) == 1
        rel = assets.relations[0]
        assert rel.relation_type == RelationType.BASIC_DNS
        assert rel.label == "a_record"
        assert rel.from_key == f"api.{target_apex}"
        assert rel.to_key == "8.8.8.8"
        assert rel.header is not None and rel.header.rr_type == 1
        assert rel.header.ttl == 300

    def test_cname_becomes_property_and_relation(self, target_apex):
        assets = dns_assets_from_dnsx(
            [DNSRecord(hostname=f"www.{target_apex}", a_records=[], cname=[f"api.{target_apex}"])]
        )
        assert assets.records[0].header.rr_type == 5  # CNAME
        assert assets.records[0].data == f"api.{target_apex}"
        rel = assets.relations[0]
        assert rel.label == "cname_record"
        assert rel.from_key == f"www.{target_apex}"
        assert rel.to_key == f"api.{target_apex}"

    def test_multiple_answers_each_get_property_and_relation(self, target_apex):
        assets = dns_assets_from_dnsx(
            [
                DNSRecord(
                    hostname=f"api.{target_apex}",
                    a_records=["8.8.8.8", "8.8.4.4"],
                    cname=[f"lb.{target_apex}"],
                )
            ]
        )
        # two A answers + one CNAME = three properties and three edges.
        assert len(assets.records) == 3
        assert len(assets.relations) == 3
        assert [r.to_key for r in assets.relations] == ["8.8.8.8", "8.8.4.4", f"lb.{target_apex}"]

    def test_empty_input(self):
        assets = dns_assets_from_dnsx([])
        assert assets.records == []
        assert assets.relations == []
