"""tests/models/asset/test_ip.py - unit tests for models/asset/ip.py."""

from __future__ import annotations

import pytest

from models import (
    AutonomousSystem,
    IPAddress,
    IpEnrichment,
    Netblock,
    Organization,
    Relation,
    RelationType,
)

pytestmark = pytest.mark.unit


class TestIpEnrichment:
    def test_empty_default(self):
        # The bundle is useful with whatever subset of enrichment returned;
        # every list defaults empty.
        bundle = IpEnrichment()
        assert bundle.ip_addresses == []
        assert bundle.netblocks == []
        assert bundle.autonomous_systems == []
        assert bundle.organizations == []
        assert bundle.relations == []

    def test_carries_the_faithful_subgraph(self):
        bundle = IpEnrichment(
            ip_addresses=[IPAddress(address="8.8.8.8", type="IPv4")],
            netblocks=[Netblock(cidr="8.8.8.0/24", type="IPv4")],
            autonomous_systems=[AutonomousSystem(number=15169)],
            organizations=[Organization(name="Google LLC")],
            relations=[
                Relation(
                    relation_type=RelationType.SIMPLE,
                    label="contains",
                    from_key="8.8.8.0/24",
                    to_key="8.8.8.8",
                )
            ],
        )
        assert bundle.ip_addresses[0].address == "8.8.8.8"
        assert bundle.autonomous_systems[0].number == 15169
        assert bundle.relations[0].label == "contains"

    def test_serialise_roundtrip(self):
        original = IpEnrichment(ip_addresses=[IPAddress(address="1.1.1.1", type="IPv4")])
        restored = IpEnrichment.model_validate_json(original.model_dump_json())
        assert restored.ip_addresses[0].address == "1.1.1.1"

    def test_rejects_invalid_address_in_node(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            IpEnrichment(ip_addresses=[IPAddress(address="not an ip", type="IPv4")])
