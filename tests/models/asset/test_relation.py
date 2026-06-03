"""tests/models/asset/test_relation.py - unit tests for models/asset/relation.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import Relation, RelationType, RRHeader

pytestmark = pytest.mark.unit


class TestRelationType:
    def test_oam_constant_values(self):
        assert RelationType.SIMPLE == "SimpleRelation"
        assert RelationType.PORT == "PortRelation"
        assert RelationType.BASIC_DNS == "BasicDNSRelation"


class TestRelation:
    def test_simple_edge(self):
        # product_used / certificate / ... - just type + label + endpoints.
        edge = Relation(
            relation_type=RelationType.SIMPLE,
            label="product_used",
            from_key="api.example.com:443/tcp",
            to_key="nginx 1.25.3",
        )
        assert edge.label == "product_used"
        assert edge.port_number is None
        assert edge.header is None

    def test_port_edge_carries_port_and_protocol(self):
        edge = Relation(
            relation_type=RelationType.PORT,
            label="port",
            from_key="api.example.com",
            to_key="api.example.com:443/tcp",
            port_number=443,
            protocol="tcp",
        )
        assert edge.port_number == 443
        assert edge.protocol == "tcp"

    def test_dns_edge_carries_header(self):
        edge = Relation(
            relation_type=RelationType.BASIC_DNS,
            label="a_record",
            from_key="example.com",
            to_key="93.184.216.34",
            header=RRHeader(rr_type=1, rr_class=1, ttl=300),
        )
        assert edge.header is not None
        assert edge.header.rr_type == 1

    def test_serialise_roundtrip(self):
        edge = Relation(
            relation_type=RelationType.PORT,
            label="port",
            from_key="h",
            to_key="h:443/tcp",
            port_number=443,
            protocol="tcp",
        )
        restored = Relation.model_validate_json(edge.model_dump_json())
        assert restored.port_number == 443
        assert restored.relation_type == RelationType.PORT

    def test_rejects_empty_label(self):
        with pytest.raises(ValidationError):
            Relation(relation_type=RelationType.SIMPLE, label="", from_key="a", to_key="b")

    def test_rejects_out_of_range_port(self):
        with pytest.raises(ValidationError):
            Relation(
                relation_type=RelationType.PORT,
                label="port",
                from_key="a",
                to_key="b",
                port_number=70000,
            )
