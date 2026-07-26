"""tests/models/asset/test_property.py - unit tests for models/asset/property.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import DNSRecordProperty, RRHeader, SimpleProperty, SourceProperty, VulnProperty

pytestmark = pytest.mark.unit


class TestSimpleProperty:
    def test_key_value(self):
        p = SimpleProperty(property_name="asn", property_value="15169")
        assert p.property_name == "asn"
        assert p.property_value == "15169"

    def test_value_defaults_empty(self):
        assert SimpleProperty(property_name="role").property_value == ""

    def test_rejects_empty_name(self):
        with pytest.raises(ValidationError):
            SimpleProperty(property_name="")


class TestSourceProperty:
    def test_provenance(self):
        p = SourceProperty(source="nmap", confidence=90)
        assert p.source == "nmap"
        assert p.confidence == 90

    def test_confidence_defaults_zero(self):
        assert SourceProperty(source="nvd").confidence == 0

    def test_rejects_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            SourceProperty(source="nmap", confidence=101)


class TestDNSRecordProperty:
    def test_record(self):
        # The DNS record's content OAM hangs off the FQDN node, reusing the
        # RRHeader (rr_type / class / ttl) from the relation module.
        rec = DNSRecordProperty(
            property_name="www.example.com",
            header=RRHeader(rr_type=1, rr_class=1, ttl=300),
            data="93.184.216.34",
        )
        assert rec.property_name == "www.example.com"
        assert rec.header.rr_type == 1
        assert rec.data == "93.184.216.34"

    def test_data_defaults_empty(self):
        rec = DNSRecordProperty(property_name="example.com", header=RRHeader(rr_type=2))
        assert rec.data == ""

    def test_rejects_empty_name(self):
        with pytest.raises(ValidationError):
            DNSRecordProperty(property_name="", header=RRHeader(rr_type=1))

    def test_rejects_oversize_data(self):
        with pytest.raises(ValidationError):
            DNSRecordProperty(
                property_name="example.com", header=RRHeader(rr_type=16), data="x" * 2049
            )


class TestVulnProperty:
    def test_minimal_record(self):
        # id is the only floor: the OA / VR can hang a bare CVE annotation off
        # an asset and let description / source / category populate from the
        # NVD lookup that produced it.
        vuln = VulnProperty(id="CVE-2022-22965")
        assert vuln.id == "CVE-2022-22965"
        assert vuln.description == ""
        assert vuln.source == ""
        assert vuln.enumeration == ""

    def test_carries_full_nvd_annotation(self):
        vuln = VulnProperty(
            id="CVE-2022-22965",
            description="Spring Framework RCE via data binding (Spring4Shell).",
            source="nvd",
            category="CWE-94",
            enumeration="CVE",
            reference="https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
        )
        assert vuln.source == "nvd"
        assert vuln.category == "CWE-94"
        assert vuln.enumeration == "CVE"

    def test_serialise_roundtrip(self):

        original = VulnProperty(id="CVE-2021-44228", source="nvd", enumeration="CVE")
        restored = VulnProperty.model_validate_json(original.model_dump_json())
        assert restored.id == "CVE-2021-44228"
        assert restored.source == "nvd"

    def test_rejects_empty_id(self):

        with pytest.raises(ValidationError):
            VulnProperty(id="")

    def test_rejects_oversize_description(self):

        with pytest.raises(ValidationError):
            VulnProperty(id="CVE-2022-22965", description="x" * 2001)
