"""tests/models/asset/test_oam_records.py - unit tests for the OAM org /
contact / people / identifier / network asset structs."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    AutonomousSystem,
    ContactRecord,
    Identifier,
    IPAddress,
    Location,
    Netblock,
    Organization,
    Person,
    Phone,
)

pytestmark = pytest.mark.unit


class TestIPAddress:
    def test_ipv4(self):
        ip = IPAddress(address="8.8.8.8", type="IPv4")
        assert ip.address == "8.8.8.8"
        assert ip.type == "IPv4"  # coerced to the IPType StrEnum
        assert ip.vulns == []
        assert ip.sources == []

    def test_ipv6(self):
        assert IPAddress(address="2001:db8::1", type="IPv6").type == "IPv6"

    def test_rejects_type_mismatched_with_address(self):
        # type is determined by the address family; a disagreement is rejected.
        with pytest.raises(ValidationError):
            IPAddress(address="8.8.8.8", type="IPv6")

    def test_rejects_non_ip_address(self):
        # The IpAddr primitive rejects a non-literal before the validator runs.
        with pytest.raises(ValidationError):
            IPAddress(address="not-an-ip", type="IPv4")


class TestAutonomousSystem:
    def test_number(self):
        assert AutonomousSystem(number=15169).number == 15169

    def test_rejects_out_of_range(self):
        with pytest.raises(ValidationError):
            AutonomousSystem(number=5_000_000_000)


class TestNetblock:
    def test_cidr_and_type(self):
        nb = Netblock(cidr="8.8.8.0/24", type="IPv4")
        assert nb.cidr == "8.8.8.0/24"
        assert nb.type == "IPv4"  # coerced to the IPType StrEnum

    def test_ipv6_type(self):
        assert Netblock(cidr="2001:db8::/32", type="IPv6").type == "IPv6"

    def test_host_bits_normalise_to_network(self):
        # Cidr validates via ipaddress.ip_network(strict=False): a host-bit-set
        # prefix normalises to its network rather than rejecting.
        assert Netblock(cidr="8.8.8.8/24", type="IPv4").cidr == "8.8.8.0/24"

    def test_rejects_type_mismatched_with_cidr(self):
        # type is exhaustive and determined by cidr's family; a disagreement
        # is a producer bug, rejected rather than persisted.
        with pytest.raises(ValidationError):
            Netblock(cidr="8.8.8.0/24", type="IPv6")

    def test_rejects_empty_cidr(self):
        with pytest.raises(ValidationError):
            Netblock(cidr="", type="IPv4")

    def test_rejects_non_cidr(self):
        # A bare address (no prefix) is an IpAddr, not a Cidr; garbage rejects.
        with pytest.raises(ValidationError):
            Netblock(cidr="8.8.8.8", type="IPv4")
        with pytest.raises(ValidationError):
            Netblock(cidr="not-a-cidr", type="IPv4")


class TestOrganization:
    def test_minimal(self):
        org = Organization(name="Google LLC")
        assert org.name == "Google LLC"
        assert org.target_markets == []
        assert org.active is False

    def test_rejects_empty_name(self):
        with pytest.raises(ValidationError):
            Organization(name="")


class TestContactRecord:
    def test_discovered_at(self):
        assert ContactRecord(discovered_at="2026-05-31").discovered_at == "2026-05-31"


class TestPerson:
    def test_full_name(self):
        p = Person(full_name="Jane Doe", first_name="Jane", family_name="Doe")
        assert p.full_name == "Jane Doe"

    def test_rejects_empty_full_name(self):
        with pytest.raises(ValidationError):
            Person(full_name="")


class TestPhone:
    def test_e164(self):
        ph = Phone(raw="+1 650 555 0100", e164="+16505550100", country_code=1)
        assert ph.e164 == "+16505550100"


class TestLocation:
    def test_address(self):
        loc = Location(address="1600 Amphitheatre Pkwy", city="Mountain View", country="US")
        assert loc.city == "Mountain View"


class TestIdentifier:
    def test_email_identifier(self):
        ident = Identifier(id="abuse@example.com", id_type="email")
        assert ident.id == "abuse@example.com"
        assert ident.id_type == "email"

    def test_rejects_empty_id(self):
        with pytest.raises(ValidationError):
            Identifier(id="")
