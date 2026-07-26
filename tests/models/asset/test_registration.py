"""tests/models/asset/test_registration.py - unit tests for models/asset/registration.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import AutnumRecord, DomainRecord, IPNetRecord

pytestmark = pytest.mark.unit


class TestDomainRecord:
    def test_minimal(self, target_apex):
        rec = DomainRecord(domain=target_apex)
        assert rec.domain == target_apex
        assert rec.status == []
        assert rec.dnssec is False

    def test_rejects_empty_domain(self):
        with pytest.raises(ValidationError):
            DomainRecord(domain="")


class TestIPNetRecord:
    def test_carries_registry_fields(self):
        rec = IPNetRecord(
            cidr="8.8.8.0/24",
            handle="NET-8-8-8-0-1",
            name="GOGL",
            country="US",
            status=["active"],
        )
        assert rec.cidr == "8.8.8.0/24"
        assert rec.handle == "NET-8-8-8-0-1"
        assert rec.status == ["active"]

    def test_rejects_empty_cidr(self):
        with pytest.raises(ValidationError):
            IPNetRecord(cidr="")

    def test_rejects_non_cidr(self):
        with pytest.raises(ValidationError):
            IPNetRecord(cidr="8.8.8.8")  # bare address, not a CIDR prefix


class TestAutnumRecord:
    def test_carries_asn_registration(self):
        rec = AutnumRecord(number=15169, handle="AS15169", name="GOOGLE")
        assert rec.number == 15169
        assert rec.handle == "AS15169"

    def test_rejects_out_of_range_number(self):
        with pytest.raises(ValidationError):
            AutnumRecord(number=5_000_000_000)
