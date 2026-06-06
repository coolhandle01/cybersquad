"""tests/models/test_network.py - unit tests for models/network.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    Contact,
    ContactRole,
    DomainRecord,
)

pytestmark = pytest.mark.unit


class TestDomainRecord:
    def test_minimal_record(self, target_apex):
        # domain is the only floor; the WHOIS facets populate as the lookup
        # recovers them.
        rec = DomainRecord(domain=target_apex)
        assert rec.domain == target_apex
        assert rec.raw == ""
        assert rec.status == []
        assert rec.dnssec is False

    def test_full_record(self, target_apex):
        rec = DomainRecord(
            domain=target_apex,
            record_id="whois-123",
            extension="com",
            whois_server="whois.verisign-grs.com",
            created_date="1997-09-15T04:00:00Z",
            expiration_date="2028-09-14T04:00:00Z",
            status=["clientTransferProhibited"],
            dnssec=True,
        )
        assert rec.extension == "com"
        assert rec.status == ["clientTransferProhibited"]
        assert rec.dnssec is True

    def test_serialise_roundtrip(self, target_apex):

        original = DomainRecord(domain=target_apex, status=["ok"], dnssec=True)
        restored = DomainRecord.model_validate_json(original.model_dump_json())
        assert restored.domain == target_apex
        assert restored.status == ["ok"]
        assert restored.dnssec is True

    def test_rejects_empty_domain(self):

        with pytest.raises(ValidationError):
            DomainRecord(domain="")

    def test_rejects_oversize_raw(self, target_apex):
        # The raw WHOIS text is tool-captured; the boundary cap is the
        # defence against an outsize injection riding the registry response.

        with pytest.raises(ValidationError):
            DomainRecord(domain=target_apex, raw="x" * 8001)


class TestContact:
    def test_role_only_minimum(self):
        # vCard fields are all optional - a Contact with just a role is
        # legal but useless. The parser's _build_contact drops these
        # before they reach RdapRecord; the model itself accepts.
        c = Contact(role=ContactRole.ABUSE)
        assert c.email is None
        assert c.name is None
        assert c.phone is None

    def test_full_contact(self):
        c = Contact(
            role=ContactRole.REGISTRANT,
            email="abuse@example.com",
            name="Example Corp",
            phone="+1-555-0123",
        )
        assert c.role is ContactRole.REGISTRANT
        assert c.email == "abuse@example.com"

    def test_invalid_email_rejects_contact(self):
        # The Email primitive's validator fires on construction; a
        # Contact carrying a mis-shaped email rejects rather than
        # silently swallowing the bad value.
        with pytest.raises(ValidationError):
            Contact(role=ContactRole.ABUSE, email="not-an-email")

    def test_serialise_roundtrip(self):
        original = Contact(role=ContactRole.NOC, email="noc@example.com")
        restored = Contact.model_validate_json(original.model_dump_json())
        assert restored.role is ContactRole.NOC
        assert restored.email == "noc@example.com"
