"""tests/models/asset/test_certificate.py - unit tests for models/asset/certificate.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import TLSCertificate

pytestmark = pytest.mark.unit


class TestTLSCertificate:
    def test_minimal_record(self, target_apex):
        # host is the only floor; the grabbed cert detail populates as
        # the tls-grab / testssl pass recovers it.

        cert = TLSCertificate(host=f"www.{target_apex}")
        assert cert.host == f"www.{target_apex}"
        assert cert.subject_common_name is None
        assert cert.fingerprint_sha256 is None
        assert cert.subject_alt_names == []

    def test_captures_wildcard_san(self, target_apex):
        # The whole reason SANs are list[str] not list[FQDN]: a wildcard
        # SAN must survive into the cert asset, where list[FQDN] would
        # reject it. iPAddress SANs land the same way.

        cert = TLSCertificate(
            host=f"www.{target_apex}",
            subject_common_name=f"www.{target_apex}",
            issuer="Let's Encrypt",
            subject_alt_names=[f"*.{target_apex}", target_apex, "203.0.113.7"],
        )
        assert f"*.{target_apex}" in cert.subject_alt_names
        assert "203.0.113.7" in cert.subject_alt_names

    def test_serialise_roundtrip(self, target_apex):

        original = TLSCertificate(
            host=f"www.{target_apex}",
            fingerprint_sha256="ab" * 32,
            subject_alt_names=[f"*.{target_apex}"],
        )
        restored = TLSCertificate.model_validate_json(original.model_dump_json())
        assert restored.fingerprint_sha256 == "ab" * 32
        assert restored.subject_alt_names == [f"*.{target_apex}"]

    def test_rejects_malformed_host(self):

        with pytest.raises(ValidationError):
            TLSCertificate(host="https://evil.test/x")

    def test_rejects_oversize_issuer(self, target_apex):
        # The attacker-controlled cert string fields carry boundary caps.

        with pytest.raises(ValidationError):
            TLSCertificate(host=f"www.{target_apex}", issuer="x" * 256)
