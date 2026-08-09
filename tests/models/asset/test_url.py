"""tests/models/asset/test_url.py - unit tests for models/asset/url.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import SourceProperty, Url

pytestmark = pytest.mark.unit


class TestUrl:
    def test_minimal_record(self, target_apex):
        # raw is the only floor; the parsed components populate as the URL
        # parser breaks it down.
        u = Url(raw=f"https://{target_apex}/")
        assert u.raw == f"https://{target_apex}/"
        assert u.scheme == ""
        assert u.port is None
        assert u.username == ""
        assert u.password == ""
        assert u.sources == []

    def test_sources_carry(self, target_apex):
        # Provenance defaults empty; the httpx producer stamps it at write time.
        u = Url(
            raw=f"https://{target_apex}/",
            sources=[SourceProperty(source="httpx", confidence=100)],
        )
        assert u.sources[0].source == "httpx"

    def test_full_parsed_components(self, target_apex):
        u = Url(
            raw=f"https://api.{target_apex}:8443/v1/users?page=2#section",
            scheme="https",
            host=f"api.{target_apex}",
            port=8443,
            path="/v1/users",
            options="page=2",
            fragment="section",
        )
        assert u.scheme == "https"
        assert u.port == 8443
        assert u.path == "/v1/users"
        assert u.options == "page=2"
        assert u.fragment == "section"

    def test_host_accepts_ip_literal(self):
        # host is a bare str, not FQDN: a URL host is legitimately an IP
        # literal as well as a hostname.
        u = Url(raw="http://203.0.113.7:8080/x", scheme="http", host="203.0.113.7", port=8080)
        assert u.host == "203.0.113.7"

    def test_carries_userinfo_credentials(self):
        # Credentials are modelled for OAM fidelity (and must be redacted
        # before any LLM-facing surface - see the model's SECURITY note).
        u = Url(raw="https://user:pass@host.test/", username="user", password="pass")
        assert u.username == "user"
        assert u.password == "pass"

    def test_serialise_roundtrip(self, target_apex):

        original = Url(raw=f"https://{target_apex}/a", scheme="https", host=target_apex)
        restored = Url.model_validate_json(original.model_dump_json())
        assert restored.raw == f"https://{target_apex}/a"
        assert restored.host == target_apex

    def test_rejects_empty_raw(self):

        with pytest.raises(ValidationError):
            Url(raw="")

    def test_rejects_out_of_range_port(self):

        with pytest.raises(ValidationError):
            Url(raw="http://x/", port=70000)
