"""tests/models/asset/test_service.py - unit tests for models/asset/service.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import Product, ProductRelease, Service, SourceProperty, VulnProperty

pytestmark = pytest.mark.unit


class TestService:
    def test_minimal_record(self):
        # id is the only floor; type / output / attributes populate as the
        # nmap service-detection pass recovers them.
        svc = Service(id="8.8.8.8:443/tcp")
        assert svc.id == "8.8.8.8:443/tcp"
        assert svc.type == ""
        assert svc.output == ""
        assert svc.attributes == {}
        assert svc.vulns == []

    def test_carries_banner_in_output_and_attributes(self, target_apex):
        # host:port -> id; the nmap banner detail -> output / attributes (the
        # product / version / cpe become Product / ProductRelease assets via
        # the producer, not Service fields).
        svc = Service(
            id=f"api.{target_apex}:443/tcp",
            type="http",
            output="nginx 1.25.3 (Ubuntu)",
            output_length=len("nginx 1.25.3 (Ubuntu)"),
            attributes={
                "product": ["nginx"],
                "version": ["1.25.3"],
                "cpe": ["cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*"],
            },
        )
        assert svc.type == "http"
        assert svc.attributes["cpe"] == ["cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*"]

    def test_serialise_roundtrip(self):
        original = Service(id="1.1.1.1:53/udp", type="domain", attributes={"product": ["dnsmasq"]})
        restored = Service.model_validate_json(original.model_dump_json())
        assert restored.id == "1.1.1.1:53/udp"
        assert restored.attributes == {"product": ["dnsmasq"]}

    def test_rejects_empty_id(self):
        with pytest.raises(ValidationError):
            Service(id="")

    def test_rejects_oversize_output(self):
        # The max_length cap on the tool-captured banner is the boundary
        # defence against an outsize injection riding a malformed banner.
        with pytest.raises(ValidationError):
            Service(id="h:1/tcp", output="x" * 2049)

    def test_carries_vulns(self, target_apex):
        svc = Service(
            id=f"api.{target_apex}:443/tcp",
            vulns=[VulnProperty(id="CVE-2021-23017", source="nvd", enumeration="CVE")],
        )
        assert svc.vulns[0].id == "CVE-2021-23017"

    def test_roundtrip_preserves_vulns(self):
        svc = Service(
            id="api:8080/tcp",
            vulns=[VulnProperty(id="CVE-2022-22965", enumeration="CVE")],
        )
        restored = Service.model_validate_json(svc.model_dump_json())
        assert restored.vulns[0].id == "CVE-2022-22965"

    def test_sources_default_and_carry(self):
        # Provenance defaults empty; the nmap producer stamps it at write time.
        assert Service(id="h:1/tcp").sources == []
        svc = Service(id="h:1/tcp", sources=[SourceProperty(source="nmap", confidence=100)])
        assert svc.sources[0].source == "nmap"


class TestProduct:
    def test_minimal_record(self):
        # product_name is the only floor; the rest of the OAM Product facets
        # populate as the agent / feed enriches them.
        p = Product(name="WordPress")
        assert p.name == "WordPress"
        assert p.product_id == ""
        assert p.category == ""

    def test_full_record(self):
        p = Product(
            name="Spring Framework",
            product_id="pkg:maven/org.springframework",
            type="web-framework",
            category="application framework",
            country_of_origin="US",
        )
        assert p.type == "web-framework"
        assert p.country_of_origin == "US"

    def test_rejects_empty_name(self):

        with pytest.raises(ValidationError):
            Product(name="")

    def test_sources_default_and_carry(self):
        assert Product(name="nginx").sources == []
        p = Product(name="nginx", sources=[SourceProperty(source="nmap", confidence=90)])
        assert p.sources[0].confidence == 90


class TestProductRelease:
    def test_minimal_record(self):
        rel = ProductRelease(name="WordPress 5.8.1")
        assert rel.name == "WordPress 5.8.1"
        assert rel.release_date == ""
        assert rel.vulns == []

    def test_carries_vulns_the_spec_proper_anchor(self):
        # ProductRelease is where a VulnProperty hangs in OAM - the CVE is
        # carried by the exact released version.
        rel = ProductRelease(
            name="WordPress 5.8.1",
            release_date="2021-09-09",
            vulns=[VulnProperty(id="CVE-2021-44223", source="nvd", enumeration="CVE")],
        )
        assert rel.vulns[0].id == "CVE-2021-44223"

    def test_serialise_roundtrip(self):

        original = ProductRelease(
            name="nginx 1.25.3",
            vulns=[VulnProperty(id="CVE-2021-23017", enumeration="CVE")],
        )
        restored = ProductRelease.model_validate_json(original.model_dump_json())
        assert restored.name == "nginx 1.25.3"
        assert restored.vulns[0].id == "CVE-2021-23017"

    def test_rejects_empty_name(self):

        with pytest.raises(ValidationError):
            ProductRelease(name="")

    def test_sources_default_and_carry(self):
        assert ProductRelease(name="nginx 1.25.3").sources == []
        rel = ProductRelease(
            name="nginx 1.25.3", sources=[SourceProperty(source="nmap", confidence=80)]
        )
        assert rel.sources[0].source == "nmap"
