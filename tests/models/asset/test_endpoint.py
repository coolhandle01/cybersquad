"""tests/models/asset/test_endpoint.py - unit tests for models/asset/endpoint.py."""

from __future__ import annotations

import pytest

from models import Endpoint, SourceProperty

pytestmark = pytest.mark.unit


# FQDN is exercised through a throwaway pydantic model so the validator
# fires the same way it does when carried on a real schema field. Stick to
# pytest.raises(ValidationError) rather than the lower-level ValueError so
# the test mirrors what schema callers will see.


class TestEndpoint:
    def test_valid_endpoint(self, endpoint):
        assert endpoint.status_code == 200
        assert "nginx" in endpoint.technologies

    def test_optional_fields_default(self, target_apex):
        ep = Endpoint(url=f"https://{target_apex}")
        assert ep.status_code is None
        assert ep.technologies == []
        assert ep.parameters == []

    def test_vulns_default_empty(self, target_apex):
        # The OAM VulnProperty annotations the OA / VR hang off an endpoint;
        # empty until a CVE is matched against a detected technology.
        ep = Endpoint(url=f"https://{target_apex}")
        assert ep.vulns == []

    def test_sources_default_and_carry(self, target_apex):
        # Provenance defaults empty; the httpx producer stamps it at write time.
        ep = Endpoint(url=f"https://{target_apex}")
        assert ep.sources == []
        ep2 = Endpoint(
            url=f"https://{target_apex}",
            sources=[SourceProperty(source="httpx", confidence=100)],
        )
        assert ep2.sources[0].source == "httpx"
