"""tests/models/test_insight.py - unit tests for models/insight.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import HostInsight, HostPriority, HostRole, HostScore, VulnProperty

pytestmark = pytest.mark.unit


class TestHostScore:
    def test_minimal(self, target_apex):

        s = HostScore(hostname=f"api.{target_apex}", role=HostRole.API, priority=HostPriority.HIGH)
        assert s.role == HostRole.API
        assert s.priority == HostPriority.HIGH
        assert s.annotated_at is not None

    def test_serialise_roundtrip(self, target_apex):

        original = HostScore(
            hostname=f"auth.{target_apex}", role=HostRole.AUTH, priority=HostPriority.MEDIUM
        )
        restored = HostScore.model_validate_json(original.model_dump_json())
        assert restored.hostname == f"auth.{target_apex}"
        assert restored.role == HostRole.AUTH

    def test_rejects_malformed_host(self):

        with pytest.raises(ValidationError):
            HostScore(hostname="https://x/y", role=HostRole.API, priority=HostPriority.LOW)


class TestHostInsight:
    def test_carries_vulns(self, target_apex):
        insight = HostInsight(
            hostname=f"blog.{target_apex}",
            role=HostRole.APP,
            priority=HostPriority.HIGH,
            notes="WordPress 5.8.1 blog host - dated core, worth a CVE pass here.",
            detected_tech=["WordPress 5.8.1"],
            vulns=[VulnProperty(id="CVE-2021-44223", source="nvd", enumeration="CVE")],
        )
        assert insight.vulns[0].id == "CVE-2021-44223"
