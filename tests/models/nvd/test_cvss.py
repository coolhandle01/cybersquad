"""tests/models/nvd/test_cvss.py - unit tests for the CvssVector primitive."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from models import CvssVector

pytestmark = pytest.mark.unit


class _CvssProbe(BaseModel):
    """Thin probe model to drive the CvssVector validator in isolation."""

    value: CvssVector


class TestCvssVector:
    @pytest.mark.parametrize(
        "raw",
        [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N",
        ],
    )
    def test_accepts_well_formed_vectors(self, raw):
        assert _CvssProbe(value=raw).value == raw

    def test_strips_whitespace(self):
        v = "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  "
        assert _CvssProbe(value=v).value == v.strip()

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            "AV:N/AC:L/PR:N",  # no CVSS:3.x prefix
            "CVSS:2.0/AV:N/AC:L",  # wrong version
            "CVSS:3.1",  # prefix but no metric tokens
            "CVSS:3.1/AVN/AC:L",  # malformed token (no colon)
            "CVSS:3.1/av:n",  # lowercase - not the uppercase KEY:VALUE shape
            "CVSS:3.1/AV:N/AC:L",  # incomplete - missing mandatory base metrics
            "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid metric value
        ],
    )
    def test_rejects_malformed(self, bad):
        with pytest.raises(ValidationError):
            _CvssProbe(value=bad)

    def test_runtime_type_is_str(self):
        probe = _CvssProbe(value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert isinstance(probe.value, str)
        assert probe.value.startswith("CVSS:3.1")
