"""tests/models/nvd/test_cve.py - unit tests for the CVE shape."""

from __future__ import annotations

import pytest

from models import CVE

pytestmark = pytest.mark.unit


class TestCVE:
    def test_minimal(self):
        entry = CVE(id="CVE-2021-44228")
        assert entry.id == "CVE-2021-44228"
        assert entry.cvss_score is None
        assert entry.cvss_vector is None
        assert entry.description == ""

    def test_full(self):
        entry = CVE(
            id="CVE-2021-44228",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            description="Log4Shell.",
        )
        assert entry.cvss_score == 10.0
        # CVE.cvss_vector stays a bare str: it carries NVD's external
        # vectorString verbatim (which may be CVSS 2.0/3.x/4.0), so it is not
        # constrained by the CvssVector primitive.
        assert entry.cvss_vector.startswith("CVSS:3.1")

    def test_serialise_roundtrip(self):
        original = CVE(id="CVE-2022-22965", cvss_score=9.8)
        restored = CVE.model_validate_json(original.model_dump_json())
        assert restored.id == "CVE-2022-22965"
        assert restored.cvss_score == 9.8

    def test_url_is_the_nvd_detail_page(self):
        entry = CVE(id="CVE-2021-44228")
        assert entry.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        # computed_field, so it serialises into the agent-facing dump.
        assert entry.model_dump()["url"] == entry.url

    def test_cwe_ids_are_carried_verbatim_no_corpus_resolution(self):
        # CVE is a flat NVD DTO: cwe_ids are stored as-is, with no enrichment /
        # corpus lookup on the model. Name resolution is the consumer's job
        # (tools.recon_insights.vuln_from_cve / the Lookup CWE tool), so the
        # dump carries plain ids - not nested CWE objects.
        entry = CVE(id="CVE-2021-44228", cwe_ids=[79, 9_999_999])
        assert entry.cwe_ids == [79, 9_999_999]
        dumped = entry.model_dump()
        assert dumped["cwe_ids"] == [79, 9_999_999]
        assert "cwes" not in dumped
