"""tests/tools/test_cpe.py - unit tests for tools/cpe.py (CPE normalisation)."""

from __future__ import annotations

import pytest

from tools.cpe import normalize_cpe, pick_application_cpe, product_release_from_cpe

pytestmark = pytest.mark.unit


class TestProductReleaseFromCpe:
    def test_decomposes_product_and_version(self):
        decomposed = product_release_from_cpe("cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*")
        assert decomposed is not None
        product, release = decomposed
        assert product.name == "nginx"
        assert release.name == "nginx 1.25.3"

    def test_no_version_uses_product_alone(self):
        decomposed = product_release_from_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
        assert decomposed is not None
        product, release = decomposed
        assert product.name == "nginx"
        assert release.name == "nginx"

    def test_none_when_no_product(self):
        # An OS / wildcard row that names no product yields nothing.
        assert product_release_from_cpe("cpe:2.3:o:*:*:*:*:*:*:*:*:*:*") is None

    def test_none_on_unparseable(self):
        assert product_release_from_cpe("not a cpe") is None


class TestNormalizeCpe:
    def test_converts_2_2_uri_to_2_3_formatted_string(self):
        # nmap emits the legacy 2.2 URI binding; we canonicalise to 2.3 FS.
        assert (
            normalize_cpe("cpe:/a:openbsd:openssh:7.4")
            == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        )

    def test_passes_through_2_3_formatted_string(self):
        fs = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        assert normalize_cpe(fs) == fs

    def test_normalises_operating_system_part(self):
        assert (
            normalize_cpe("cpe:/o:linux:linux_kernel")
            == "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
        )

    def test_unparseable_string_returns_none(self):
        assert normalize_cpe("not-a-cpe") is None

    def test_empty_and_none_return_none(self):
        assert normalize_cpe("") is None
        assert normalize_cpe("   ") is None
        assert normalize_cpe(None) is None

    def test_over_length_input_returns_none(self):
        # A value longer than the field cap is junk / injection, not a CPE -
        # rejected before the parser is asked to make sense of it.
        assert normalize_cpe("cpe:/a:" + "x" * 300) is None


class TestPickApplicationCpe:
    def test_prefers_application_over_os(self):
        # A service row carrying both the app and host-OS CPE: the app one
        # keys CVEs for the listening software, so it wins.
        picked = pick_application_cpe(["cpe:/o:linux:linux_kernel", "cpe:/a:openbsd:openssh:7.4"])
        assert picked == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"

    def test_falls_back_to_first_parseable_when_no_application(self):
        picked = pick_application_cpe(["cpe:/o:linux:linux_kernel"])
        assert picked == "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"

    def test_skips_unparseable_entries(self):
        picked = pick_application_cpe(["garbage", "cpe:/a:nginx:nginx:1.18.0"])
        assert picked == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"

    def test_empty_list_returns_none(self):
        assert pick_application_cpe([]) is None

    def test_all_unparseable_returns_none(self):
        assert pick_application_cpe(["garbage", "also-not-a-cpe"]) is None
