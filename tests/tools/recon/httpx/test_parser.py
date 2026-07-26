"""tests/tools/recon/httpx/test_parser.py - unit tests for tools/recon/httpx/parser.py."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


class TestBuildTlsCertificate:
    """Direct coverage of the defensive branches in ``_build_tls_certificate``
    that the mode-level tests do not reach."""

    def test_empty_or_non_dict_block_yields_none(self, target_url):
        from tools.recon.httpx.parser import _build_tls_certificate

        assert _build_tls_certificate({}, [], target_url) is None
        assert _build_tls_certificate("not-a-dict", [], target_url) is None

    def test_no_derivable_host_yields_none(self):
        from tools.recon.httpx.parser import _build_tls_certificate

        # A URL with no hostname -> the cert has nothing to anchor to.
        assert _build_tls_certificate({"subject_cn": "x"}, [], "not a url") is None

    def test_oversize_field_drops_cert(self, target_url):
        from tools.recon.httpx.parser import _build_tls_certificate

        # issuer past the 255-char cap trips the model -> cert dropped.
        assert _build_tls_certificate({"issuer_cn": "x" * 256}, [], target_url) is None


class TestParseCertDatetime:
    def test_parses_rfc3339_z(self):
        from tools.recon.httpx.parser import _parse_cert_datetime

        assert _parse_cert_datetime("2026-09-01T00:00:00Z") is not None

    def test_none_for_non_string(self):
        from tools.recon.httpx.parser import _parse_cert_datetime

        assert _parse_cert_datetime(None) is None
        assert _parse_cert_datetime(1717200000) is None

    def test_none_for_malformed(self):
        from tools.recon.httpx.parser import _parse_cert_datetime

        assert _parse_cert_datetime("not-a-date") is None
