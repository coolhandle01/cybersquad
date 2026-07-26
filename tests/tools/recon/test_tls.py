"""tests/tools/recon/test_tls.py - unit tests for tools/recon/tls.py"""

from __future__ import annotations

import json
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from models import Endpoint, Severity
from tools.recon.tls import (
    _get_dmarc,
    _get_spf,
    _root_domain,
    check_dns_email_security,
    check_tls,
)

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# _root_domain
# ---------------------------------------------------------------------------


class TestRootDomain:
    def test_strips_subdomain(self):
        assert _root_domain("app.example.com") == "example.com"

    def test_leaves_root_unchanged(self):
        assert _root_domain("example.com") == "example.com"

    def test_strips_deep_subdomain(self):
        assert _root_domain("a.b.c.example.com") == "example.com"

    def test_single_label(self):
        assert _root_domain("localhost") == "localhost"


# ---------------------------------------------------------------------------
# check_tls
# ---------------------------------------------------------------------------


class TestCheckTls:
    def _testssl_item(self, test_id: str, severity: str, finding: str, cve: str = "") -> dict:
        return {"id": test_id, "severity": severity, "finding": finding, "cve": cve}

    def test_returns_empty_when_testssl_missing(self, target_url: str):
        ep = Endpoint(url=f"{target_url}/", status_code=200)
        with patch("shutil.which", return_value=None):
            results = check_tls([ep])
        assert results == []

    def test_skips_when_tls_disabled(self, monkeypatch, target_url: str):
        """STEALTH posture flips ``config.scan.tls_enabled`` False.

        Gate fires before endpoint filtering / testssl detection - no
        subprocess fires when the operator dial is stealth. Parallel
        to the traceroute gate; both are binary "do this at all" levers
        because slowing them does not buy quiet.
        """
        import tools.recon.tls as tls_mod

        monkeypatch.setattr(tls_mod.config.scan, "tls_enabled", False)
        endpoint = Endpoint(url=f"{target_url}/", status_code=200)
        with patch("shutil.which") as which:
            with patch("tools.recon.tls._run") as run:
                findings = check_tls([endpoint])
        assert findings == []
        which.assert_not_called()
        run.assert_not_called()

    def test_returns_empty_when_no_https_endpoints(self):
        ep = Endpoint(url="http://app.example.com/", status_code=200)
        with patch("shutil.which", return_value="/usr/bin/testssl.sh"):
            results = check_tls([ep])
        assert results == []

    def test_parses_testssl_findings(self, target_url: str):
        ep = Endpoint(url=f"{target_url}/", status_code=200)
        report = [
            self._testssl_item("heartbleed", "CRITICAL", "VULNERABLE", "CVE-2014-0160"),
            self._testssl_item("SSLv2", "HIGH", "offered (deprecated)"),
            self._testssl_item("service", "INFO", "HTTP"),  # should be skipped
        ]

        def fake_run(cmd, timeout: int = 120, input: str | None = None) -> CompletedProcess:
            out_path = cmd[cmd.index("--jsonfile") + 1]
            with open(out_path, "w") as fh:
                json.dump(report, fh)
            return CompletedProcess(cmd, 0, "", "")

        with patch("shutil.which", return_value="/usr/bin/testssl.sh"):
            with patch("tools.recon.tls._run", side_effect=fake_run):
                results = check_tls([ep])

        assert len(results) == 2
        titles = [r.title for r in results]
        assert any("heartbleed" in t for t in titles)
        assert any("SSLv2" in t for t in titles)

        crit = next(r for r in results if "heartbleed" in r.title)
        assert crit.severity_hint == Severity.CRITICAL
        assert "CVE-2014-0160" in crit.evidence

    def test_skips_ok_and_info_severity(self, target_url: str):
        ep = Endpoint(url=f"{target_url}/", status_code=200)
        report = [
            self._testssl_item("TLS1_3", "OK", "offered"),
            self._testssl_item("cert_chain_of_trust", "INFO", "chain ok"),
        ]

        def fake_run(cmd, timeout: int = 120, input: str | None = None) -> CompletedProcess:
            out_path = cmd[cmd.index("--jsonfile") + 1]
            with open(out_path, "w") as fh:
                json.dump(report, fh)
            return CompletedProcess(cmd, 0, "", "")

        with patch("shutil.which", return_value="/usr/bin/testssl.sh"):
            with patch("tools.recon.tls._run", side_effect=fake_run):
                results = check_tls([ep])

        assert results == []

    def test_deduplicates_same_host(self, target_url: str):
        endpoints = [
            Endpoint(url=f"{target_url}/page1", status_code=200),
            Endpoint(url=f"{target_url}/page2", status_code=200),
        ]
        call_count = 0

        def fake_run(cmd, timeout: int = 120, input: str | None = None) -> CompletedProcess:
            nonlocal call_count
            call_count += 1
            out_path = cmd[cmd.index("--jsonfile") + 1]
            with open(out_path, "w") as fh:
                json.dump([], fh)
            return CompletedProcess(cmd, 0, "", "")

        with patch("shutil.which", return_value="/usr/bin/testssl.sh"):
            with patch("tools.recon.tls._run", side_effect=fake_run):
                check_tls(endpoints)

        assert call_count == 1

    def test_skips_non_200_endpoints(self, target_url: str):
        ep = Endpoint(url=f"{target_url}/", status_code=500)
        with patch("shutil.which", return_value="/usr/bin/testssl.sh"):
            with patch("tools.recon.tls._run") as mock_run:
                results = check_tls([ep])
        mock_run.assert_not_called()
        assert results == []

    def test_handles_run_exception(self, target_url: str):
        ep = Endpoint(url=f"{target_url}/", status_code=200)
        with patch("shutil.which", return_value="/usr/bin/testssl.sh"):
            with patch("tools.recon.tls._run", side_effect=Exception("timeout")):
                results = check_tls([ep])
        assert results == []

    def test_handles_missing_output_file(self, target_url: str):
        ep = Endpoint(url=f"{target_url}/", status_code=200)

        def fake_run(cmd, timeout: int = 120, input: str | None = None) -> CompletedProcess:
            # Do not write the JSON file
            return CompletedProcess(cmd, 1, "", "error")

        with patch("shutil.which", return_value="/usr/bin/testssl.sh"):
            with patch("tools.recon.tls._run", side_effect=fake_run):
                results = check_tls([ep])
        assert results == []


# ---------------------------------------------------------------------------
# _get_spf / _get_dmarc (unit tests via dns mock)
# ---------------------------------------------------------------------------


def _make_dns_answer(txt: str) -> MagicMock:
    """Build a mock dns.resolver answer containing a single TXT record."""
    rdata = MagicMock()
    rdata.strings = [txt.encode()]
    answer = MagicMock()
    answer.__iter__ = MagicMock(return_value=iter([rdata]))
    return answer


class TestGetSpf:
    def test_returns_spf_record(self):
        spf = "v=spf1 include:_spf.example.com ~all"
        with patch("dns.resolver.resolve", return_value=_make_dns_answer(spf)):
            result = _get_spf("example.com")
        assert result == spf

    def test_returns_none_when_absent(self):
        import dns.exception

        with patch("dns.resolver.resolve", side_effect=dns.exception.DNSException):
            result = _get_spf("example.com")
        assert result is None

    def test_returns_none_when_only_unrelated_txt(self):
        txt = "google-site-verification=abc123"
        with patch("dns.resolver.resolve", return_value=_make_dns_answer(txt)):
            result = _get_spf("example.com")
        assert result is None


class TestGetDmarc:
    def test_returns_dmarc_record(self):
        dmarc = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        with patch("dns.resolver.resolve", return_value=_make_dns_answer(dmarc)):
            result = _get_dmarc("example.com")
        assert result is not None
        assert "p=reject" in result

    def test_returns_none_when_absent(self):
        import dns.exception

        with patch("dns.resolver.resolve", side_effect=dns.exception.DNSException):
            result = _get_dmarc("example.com")
        assert result is None


# ---------------------------------------------------------------------------
# check_dns_email_security
# ---------------------------------------------------------------------------


class TestCheckDnsEmailSecurity:
    def test_flags_missing_spf(self):
        with patch("tools.recon.tls._get_spf", return_value=None):
            with patch("tools.recon.tls._get_dmarc", return_value="v=DMARC1; p=reject"):
                results = check_dns_email_security(["example.com"])

        spf_findings = [r for r in results if "SPF" in r.title and "Missing" in r.title]
        assert len(spf_findings) == 1
        assert spf_findings[0].severity_hint == Severity.MEDIUM

    def test_flags_permissive_spf(self):
        with patch("tools.recon.tls._get_spf", return_value="v=spf1 +all"):
            with patch("tools.recon.tls._get_dmarc", return_value="v=DMARC1; p=reject"):
                results = check_dns_email_security(["example.com"])

        spf_findings = [r for r in results if "+all" in r.title]
        assert len(spf_findings) == 1
        assert spf_findings[0].severity_hint == Severity.HIGH

    def test_flags_missing_dmarc(self):
        with patch("tools.recon.tls._get_spf", return_value="v=spf1 include:_ ~all"):
            with patch("tools.recon.tls._get_dmarc", return_value=None):
                results = check_dns_email_security(["example.com"])

        dmarc_findings = [r for r in results if "DMARC" in r.title and "Missing" in r.title]
        assert len(dmarc_findings) == 1
        assert dmarc_findings[0].severity_hint == Severity.MEDIUM

    def test_flags_dmarc_p_none(self):
        dmarc = "v=DMARC1; p=none; rua=mailto:x@y.com"
        with patch("tools.recon.tls._get_spf", return_value="v=spf1 include:_ ~all"):
            with patch("tools.recon.tls._get_dmarc", return_value=dmarc):
                results = check_dns_email_security(["example.com"])

        none_findings = [r for r in results if "p=none" in r.title]
        assert len(none_findings) == 1
        assert none_findings[0].severity_hint == Severity.LOW

    def test_no_finding_when_spf_and_dmarc_ok(self):
        with patch("tools.recon.tls._get_spf", return_value="v=spf1 include:_ ~all"):
            with patch("tools.recon.tls._get_dmarc", return_value="v=DMARC1; p=reject"):
                results = check_dns_email_security(["example.com"])
        assert results == []

    def test_deduplicates_subdomains_to_root(self):
        calls: list[str] = []

        def tracking_spf(domain: str) -> str | None:
            calls.append(domain)
            return "v=spf1 include:_ ~all"

        with patch("tools.recon.tls._get_spf", side_effect=tracking_spf):
            with patch("tools.recon.tls._get_dmarc", return_value="v=DMARC1; p=reject"):
                check_dns_email_security(["app.example.com", "api.example.com", "example.com"])

        # All three hostnames collapse to example.com - only one DNS call
        assert calls == ["example.com"]

    def test_empty_domain_list(self):
        results = check_dns_email_security([])
        assert results == []
