"""tests/tools/test_nvd.py - unit tests for the NVD REST client (tools/nvd.py).

All HTTP is mocked; no live NVD calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import CVE
from tools import nvd

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_nvd_cache():
    """Each test starts with an empty in-process cache."""
    nvd.clear_cache()
    yield
    nvd.clear_cache()


def _cve_payload():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {"lang": "en", "value": "Log4Shell RCE"},
                        {"lang": "es", "value": "ignored"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "type": "Primary",
                            "description": [
                                {"lang": "en", "value": "CWE-502"},
                                {"lang": "en", "value": "NVD-CWE-noinfo"},
                            ],
                        },
                        {"type": "Secondary", "description": [{"lang": "en", "value": "CWE-917"}]},
                    ],
                }
            }
        ]
    }


def _cpe_payload():
    return {
        "products": [
            {"cpe": {"cpeName": "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"}},
            {"cpe": {"cpeName": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}},
        ]
    }


def _ok(json_body):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_body
    return resp


class TestParseCweIds:
    def test_extracts_numeric_cwes_dropping_placeholders_and_garbage(self):
        weaknesses = [
            "not-a-dict",  # malformed entry is skipped
            {"description": [{"value": "CWE-89"}, {"value": "NVD-CWE-Other"}, "not-a-dict"]},
            {"description": [{"value": "CWE-89"}]},  # duplicate id de-duped
        ]
        assert nvd._parse_cwe_ids(weaknesses) == [89]

    def test_empty_returns_empty(self):
        assert nvd._parse_cwe_ids([]) == []


class TestCvesForKeyword:
    def test_parses_typed_cve_entry(self):
        with patch("tools.nvd.http.get", return_value=_ok(_cve_payload())) as mget:
            results = nvd.cves_for_keyword("log4shell")
        assert len(results) == 1
        assert isinstance(results[0], CVE)
        assert results[0].id == "CVE-2021-44228"
        assert results[0].cvss_score == 10.0
        assert results[0].description == "Log4Shell RCE"
        # CWE comes from NVD's weaknesses (authoritative), not an agent guess;
        # the NVD-CWE-noinfo placeholder is dropped.
        assert results[0].cwe_ids == [502, 917]
        # keyword path uses the CVE endpoint + keywordSearch
        assert mget.call_args.kwargs["params"]["keywordSearch"] == "log4shell"

    def test_empty_keyword_short_circuits_without_request(self):
        with patch("tools.nvd.http.get") as mget:
            assert nvd.cves_for_keyword("   ") == []
        mget.assert_not_called()

    def test_network_error_degrades_to_empty(self):
        with patch("tools.nvd.http.get", side_effect=Exception("network down")):
            assert nvd.cves_for_keyword("sqli") == []

    def test_result_is_cached_second_call_no_request(self):
        with patch("tools.nvd.http.get", return_value=_ok(_cve_payload())) as mget:
            nvd.cves_for_keyword("log4shell")
            nvd.cves_for_keyword("log4shell")
        assert mget.call_count == 1


class TestCvesForCpe:
    def test_queries_by_cpe_name(self):
        cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        with patch("tools.nvd.http.get", return_value=_ok(_cve_payload())) as mget:
            results = nvd.cves_for_cpe(cpe)
        assert results[0].id == "CVE-2021-44228"
        assert mget.call_args.kwargs["params"]["cpeName"] == cpe

    def test_empty_cpe_short_circuits(self):
        with patch("tools.nvd.http.get") as mget:
            assert nvd.cves_for_cpe("") == []
        mget.assert_not_called()

    def test_keyword_and_cpe_caches_are_distinct(self):
        # Same string queried two ways must not collide in the cache.
        with patch("tools.nvd.http.get", return_value=_ok(_cve_payload())) as mget:
            nvd.cves_for_keyword("openssh")
            nvd.cves_for_cpe("openssh")
        assert mget.call_count == 2


class TestSearchCpes:
    def test_returns_cpe_names(self):
        with patch("tools.nvd.http.get", return_value=_ok(_cpe_payload())) as mget:
            names = nvd.search_cpes("apache http server")
        assert names == [
            "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        ]
        # CPE search hits the CPE endpoint with keywordSearch
        assert mget.call_args.args[0].endswith("/cpes/2.0")
        assert mget.call_args.kwargs["params"]["keywordSearch"] == "apache http server"

    def test_empty_query_short_circuits(self):
        with patch("tools.nvd.http.get") as mget:
            assert nvd.search_cpes("") == []
        mget.assert_not_called()

    def test_network_error_degrades_to_empty(self):
        with patch("tools.nvd.http.get", side_effect=Exception("boom")):
            assert nvd.search_cpes("nginx") == []

    def test_result_is_cached_second_call_no_request(self):
        with patch("tools.nvd.http.get", return_value=_ok(_cpe_payload())) as mget:
            first = nvd.search_cpes("apache")
            second = nvd.search_cpes("apache")
        assert first == second
        assert mget.call_count == 1


class TestApiKeyHeader:
    def test_sends_api_key_header_when_configured(self, monkeypatch):
        monkeypatch.setattr("tools.nvd.config.scan.nvd_api_key", "test-key-123")
        with patch("tools.nvd.http.get", return_value=_ok(_cve_payload())) as mget:
            nvd.cves_for_keyword("xss")
        assert mget.call_args.kwargs["headers"]["apiKey"] == "test-key-123"

    def test_no_header_when_key_absent(self, monkeypatch):
        monkeypatch.setattr("tools.nvd.config.scan.nvd_api_key", None)
        with patch("tools.nvd.http.get", return_value=_ok(_cve_payload())) as mget:
            nvd.cves_for_keyword("xss")
        assert "apiKey" not in mget.call_args.kwargs["headers"]
