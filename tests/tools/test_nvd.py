"""tests/tools/test_nvd.py - unit tests for the NVD REST client (tools/nvd.py).

All HTTP is mocked; no live NVD calls. Response mocks come from the shared
``make_response`` fixture (tests/fixtures/responses.py) - it is the canonical
``requests.Response`` double, so this file does not hand-roll one.

The suite observes three seams the module contracts on:

* the *outbound request* - endpoint URL, the ``params`` dict (query field +
  ``resultsPerPage``), the ``apiKey`` header, and the ``timeout`` - because a
  wrong param silently returns the wrong CVEs;
* the *parse* - ``_parse_cve`` / ``_parse_cwe_ids`` are driven directly so a
  degrade-to-empty branch surfaces as a return value, not a swallowed
  exception. The module's promise is "a rough-shaped response never blocks the
  pipeline", so every missing-key path is asserted to keep the record rather
  than drop the batch;
* the *cache* - the module docstring promises repeated lookups within a run do
  not re-hit the rate-limited API, and that the keyword and CPE paths do not
  collide. Both directions are pinned by observing ``http.get`` call counts.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

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


def _cve_body(cve: dict[str, Any]) -> dict[str, Any]:
    """Wrap a single ``cve`` object in the NVD CVE-API envelope."""
    return {"vulnerabilities": [{"cve": cve}]}


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

    def test_weakness_without_description_key_is_skipped_not_fatal(self):
        # A weakness dict that carries no "description" must degrade to the empty
        # list, not blow up the parse - the default [] is load-bearing. A second,
        # well-formed weakness proves the loop keeps going and still extracts.
        weaknesses = [
            {"type": "Primary"},  # no "description" key at all
            {"description": [{"value": "CWE-89"}]},
        ]
        assert nvd._parse_cwe_ids(weaknesses) == [89]

    def test_description_entry_without_value_key_is_skipped_not_fatal(self):
        # A description entry missing "value" degrades to "" (skipped), it does
        # not abort the surrounding weakness. The CWE-79 sibling still lands.
        weaknesses = [{"description": [{"lang": "en"}, {"value": "CWE-79"}]}]
        assert nvd._parse_cwe_ids(weaknesses) == [79]

    def test_requires_both_cwe_prefix_and_numeric_suffix(self):
        # The guard is an AND: a numeric suffix under a non-CWE prefix (CAPEC-66)
        # is NOT a CWE and must be dropped; only the genuine CWE-89 survives.
        weaknesses = [
            {"description": [{"value": "CAPEC-66"}, {"value": "CWE-89"}]},
        ]
        assert nvd._parse_cwe_ids(weaknesses) == [89]


class TestParseCve:
    """``_parse_cve`` is driven directly so a degrade branch shows up as a
    returned value (or a raise the test would catch), not a swallowed one."""

    def test_full_v31_metric_maps_every_field(self):
        cve = _cve_payload()["vulnerabilities"][0]["cve"]
        result = nvd._parse_cve(cve)
        assert result.id == "CVE-2021-44228"
        assert result.cvss_score == 10.0
        # The vector is pinned exactly - not just "non-None" - so a mutation of
        # the "vectorString" key (or a hardcoded None) reddens the test.
        assert result.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        assert result.description == "Log4Shell RCE"
        # Authoritative CWEs from NVD's weaknesses; the NVD-CWE-noinfo placeholder
        # is dropped, order preserved.
        assert result.cwe_ids == [502, 917]

    def test_sparse_cve_degrades_every_field_without_dropping_the_record(self):
        # The docstring promise: "a CVE with no scored metric is still a real CVE
        # worth surfacing". An object with none of the optional keys must come
        # back as a well-formed CVE with empty/None fields - never raise, never
        # get dropped. Each default here ({}/[]/"" ) is what stops a missing key
        # from turning into a None that the next .get()/iteration explodes on.
        result = nvd._parse_cve({})
        assert result.id == ""
        assert result.cvss_score is None
        assert result.cvss_vector is None
        assert result.description == ""
        assert result.cwe_ids == []

    def test_prefers_v30_metric_when_v31_absent(self):
        cve = {
            "metrics": {
                "cvssMetricV30": [
                    {"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.0/AV:N/AC:L"}}
                ]
            }
        }
        result = nvd._parse_cve(cve)
        assert result.cvss_score == 7.5
        assert result.cvss_vector == "CVSS:3.0/AV:N/AC:L"

    def test_falls_back_to_v2_metric_when_v3_absent(self):
        cve = {
            "metrics": {
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L"}}]
            }
        }
        result = nvd._parse_cve(cve)
        assert result.cvss_score == 5.0
        assert result.cvss_vector == "AV:N/AC:L"

    def test_metric_entry_without_cvss_data_degrades_to_none(self):
        # Metric list present, but the entry carries no "cvssData" - the {} default
        # keeps the parse alive with None score/vector rather than raising on
        # None.get(...) and dropping the record.
        result = nvd._parse_cve({"metrics": {"cvssMetricV31": [{}]}})
        assert result.cvss_score is None
        assert result.cvss_vector is None
        assert result.id == ""  # still a real record


class TestCvesForKeyword:
    def test_parses_typed_cve_entry(self, make_response):
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
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

    def test_request_targets_cve_endpoint_with_default_page_size(self, make_response):
        # Pin the whole outbound shape, not just the search field: endpoint URL,
        # the default resultsPerPage (=5, the function's default limit), and the
        # NVD timeout. A wrong page-size key or a dropped timeout silently
        # changes what the pipeline sees.
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            nvd.cves_for_keyword("log4shell")
        assert mget.call_args.args == (nvd._CVE_API_URL,)
        assert mget.call_args.kwargs["params"]["resultsPerPage"] == 5
        assert mget.call_args.kwargs["timeout"] == nvd._TIMEOUT_S

    def test_limit_flows_into_results_per_page(self, make_response):
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            nvd.cves_for_keyword("log4shell", limit=3)
        assert mget.call_args.kwargs["params"]["resultsPerPage"] == 3

    def test_empty_keyword_short_circuits_without_request(self):
        with patch("tools.nvd.http.get") as mget:
            assert nvd.cves_for_keyword("   ") == []
        mget.assert_not_called()

    def test_network_error_degrades_to_empty(self):
        with patch("tools.nvd.http.get", side_effect=Exception("network down")):
            assert nvd.cves_for_keyword("sqli") == []

    def test_result_is_cached_second_call_no_request(self, make_response):
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            nvd.cves_for_keyword("log4shell")
            nvd.cves_for_keyword("log4shell")
        assert mget.call_count == 1

    def test_distinct_keywords_do_not_collide_in_cache(self, make_response):
        # Two different keywords must each hit the API and get their own result -
        # the cache key carries the keyword. A cache key that ignored the keyword
        # would serve the first payload for the second query.
        first = _cve_body({"id": "CVE-1111-0001"})
        second = _cve_body({"id": "CVE-2222-0002"})
        with patch(
            "tools.nvd.http.get",
            side_effect=[make_response(json=first), make_response(json=second)],
        ) as mget:
            r1 = nvd.cves_for_keyword("alpha")
            r2 = nvd.cves_for_keyword("beta")
        assert mget.call_count == 2
        assert r1[0].id == "CVE-1111-0001"
        assert r2[0].id == "CVE-2222-0002"

    def test_missing_vulnerabilities_key_returns_and_caches_empty(self, make_response):
        # A well-formed-but-empty envelope (no "vulnerabilities") degrades to []
        # AND is cached, so a malformed upstream response is not re-fetched. The
        # [] default is what makes the second call a cache hit instead of a raise.
        with patch("tools.nvd.http.get", return_value=make_response(json={})) as mget:
            first = nvd.cves_for_keyword("nothing")
            second = nvd.cves_for_keyword("nothing")
        assert first == []
        assert second == []
        assert mget.call_count == 1

    def test_skips_malformed_vuln_entries_keeping_valid_ones(self, make_response):
        # The isinstance guard is an AND: an entry that is a dict but whose "cve"
        # is absent, and an entry that is not a dict at all, are both filtered
        # out - the one valid CVE still comes through. A guard that dropped the
        # batch on a single bad row would be the empty-result-that-exits-0 bug.
        body = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-3333-0003"}},
                {"not_cve": 1},
                "not-a-dict",
            ]
        }
        with patch("tools.nvd.http.get", return_value=make_response(json=body)):
            results = nvd.cves_for_keyword("mixed")
        assert [c.id for c in results] == ["CVE-3333-0003"]


class TestCvesForCpe:
    def test_queries_by_cpe_name(self, make_response):
        cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            results = nvd.cves_for_cpe(cpe)
        assert results[0].id == "CVE-2021-44228"
        assert mget.call_args.kwargs["params"]["cpeName"] == cpe

    def test_request_targets_cve_endpoint_with_default_page_size(self, make_response):
        cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            nvd.cves_for_cpe(cpe)
        assert mget.call_args.args == (nvd._CVE_API_URL,)
        assert mget.call_args.kwargs["params"]["resultsPerPage"] == 5
        assert mget.call_args.kwargs["timeout"] == nvd._TIMEOUT_S

    def test_limit_flows_into_results_per_page(self, make_response):
        cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            nvd.cves_for_cpe(cpe, limit=2)
        assert mget.call_args.kwargs["params"]["resultsPerPage"] == 2

    def test_empty_cpe_short_circuits(self):
        with patch("tools.nvd.http.get") as mget:
            assert nvd.cves_for_cpe("") == []
        mget.assert_not_called()

    def test_keyword_and_cpe_caches_are_distinct(self, make_response):
        # Same string queried two ways must not collide in the cache.
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            nvd.cves_for_keyword("openssh")
            nvd.cves_for_cpe("openssh")
        assert mget.call_count == 2

    def test_distinct_cpes_do_not_collide_in_cache(self, make_response):
        first = _cve_body({"id": "CVE-1111-0001"})
        second = _cve_body({"id": "CVE-2222-0002"})
        with patch(
            "tools.nvd.http.get",
            side_effect=[make_response(json=first), make_response(json=second)],
        ) as mget:
            r1 = nvd.cves_for_cpe("cpe:2.3:a:x:one:1:*:*:*:*:*:*:*")
            r2 = nvd.cves_for_cpe("cpe:2.3:a:x:two:2:*:*:*:*:*:*:*")
        assert mget.call_count == 2
        assert r1[0].id == "CVE-1111-0001"
        assert r2[0].id == "CVE-2222-0002"


class TestSearchCpes:
    def test_returns_cpe_names(self, make_response):
        with patch("tools.nvd.http.get", return_value=make_response(json=_cpe_payload())) as mget:
            names = nvd.search_cpes("apache http server")
        assert names == [
            "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        ]
        # CPE search hits the CPE endpoint with keywordSearch
        assert mget.call_args.args[0].endswith("/cpes/2.0")
        assert mget.call_args.kwargs["params"]["keywordSearch"] == "apache http server"

    def test_request_targets_cpe_endpoint_with_headers_page_size_and_timeout(self, make_response):
        # The CPE path builds its own http.get call (not via _get_cves), so its
        # header/page-size/timeout wiring is pinned independently. No API key is
        # configured in the test env, so headers is the empty dict _headers()
        # returns - asserting it (not just "present") kills a headers=None drop.
        with patch("tools.nvd.http.get", return_value=make_response(json=_cpe_payload())) as mget:
            nvd.search_cpes("apache")
        assert mget.call_args.args == (nvd._CPE_API_URL,)
        assert mget.call_args.kwargs["params"]["resultsPerPage"] == 10
        assert mget.call_args.kwargs["headers"] == {}
        assert mget.call_args.kwargs["timeout"] == nvd._TIMEOUT_S

    def test_limit_flows_into_results_per_page(self, make_response):
        with patch("tools.nvd.http.get", return_value=make_response(json=_cpe_payload())) as mget:
            nvd.search_cpes("apache", limit=4)
        assert mget.call_args.kwargs["params"]["resultsPerPage"] == 4

    def test_empty_query_short_circuits(self):
        with patch("tools.nvd.http.get") as mget:
            assert nvd.search_cpes("") == []
        mget.assert_not_called()

    def test_network_error_degrades_to_empty(self):
        with patch("tools.nvd.http.get", side_effect=Exception("boom")):
            assert nvd.search_cpes("nginx") == []

    def test_result_is_cached_second_call_no_request(self, make_response):
        with patch("tools.nvd.http.get", return_value=make_response(json=_cpe_payload())) as mget:
            first = nvd.search_cpes("apache")
            second = nvd.search_cpes("apache")
        assert first == second
        assert mget.call_count == 1

    def test_distinct_keywords_do_not_collide_in_cache(self, make_response):
        first = {"products": [{"cpe": {"cpeName": "cpe:2.3:a:x:one:1:*:*:*:*:*:*:*"}}]}
        second = {"products": [{"cpe": {"cpeName": "cpe:2.3:a:x:two:2:*:*:*:*:*:*:*"}}]}
        with patch(
            "tools.nvd.http.get",
            side_effect=[make_response(json=first), make_response(json=second)],
        ) as mget:
            r1 = nvd.search_cpes("one")
            r2 = nvd.search_cpes("two")
        assert mget.call_count == 2
        assert r1 == ["cpe:2.3:a:x:one:1:*:*:*:*:*:*:*"]
        assert r2 == ["cpe:2.3:a:x:two:2:*:*:*:*:*:*:*"]

    def test_missing_products_key_returns_and_caches_empty(self, make_response):
        with patch("tools.nvd.http.get", return_value=make_response(json={})) as mget:
            first = nvd.search_cpes("nothing")
            second = nvd.search_cpes("nothing")
        assert first == []
        assert second == []
        assert mget.call_count == 1

    def test_skips_products_without_cpe_key_keeping_valid_ones(self, make_response):
        # A product row lacking a "cpe" object degrades to no name (the {} default
        # feeds a .get that yields None, excluded by the walrus guard); the valid
        # row still produces its canonical name rather than the batch collapsing.
        body = {
            "products": [
                {"cpe": {"cpeName": "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"}},
                {"no_cpe": 1},
            ]
        }
        with patch("tools.nvd.http.get", return_value=make_response(json=body)):
            names = nvd.search_cpes("apache")
        assert names == ["cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"]


class TestApiKeyHeader:
    def test_sends_api_key_header_when_configured(self, monkeypatch, make_response):
        monkeypatch.setattr("tools.nvd.config.scan.nvd_api_key", "test-key-123")
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            nvd.cves_for_keyword("xss")
        assert mget.call_args.kwargs["headers"]["apiKey"] == "test-key-123"

    def test_no_header_when_key_absent(self, monkeypatch, make_response):
        monkeypatch.setattr("tools.nvd.config.scan.nvd_api_key", None)
        with patch("tools.nvd.http.get", return_value=make_response(json=_cve_payload())) as mget:
            nvd.cves_for_keyword("xss")
        assert "apiKey" not in mget.call_args.kwargs["headers"]
