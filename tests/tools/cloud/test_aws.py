"""tests/tools/cloud/test_aws.py - unit tests for tools/cloud/aws.py.

S3 bucket exposure checks. The agent only probes S3 hostnames OSINT
actually surfaced in recon - no bucket-name guessing - so the fixtures
hand in already-discovered hostnames.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from models import Severity
from tools.cloud.aws import check_s3_buckets

pytestmark = pytest.mark.unit


class TestCheckS3Buckets:
    """The agent picks S3 hostnames OSINT actually surfaced in recon;
    no bucket-name guessing - we only probe assets the programme has
    exposed."""

    def test_detects_publicly_listable_bucket(self, s3_hostname, make_response):
        listing_xml = '<?xml version="1.0"?><ListBucketResult></ListBucketResult>'
        with patch("requests.get", return_value=make_response(status=200, body=listing_xml)):
            results = check_s3_buckets([s3_hostname])

        listable = [r for r in results if "Publicly Listable" in r.title]
        assert len(listable) == 1
        assert listable[0].severity_hint == Severity.HIGH
        assert listable[0].vuln_class == "CloudMisconfiguration"
        assert listable[0].target == f"https://{s3_hostname}/"

    def test_detects_publicly_accessible_bucket(self, make_s3_hostname, make_response):
        with patch(
            "requests.get",
            return_value=make_response(status=200, body="some non-listing content"),
        ):
            results = check_s3_buckets([make_s3_hostname()])

        accessible = [r for r in results if "Publicly Accessible" in r.title]
        assert len(accessible) == 1
        assert accessible[0].severity_hint == Severity.MEDIUM

    def test_listable_finding_fields_and_call_args(self, s3_hostname, make_response):
        # Long, listing-bearing body: pins the evidence excerpt (and its
        # [:500] truncation boundary) and every other finding field, plus
        # the outbound call args (URL / timeout / allow_redirects).
        body = "<ListBucketResult>" + "x" * 600
        calls: list[tuple[str, dict]] = []

        def recording_get(url, **kwargs):
            calls.append((url, kwargs))
            return make_response(status=200, body=body)

        with patch("requests.get", side_effect=recording_get):
            results = check_s3_buckets([s3_hostname])

        assert len(calls) == 1
        url, kwargs = calls[0]
        assert url == f"https://{s3_hostname}/"
        assert kwargs["timeout"] == 10
        assert kwargs["allow_redirects"] is False

        listable = [r for r in results if "Publicly Listable" in r.title]
        assert len(listable) == 1
        f = listable[0]
        assert f.title == f"S3 Bucket Publicly Listable - {s3_hostname}"
        assert f.target == f"https://{s3_hostname}/"
        assert f.vuln_class == "CloudMisconfiguration"
        assert f.tool == "s3_bucket_check"
        assert f.severity_hint == Severity.HIGH
        assert f.evidence == (f"Bucket listing returned HTTP 200.\nResponse excerpt:\n{body[:500]}")

    def test_accessible_finding_fields(self, s3_hostname, make_response):
        with patch("requests.get", return_value=make_response(status=200, body="plain page")):
            results = check_s3_buckets([s3_hostname])

        accessible = [r for r in results if "Publicly Accessible" in r.title]
        assert len(accessible) == 1
        f = accessible[0]
        assert f.title == f"S3 Bucket Publicly Accessible - {s3_hostname}"
        assert f.target == f"https://{s3_hostname}/"
        assert f.vuln_class == "CloudMisconfiguration"
        assert f.tool == "s3_bucket_check"
        assert f.severity_hint == Severity.MEDIUM
        assert f.evidence == "Bucket URL returned HTTP 200 without listing - verify manually."

    def test_probe_continues_after_a_host_errors(self, make_s3_hostname, make_response):
        # A per-host failure must not abandon the remaining hostnames: the
        # loop continues past the exception rather than breaking out.
        bad = make_s3_hostname("broken")
        good = make_s3_hostname("open")

        def flaky_get(url, **kwargs):
            if bad in url:
                raise Exception("connection reset")
            return make_response(status=200, body="<ListBucketResult>listing</ListBucketResult>")

        with patch("requests.get", side_effect=flaky_get):
            results = check_s3_buckets([bad, good])

        assert [r.target for r in results] == [f"https://{good}/"]

    def test_non_200_produces_no_finding(self, s3_hostname, make_response):
        with patch("requests.get", return_value=make_response(status=403, body="Access Denied")):
            results = check_s3_buckets([s3_hostname])

        assert results == []

    def test_empty_input_makes_no_requests(self):
        with patch("requests.get") as mget:
            results = check_s3_buckets([])

        assert results == []
        mget.assert_not_called()

    def test_iterates_every_supplied_hostname(self, make_s3_hostname, make_response):
        seen_urls: list[str] = []

        def recording_get(url, **kwargs):
            seen_urls.append(url)
            return make_response(status=403, body="Denied")

        hostnames = [make_s3_hostname("assets"), make_s3_hostname("backup")]
        with patch("requests.get", side_effect=recording_get):
            check_s3_buckets(hostnames)

        for hostname in hostnames:
            assert any(hostname in u for u in seen_urls)

    def test_network_exception_is_swallowed(self, s3_hostname):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_s3_buckets([s3_hostname])
        assert results == []
