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
