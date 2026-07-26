"""tests/tools/cloud/test_azure.py - unit tests for tools/cloud/azure.py.

Azure Blob container listing checks and the static SAS-token URL
inspection. As with S3, the hostnames are ones OSINT already surfaced;
the SAS check fires no HTTP at all (pure URL inspection).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from models import Endpoint, Severity
from tools.cloud.azure import check_azure_blob_containers, check_azure_sas_tokens

pytestmark = pytest.mark.unit


class TestCheckAzureBlobContainers:
    """The agent picks Azure Blob hostnames OSINT actually surfaced in
    recon; the canonical container-name list (``public``, ``assets``,
    ``static``, ...) is probed against each."""

    def test_detects_publicly_listed_container(self, azure_blob_hostname, make_response):
        listing_xml = '<?xml version="1.0"?><EnumerationResults><Blobs/></EnumerationResults>'
        with patch("requests.get", return_value=make_response(status=200, body=listing_xml)):
            results = check_azure_blob_containers([azure_blob_hostname])

        listed = [r for r in results if "Publicly Listed" in r.title]
        assert len(listed) >= 1
        assert listed[0].severity_hint == Severity.HIGH

    def test_empty_input_makes_no_requests(self):
        with patch("requests.get") as mget:
            results = check_azure_blob_containers([])

        assert results == []
        mget.assert_not_called()

    def test_probes_every_supplied_hostname(self, make_azure_blob_hostname, make_response):
        seen_urls: list[str] = []

        def recording_get(url, **kwargs):
            seen_urls.append(url)
            return make_response(status=403, body="Denied")

        hostnames = [make_azure_blob_hostname("storage"), make_azure_blob_hostname("assets")]
        with patch("requests.get", side_effect=recording_get):
            check_azure_blob_containers(hostnames)

        for hostname in hostnames:
            assert any(hostname in u for u in seen_urls)

    def test_network_exception_is_swallowed(self, azure_blob_hostname):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_azure_blob_containers([azure_blob_hostname])
        assert results == []


class TestCheckAzureSasTokens:
    """Static URL inspection - no HTTP requests fire."""

    def test_detects_sas_token_in_endpoint_url(self, azure_sas_endpoint):
        with patch("requests.get") as mget:
            results = check_azure_sas_tokens([azure_sas_endpoint])

        sas_findings = [r for r in results if "SAS Token" in r.title]
        assert len(sas_findings) == 1
        assert sas_findings[0].severity_hint == Severity.HIGH
        # Static URL inspection: never fires HTTP.
        mget.assert_not_called()

    def test_clean_urls_produce_no_findings(self, target_url):
        endpoint = Endpoint(url=f"{target_url}/files/doc.pdf?download=1", status_code=200)

        with patch("requests.get") as mget:
            results = check_azure_sas_tokens([endpoint])

        assert results == []
        mget.assert_not_called()

    def test_empty_input_makes_no_requests(self):
        with patch("requests.get") as mget:
            results = check_azure_sas_tokens([])

        assert results == []
        mget.assert_not_called()
