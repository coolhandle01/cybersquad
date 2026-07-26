"""
Cloud-storage exposure probes:

- ``S3 Bucket Check`` - ``list[FQDN]`` of ``*.s3.*.amazonaws.com``
  hostnames; probes each for public listing.
- ``Azure Blob Container Check`` - ``list[FQDN]`` of
  ``*.blob.core.windows.net`` hostnames; probes each for publicly
  listable containers under the canonical Azure-pattern names.
- ``Azure SAS Token Check`` - ``list[Endpoint]``; static URL inspection
  for embedded SAS query parameters (no HTTP).

Each wrapper carries a single ``scope_filter`` so out-of-scope targets
reject at the wrapper boundary before any HTTP request fires.
"""

from pydantic import BaseModel, Field

from models import FQDN, Endpoint, RawFinding
from squad import cyber_tool
from squad.penetration_tester.tools._decorator import _parse_endpoints
from tools.cloud.aws import check_s3_buckets
from tools.cloud.azure import check_azure_blob_containers, check_azure_sas_tokens
from tools.recon.scope import TargetEndpoints, TargetFQDNs


class _S3CheckArgs(BaseModel):
    """Explicit args_schema for the S3 Bucket Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "S3 hostnames the OSINT Analyst surfaced in recon.subdomains"
            " (matching ``*.s3.*.amazonaws.com``) or via cert"
            " transparency / historical URLs. Probes each for public"
            " listing (``<ListBucketResult``) or bare 200. The wrapper's"
            " scope filter drops out-of-scope hostnames before any HTTP"
            " request."
        ),
    )


@cyber_tool("S3 Bucket Check", args_schema=_S3CheckArgs)
def s3_check_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check each supplied S3 hostname for public listing or accessibility.

    Pick hostnames from Recon Subdomains where the entry matches
    ``*.s3.*.amazonaws.com``, or from Recon Endpoints whose host fits
    that pattern. The wrapper scope-filters the list against the
    selected programme; the body probes whatever survives.
    """
    return list(check_s3_buckets(hostnames))


class _AzureBlobContainerArgs(BaseModel):
    """Explicit args_schema for the Azure Blob Container Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "Azure Blob hostnames the OSINT Analyst surfaced in"
            " recon.subdomains (matching ``*.blob.core.windows.net``)."
            " Probes each for publicly listable containers under the"
            " canonical Azure-pattern names (``public``, ``assets``,"
            " ``static``, ``uploads``, ...). The wrapper's scope filter"
            " drops out-of-scope hostnames before any HTTP request."
        ),
    )


@cyber_tool("Azure Blob Container Check", args_schema=_AzureBlobContainerArgs)
def azure_blob_container_check_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check each supplied Azure Blob hostname for publicly listable
    containers under the canonical Azure-pattern names.

    Pick hostnames from Recon Subdomains where the entry matches
    ``*.blob.core.windows.net``. The wrapper scope-filters the list
    against the selected programme; the body probes whatever survives.
    """
    return list(check_azure_blob_containers(hostnames))


class _AzureSasTokenArgs(BaseModel):
    """Explicit args_schema for the Azure SAS Token Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Scans each URL for embedded Azure SAS"
            " token query parameters (sv / se / sig / sr / sp). Static"
            " URL inspection - no HTTP requests fire. Run broadly on"
            " all live endpoints; SAS tokens in URLs leak via proxy"
            " logs and browser history. The wrapper's scope filter"
            " drops endpoints whose host is outside the selected"
            " programme's structured scope."
        ),
    )


@cyber_tool("Azure SAS Token Check", args_schema=_AzureSasTokenArgs)
def azure_sas_token_check_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Scan each supplied endpoint URL for embedded Azure SAS-token query
    parameters (``sv`` / ``se`` / ``sig`` / ``sr`` / ``sp``). No HTTP
    requests fire - this is static URL inspection.

    Pick a representative set of live endpoints from Recon Endpoints.
    The wrapper scope-filters the list against the selected programme.
    """
    return list(check_azure_sas_tokens(_parse_endpoints(endpoints)))
