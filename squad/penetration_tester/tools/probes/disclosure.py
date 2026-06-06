"""
Information-disclosure probes - look for what the application has
leaked (JS source maps, missing Subresource Integrity, stack traces
in error responses) rather than for injection points.
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad.penetration_tester.tools._decorator import (
    _parse_endpoints,
    _recon_from_path,
    pentest_tool,
)
from tools.pentest.errors import check_error_disclosure
from tools.pentest.sourcemaps import check_js_source_maps
from tools.pentest.sri import check_sri
from tools.recon.scope import TargetEndpoints


class _SourceMapsArgs(BaseModel):
    """Explicit args_schema for the JS Source Map Scan tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Exposed"
            " .js.map files are discovered across every HTML page that"
            " loads JavaScript bundles."
        ),
    )


@pentest_tool(
    "JS Source Map Scan",
    check_fn=check_js_source_maps,
    args_schema=_SourceMapsArgs,
)
def source_maps_tool(recon_path: str) -> list[RawFinding]:
    """
    Discover exposed .js.map source map files and scan reconstructed source for
    secrets and internal paths. Use when the recon surface includes HTML pages
    that load JavaScript bundles (React, Angular, Vue, etc.).
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_js_source_maps(recon.endpoints))


class _SriCheckArgs(BaseModel):
    """Explicit args_schema for the Subresource Integrity Check tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. SRI gaps are"
            " scanned across every HTML-serving endpoint."
        ),
    )


@pentest_tool(
    "Subresource Integrity Check",
    check_fn=check_sri,
    args_schema=_SriCheckArgs,
)
def sri_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Scan HTML pages for cross-origin <script> and <link> tags missing an
    integrity= attribute. Run broadly against all HTML-serving endpoints.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_sri(recon.endpoints))


class _ErrorDisclosureArgs(BaseModel):
    """Explicit args_schema for the Error and Stack Trace Disclosure Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects to probe with error-triggering inputs."
            " Prioritise parameterised endpoints (parameters increase the"
            " chance of triggering an error) and any endpoint where passive"
            " error-disclosure findings already suggest verbose errors."
        ),
    )


@pentest_tool(
    "Error and Stack Trace Disclosure Check",
    check_fn=check_error_disclosure,
    args_schema=_ErrorDisclosureArgs,
)
def error_disclosure_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Probe endpoints with error-triggering inputs and scan responses for framework
    stack traces and SQL error messages.

    endpoints: list of endpoint objects to probe. Prioritise endpoints
      where parameters are present (they increase the chance of triggering errors)
      and any endpoint where the error disclosure passive findings from recon suggest
      verbose errors are already present.
      Example: [{"url": "https://example.com/api/user", "parameters": ["id"]}]


    """
    return list(check_error_disclosure(_parse_endpoints(endpoints)))
