"""
Network-tier URL / redirect abuse - SSRF (the wrapper makes the
server fetch an internal address on the attacker's behalf) and Open
Redirect (the wrapper bounces user traffic to an attacker-chosen
host).
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad.penetration_tester.tools._decorator import _parse_endpoints, pentest_tool
from tools.pentest.open_redirect import OpenRedirectPayload, check_open_redirect
from tools.pentest.ssrf import SsrfPayload, check_ssrf
from tools.recon.scope import TargetEndpoints


class _SsrfArgs(BaseModel):
    """Explicit args_schema for the SSRF Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects whose parameters plausibly accept URLs,"
            " hostnames, file paths, or resource identifiers (url=, path=,"
            " file=, redirect=, src=). Skip endpoints without parameters."
        ),
    )
    payloads: list[SsrfPayload] | None = Field(
        default=None,
        description=(
            "Optional list of internal-address variants to try; omit or pass"
            " null to try all. Pass ['aws-imds'] for an AWS-hosted target,"
            " ['localhost-ipv4'] / ['localhost-ipv6'] for internal-service"
            " reachability."
        ),
    )


@pentest_tool("SSRF Probe", check_fn=check_ssrf, args_schema=_SsrfArgs)
def ssrf_probe_tool(
    endpoints: list[Endpoint],
    payloads: list[SsrfPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject cloud metadata (169.254.169.254) and loopback (127.0.0.1) payloads
    into URL parameters to detect Server-Side Request Forgery.

    endpoints: list of endpoint objects. Only pass endpoints that have
      parameters AND where those parameters plausibly accept URLs, hostnames,
      file paths, or resource identifiers (e.g. url=, path=, file=, redirect=, src=).
      Example: [{"url": "https://example.com/fetch", "parameters": ["url"]}]

    payloads: optional list of internal-address variants to try; omit or pass
      null to try all. Useful for stealth or when the cloud provider is known
      (e.g. just "aws-imds" for an AWS-hosted target).


    """
    return list(check_ssrf(_parse_endpoints(endpoints), payloads))


class _OpenRedirectArgs(BaseModel):
    """Explicit args_schema for the Open Redirect Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects. Prioritise redirect-shaped"
            " parameter names (redirect, redirect_uri, return, return_to,"
            " returnto, next, url, dest, destination, goto, target, link,"
            " forward, continue, callback, rurl, r, u) and auth-flow paths"
            " (/login, /logout, /signin, /oauth, /sso)."
        ),
    )
    payloads: list[OpenRedirectPayload] | None = Field(
        default=None,
        description=(
            "Optional list of redirect encoding variants to try; omit or pass null to try all."
        ),
    )


@pentest_tool(
    "Open Redirect Probe",
    check_fn=check_open_redirect,
    args_schema=_OpenRedirectArgs,
)
def open_redirect_tool(
    endpoints: list[Endpoint],
    payloads: list[OpenRedirectPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject external URL payloads (https, protocol-relative, backslash, userinfo)
    into URL parameters and check whether the response Location, Refresh header,
    or meta-refresh tag points to the canary host.

    endpoints: list of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Parameter names look redirect-shaped (redirect, redirect_uri, return,
        return_to, returnto, next, url, dest, destination, goto, target, link,
        forward, continue, callback, rurl, r, u)
      - Path looks like an auth flow (/login, /logout, /signin, /oauth, /sso)
      - Recon noted a 30x response on the endpoint already
      Example: [{"url": "https://example.com/login", "parameters": ["next"]}]

    payloads: optional list of encoding variants to try; omit or pass null to
      try all.

    Open redirect on its own is typically MEDIUM, but it escalates on OAuth
    redirect_uri and SSO callback endpoints (token theft) - flag those for VR.

    """
    return list(check_open_redirect(_parse_endpoints(endpoints), payloads))
