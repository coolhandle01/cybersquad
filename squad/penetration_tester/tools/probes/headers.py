"""
HTTP-shape and parameter-handling misconfiguration probes - checks
that target what the server does with cookies, CORS preflight, CSRF
tokens, header values, and parameter parsing rather than executing
injected payloads on a downstream interpreter.
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad.penetration_tester.tools._decorator import (
    _parse_endpoints,
    _recon_from_path,
    pentest_tool,
)
from tools.pentest.cookies import check_cookies
from tools.pentest.cors import check_cors_misconfiguration
from tools.pentest.csrf import check_csrf
from tools.pentest.hpp import check_hpp
from tools.pentest.webapp_headers import check_header_injection, check_host_headers
from tools.recon.scope import TargetEndpoints


class _CookieCheckArgs(BaseModel):
    """Explicit args_schema for the Cookie Security Check tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Cookies are"
            " inspected across every host the OSINT Analyst recorded."
        ),
    )


@pentest_tool("Cookie Security Check", check_fn=check_cookies, args_schema=_CookieCheckArgs)
def cookie_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Inspect Set-Cookie attributes across the recon surface for: missing
    Secure on HTTPS cookies, missing HttpOnly on session-shaped cookies,
    SameSite=None without Secure, Domain attribute scoped broader than the
    setting host, persistent (Max-Age/Expires) session-shaped cookies, and
    sensitive data (API keys, JWTs carrying password/secret claims, emails,
    base64-encoded JSON with sensitive keys) in cookie values.

    Run this broadly - one request per distinct host, findings deduped per
    (host, cookie name, check class). Especially useful on login, dashboard,
    and authenticated API endpoints where Set-Cookie is most likely.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_cookies(recon.endpoints))


class _CorsCheckArgs(BaseModel):
    """Explicit args_schema for the CORS Misconfiguration Check tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. CORS"
            " misconfigurations are probed against every live endpoint."
        ),
    )


@pentest_tool(
    "CORS Misconfiguration Check",
    check_fn=check_cors_misconfiguration,
    args_schema=_CorsCheckArgs,
)
def cors_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Check all live endpoints for CORS misconfigurations: origin reflection,
    null origin acceptance, and overly permissive Access-Control-Allow-Origin headers.
    Relevant wherever the target exposes an API or serves authenticated content.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_cors_misconfiguration(recon.endpoints))


class _CsrfCheckArgs(BaseModel):
    """Explicit args_schema for the CSRF Detection tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. CSRF probes"
            " run against every HTML endpoint with a POST form."
        ),
    )


@pentest_tool("CSRF Detection", check_fn=check_csrf, args_schema=_CsrfCheckArgs)
def csrf_check_tool(recon_path: str) -> list[RawFinding]:
    """
    Detect CSRF vulnerabilities across HTML endpoints in the recon surface.

    Tier 1 (MEDIUM): fetches each HTML endpoint and checks for page-level
    CSRF protection before inspecting forms.  When the response sets a
    CSRF-pattern cookie (Angular XSRF-TOKEN, Django csrftoken, Tornado _xsrf)
    or the HTML contains a <meta name="csrf-token"> tag (Rails, Spring), the
    missing-input finding is suppressed - those frameworks protect POSTs via JS
    without hidden form inputs.  For other pages, any POST form with no hidden
    input matching a CSRF token name pattern is flagged.

    Tier 2 (HIGH): POSTs to the form action with an evil Origin header and
    with the correct Origin.  Runs against every endpoint with a POST form,
    including those where Tier 1 was suppressed, because per-view bypasses
    (Django @csrf_exempt, Rails skip_before_action, Spring csrf().disable(),
    Laravel $except) mean a page-level cookie or meta tag cannot be trusted
    to cover every route.  When Tier 2 fires on a page-protected endpoint the
    evidence names the likely bypass pattern so the agent can report it
    accurately.

    Run broadly against all HTML-serving endpoints; especially relevant on
    login, registration, account management, and any state-changing form.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_csrf(recon.endpoints))


class _HeaderInjectionArgs(BaseModel):
    """Explicit args_schema for the Header Injection Check tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. CRLF probes"
            " run broadly against every endpoint."
        ),
    )


@pentest_tool(
    "Header Injection Check",
    check_fn=check_header_injection,
    args_schema=_HeaderInjectionArgs,
)
def header_injection_tool(recon_path: str) -> list[RawFinding]:
    """
    Check for CRLF injection via X-Forwarded-For and similar headers.
    Relevant on all endpoints - run this broadly.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_header_injection(recon.endpoints))


class _HostHeaderArgs(BaseModel):
    """Explicit args_schema for the Host Header Attack Check tool."""

    recon_path: str = Field(
        description=(
            "Relative path to recon.json in the run directory. Host-header"
            " reflection and X-Original-URL / X-Rewrite-URL overrides are"
            " probed across every endpoint."
        ),
    )


@pentest_tool(
    "Host Header Attack Check",
    check_fn=check_host_headers,
    args_schema=_HostHeaderArgs,
)
def host_header_tool(recon_path: str) -> list[RawFinding]:
    """
    Test for Host header reflection (cache poisoning, password-reset poisoning)
    and X-Original-URL / X-Rewrite-URL overrides that may bypass access controls.
    Pass the path to the recon.json file in the run directory.
    """
    recon = _recon_from_path(recon_path)
    return list(check_host_headers(recon.endpoints))


class _HppArgs(BaseModel):
    """Explicit args_schema for the HTTP Parameter Pollution Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects. Prioritise authorisation-shaped"
            " parameter names (role, admin, is_admin, permission, group,"
            " user_id), WAF-fronted endpoints, and auth or admin flows -"
            " HPP is highest-impact as a WAF bypass or privilege flip"
            " primitive."
        ),
    )


@pentest_tool(
    "HTTP Parameter Pollution Probe",
    check_fn=check_hpp,
    args_schema=_HppArgs,
)
def hpp_probe_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Detect HTTP Parameter Pollution by sending a baseline request
    (`?param=1`) and a polluted request (`?param=1&param=2`) and comparing
    status code + body length. A status-code change confirms alone; a
    body-length change confirms only once it exceeds the bytes the duplicated
    parameter itself adds (so a page that merely echoes its query string is not
    flagged). A confirmed divergence means the server treats duplicate values
    as distinguishable from a single value - the pre-condition for WAF bypass
    and access-control bypass exploits.

    endpoints: list of endpoint objects. Prioritise endpoints
      where any of the following apply:
      - Parameter names look authorisation-shaped (role, admin, is_admin,
        permission, group, user_id) - HPP is most impactful when it can
        flip a privilege check
      - Endpoint sits behind a WAF or rate-limit (HPP is a classic WAF
        bypass primitive)
      - Endpoint is part of an auth or admin flow
      Example: [{"url": "https://example.com/api/user", "parameters": ["role", "id"]}]

    Severity LOW on its own - HPP is a class of behaviour that enables
    further exploitation rather than a vuln in itself. The VR should
    escalate when the divergence can be chained with another finding
    (SQLi filter bypass, access-control override, cache poisoning).

    """
    return list(check_hpp(_parse_endpoints(endpoints)))
