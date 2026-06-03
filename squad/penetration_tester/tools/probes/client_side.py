"""
Client-side / reflective probes - payloads that get echoed back to
the user's browser (reflected XSS, header-driven XSS, path-traversal
into client-visible content). The vulnerability lives in the response
the server sends back, not in code executing on the server.
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad.penetration_tester.tools._decorator import _parse_endpoints, pentest_tool
from tools.pentest.header_xss import XSSHeader, check_header_xss
from tools.pentest.path_traversal import PathTraversalPayload, check_path_traversal
from tools.pentest.xss import check_reflected_xss
from tools.recon.scope import TargetEndpoints


class _HeaderXssArgs(BaseModel):
    """Explicit args_schema for the Header XSS Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Live HTML-serving endpoint objects. Error pages and admin paths"
            " are especially fruitful - they tend to echo request metadata"
            " into the response body."
        ),
    )
    header_names: list[XSSHeader] | None = Field(
        default=None,
        description=(
            "Optional list of headers to probe; omit or pass null to test all"
            " five. Narrow when recon evidence points to a specific header"
            " (e.g. ['User-Agent', 'Referer'])."
        ),
    )


@pentest_tool("Header XSS Probe", check_fn=check_header_xss, args_schema=_HeaderXssArgs)
def header_xss_tool(
    endpoints: list[Endpoint],
    header_names: list[XSSHeader] | None = None,
) -> list[RawFinding]:
    """
    Inject an angle-bracket canary into request headers and check whether the
    response body contains the canary verbatim (unencoded).

    Unencoded reflection confirms the application echoes raw header values into
    HTML output without sanitisation, which is sufficient evidence of a Header
    XSS vulnerability (H1 weakness: Improper Neutralization of HTTP Headers for
    Scripting Syntax).

    Use when:
      - The target renders content server-side (templates, SSR, admin dashboards)
      - Error pages are verbose and likely to echo request metadata
      - Recon found analytics or logging endpoints that display User-Agent strings
      - The target is an older web application (PHP, JSP, ASP) with legacy templating

    endpoints: list of endpoint objects. Pass a broad set of live
      HTML-serving endpoints; error pages and admin paths are especially fruitful.
      Example: [{"url": "https://example.com/error", "status_code": 404}]

    header_names: optional list of headers to probe; omit or pass null to test
      all five. Narrow this when recon evidence points to a specific header
      (e.g. error pages that echo the User-Agent, analytics that log Referer).
      Example: ["User-Agent", "Referer"]


    """
    return list(check_header_xss(_parse_endpoints(endpoints), header_names))


class _PathTraversalArgs(BaseModel):
    """Explicit args_schema for the Path Traversal Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects. Prioritise filesystem-shaped"
            " parameter names (file, filename, path, page, template, include,"
            " require, download, doc, image, img, src, view) and paths that"
            " suggest file serving (/download, /view, /preview, /fetch,"
            " /report, /export)."
        ),
    )
    payloads: list[PathTraversalPayload] | None = Field(
        default=None,
        description=(
            "Optional list of traversal encoding variants to try; omit or"
            " pass null to try all. When the target OS is known, pass only"
            " the matching set (e.g. ['unix-basic', 'unix-encoded'] for"
            " Linux)."
        ),
    )


@pentest_tool(
    "Path Traversal Probe",
    check_fn=check_path_traversal,
    args_schema=_PathTraversalArgs,
)
def path_traversal_tool(
    endpoints: list[Endpoint],
    payloads: list[PathTraversalPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject directory-traversal payloads (plain, URL-encoded, double-encoded,
    backslash for Windows, null-byte truncation) into URL parameters and look
    for unique content markers from OS sentinel files (/etc/passwd,
    Windows win.ini) in the response body.

    endpoints: list of endpoint objects. Prioritise endpoints that
      have parameters AND where any of the following apply:
      - Parameter names look filesystem-shaped (file, filename, path, page,
        template, include, require, download, doc, image, img, src, view)
      - URL path or query suggests file serving (/download, /view, /preview,
        /fetch, /report, /export)
      - The response Content-Type or filename hint shows the server is reading
        files based on the parameter
      Example: [{"url": "https://example.com/download", "parameters": ["file"]}]

    payloads: optional list of traversal variants to try; omit or pass null
      to try all. When the OS is known, pass only the matching set (e.g. just
      "unix-basic" and "unix-encoded" for a Linux target).

    Read-only sentinel paths only; no writes, no destructive payloads. A
    confirmed match returns severity HIGH - traversal that yields /etc/passwd
    or win.ini almost always implies a file-read primitive worth escalating.

    """
    return list(check_path_traversal(_parse_endpoints(endpoints), payloads))


class _XssArgs(BaseModel):
    """Explicit args_schema for the Reflected XSS Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects. Pass only endpoints whose"
            " response is HTML (the target renders user input back into a"
            " page) rather than JSON or a redirect."
        ),
    )


@pentest_tool(
    "Reflected XSS Probe",
    check_fn=check_reflected_xss,
    args_schema=_XssArgs,
)
def xss_probe_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Inject an angle-bracket canary into URL parameters and check for unescaped
    reflection in the response body.

    endpoints: list of endpoint objects. Only pass endpoints that have
      parameters AND where the response is HTML (i.e. the target renders user input
      back into a page rather than returning JSON or a redirect).
      Example: [{"url": "https://example.com/search", "parameters": ["q"]}]


    """
    return list(check_reflected_xss(_parse_endpoints(endpoints)))
