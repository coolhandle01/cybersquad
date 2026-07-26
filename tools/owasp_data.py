"""
tools/owasp_data.py - local OWASP Cheat Sheet catalogue.

The Cheat Sheet Series at https://cheatsheetseries.owasp.org publishes
canonical mitigation guidance keyed by URL slug. The Technical Author cites
these in the Remediation section of every disclosure; this module is the
single source of truth for those slugs and a short summary so the agent does
not have to remember (or worse, hallucinate) URLs.

Entries are looked up by case-insensitive substring match against the topic
slug or title. The CWE catalogue cross-references this module via
``owasp_topic`` so a CWE lookup hands the agent the matching cheat-sheet URL
in one hop.
"""

from __future__ import annotations

# OWASPEntry lives in models/owasp.py per the typed-shapes-live-in-
# models rule. Re-exported here so existing ``from tools.owasp_data
# import OWASPEntry`` consumers keep working; the canonical import
# path is ``from models import OWASPEntry``.
from models.owasp import OWASPEntry

# Curated subset of the OWASP Cheat Sheet Series covering the vuln_class
# strings cybersquad emits. The "key_principles" entries are deliberately
# short so the TA can paste them verbatim into a Remediation section without
# rewriting.
OWASP_CATALOGUE: list[OWASPEntry] = [
    OWASPEntry(
        topic="Authentication",
        title="Authentication",
        key_principles=[
            "Reject weak passwords and require multi-factor authentication for "
            "privileged accounts.",
            "Bind session identifiers to the authenticated user and rotate them on "
            "privilege change.",
        ],
    ),
    OWASPEntry(
        topic="Authorization",
        title="Authorization",
        key_principles=[
            "Enforce authorization on every request server-side; never trust "
            "client-supplied role or owner identifiers.",
            "Default deny: explicitly grant access rather than removing it.",
        ],
    ),
    OWASPEntry(
        topic="Clickjacking_Defense",
        title="Clickjacking Defense",
        key_principles=[
            "Send `Content-Security-Policy: frame-ancestors 'self'` (or specific "
            "origins) on every authenticated response.",
            "Set the `X-Frame-Options: DENY` header for legacy browser support.",
        ],
    ),
    OWASPEntry(
        topic="Cross_Site_Scripting_Prevention",
        title="Cross-Site Scripting Prevention",
        key_principles=[
            "Context-aware output encoding: HTML body, attribute, JavaScript, URL, "
            "and CSS contexts each need a different escape function.",
            "Use a strict Content-Security-Policy with nonces or hashes for inline scripts.",
        ],
        aliases=["xss"],
    ),
    OWASPEntry(
        topic="Cross-Site_Request_Forgery_Prevention",
        title="Cross-Site Request Forgery Prevention",
        key_principles=[
            "Use the synchronizer-token or double-submit cookie pattern on every "
            "state-changing request.",
            "Set session cookies with `SameSite=Lax` (or `Strict` where compatible).",
        ],
        aliases=["csrf"],
    ),
    OWASPEntry(
        topic="Error_Handling",
        title="Error Handling",
        key_principles=[
            "Return generic error pages to users; log full diagnostic detail "
            "server-side keyed by a request id.",
            "Disable framework debug pages in production builds.",
        ],
    ),
    OWASPEntry(
        topic="File_Upload",
        title="File Upload",
        key_principles=[
            "Validate file type by content (magic bytes) and reject anything "
            "outside the allow-list.",
            "Store uploads outside the web root and serve them through a handler "
            "that sets `Content-Disposition: attachment`.",
        ],
    ),
    OWASPEntry(
        topic="HTML5_Security",
        title="HTML5 Security",
        key_principles=[
            "Restrict CORS to a known allow-list of origins; never reflect "
            "`Origin` into `Access-Control-Allow-Origin` with credentials.",
            "Use postMessage with strict origin checks.",
        ],
        aliases=["cors", "postmessage"],
    ),
    OWASPEntry(
        topic="Input_Validation",
        title="Input Validation",
        key_principles=[
            "Validate against an allow-list of expected values; reject everything "
            "else at the trust boundary.",
            "Validate type, length, format, and range before any further processing.",
        ],
    ),
    OWASPEntry(
        topic="Injection_Prevention_in_Java",
        title="Injection Prevention (NoSQL & GraphQL)",
        key_principles=[
            "Use parameterised query APIs; never concatenate user input into a query string.",
            "For NoSQL drivers, ensure operators in user input are escaped or "
            "rejected (e.g. `$where`, `$ne`).",
        ],
        aliases=["nosql", "nosqli", "graphql"],
    ),
    OWASPEntry(
        topic="LDAP_Injection_Prevention",
        title="LDAP Injection Prevention",
        key_principles=[
            "Escape every special character (`*`, `(`, `)`, `\\`, NUL) in user "
            "input before composing an LDAP filter.",
            "Bind to LDAP with the lowest privilege account that can satisfy the query.",
        ],
    ),
    OWASPEntry(
        topic="OS_Command_Injection_Defense",
        title="OS Command Injection Defense",
        key_principles=[
            "Avoid invoking the shell: pass arguments as an array to `execve`-style APIs.",
            "Validate against a strict allow-list of expected values.",
        ],
    ),
    OWASPEntry(
        topic="Secrets_Management",
        title="Secrets Management",
        key_principles=[
            "Store credentials in a managed secret store (Vault, KMS); never in "
            "source control or environment variables on a shared host.",
            "Rotate any secret that has been exposed in logs or repositories.",
        ],
    ),
    OWASPEntry(
        topic="Server_Side_Request_Forgery_Prevention",
        title="Server-Side Request Forgery Prevention",
        key_principles=[
            "Validate URLs against an allow-list of expected hosts; resolve and "
            "compare the IP, not just the hostname.",
            "Block private and link-local IP ranges (RFC 1918, 169.254.0.0/16) "
            "at the egress proxy.",
        ],
        aliases=["ssrf"],
    ),
    OWASPEntry(
        topic="Server_Side_Template_Injection_Prevention",
        title="Server-Side Template Injection Prevention",
        key_principles=[
            "Never render user-controlled data as a template; pass it as a "
            "context variable into a pre-defined template.",
            "Sandbox the template engine to disable filesystem and process primitives.",
        ],
        aliases=["ssti"],
    ),
    OWASPEntry(
        topic="SQL_Injection_Prevention",
        title="SQL Injection Prevention",
        key_principles=[
            "Use parameterised queries (prepared statements) for every SQL operation.",
            "Avoid dynamic SQL string concatenation; if unavoidable, use an "
            "allow-list escape routine specific to the database engine.",
        ],
        aliases=["sqli"],
    ),
    OWASPEntry(
        topic="Third_Party_Javascript_Management",
        title="Third Party Javascript Management",
        key_principles=[
            "Include `integrity` and `crossorigin` attributes on every external "
            "script tag (Subresource Integrity).",
            "Vendor critical third-party scripts and serve them from your own origin under SRI.",
        ],
    ),
    OWASPEntry(
        topic="Transport_Layer_Security",
        title="Transport Layer Security",
        key_principles=[
            "Disable TLS 1.0/1.1 and SSLv2/v3; require TLS 1.2 or newer.",
            "Set `Strict-Transport-Security` with a long `max-age` and `includeSubDomains`.",
        ],
    ),
    OWASPEntry(
        topic="Unvalidated_Redirects_and_Forwards",
        title="Unvalidated Redirects and Forwards",
        key_principles=[
            "Validate the redirect target against an allow-list of known destinations.",
            "Prefer indirect redirects: accept a token that maps server-side to the real URL.",
        ],
        aliases=["open redirect", "openredirect"],
    ),
    OWASPEntry(
        topic="XML_External_Entity_Prevention",
        title="XML External Entity Prevention",
        key_principles=[
            "Disable external entity resolution in every XML parser the "
            "application uses (`DOCTYPE`, `ENTITY`).",
            "Where possible, switch to a non-XML data format (JSON).",
        ],
        aliases=["xxe"],
    ),
    OWASPEntry(
        topic="JSON_Web_Token_for_Java",
        title="JSON Web Token (JWT) Security",
        key_principles=[
            "Reject tokens with `alg: none` or unexpected algorithms; pin the "
            "expected algorithm server-side.",
            "Validate `iss`, `aud`, and `exp` on every request.",
        ],
        aliases=["jwt"],
    ),
    OWASPEntry(
        topic="LLM_Top_10",
        title="OWASP Top 10 for LLM Applications",
        key_principles=[
            "Treat all model output as untrusted input downstream; do not embed "
            "it directly in shell or SQL.",
            "Separate system, developer, and user prompt channels; deny the "
            "model authority to modify its own system prompt.",
        ],
    ),
]


_BY_TOPIC: dict[str, OWASPEntry] = {e.topic: e for e in OWASP_CATALOGUE}


def get_by_topic(topic: str) -> OWASPEntry | None:
    """Return the catalogue entry for ``topic`` (the slug) or None."""
    return _BY_TOPIC.get(topic)


def lookup(query: str, limit: int = 5) -> list[OWASPEntry]:
    """Return cheat-sheet entries whose topic, title, or aliases match
    ``query`` case-insensitively. Returns up to ``limit`` entries, exact
    matches first."""
    if not query:
        return []
    needle = query.strip().lower()

    exact: list[OWASPEntry] = []
    substring: list[OWASPEntry] = []
    for entry in OWASP_CATALOGUE:
        haystack = [entry.topic.lower(), entry.title.lower(), *(a.lower() for a in entry.aliases)]
        if any(h == needle for h in haystack):
            exact.append(entry)
        elif any(needle in h for h in haystack):
            substring.append(entry)
    return (exact + substring)[:limit]
