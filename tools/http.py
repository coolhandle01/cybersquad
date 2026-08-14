"""HTTP wrappers that inject a traceable User-Agent on every outbound request.

Every tool that makes HTTP requests should call into this module rather than
``requests`` directly. The module-level wrappers (``get``, ``post``, etc.)
delegate to ``requests.<verb>`` underneath, so existing tests that patch
``requests.get`` continue to intercept calls without modification.

The User-Agent is built from operator config (platform, H1 username, contact
email) plus the in-flight programme handle read from ``runtime.programme_handle``.
A SOC operator seeing this UA can verify the H1 username and programme handle
against their HackerOne dashboard and use the contact email to reach the
operator without having to ban the IP first. See issue #46.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from requests.structures import CaseInsensitiveDict

import runtime
from config import config

# Identifies the platform the squad operates against. Hardcoded for now;
# move to config when a second platform is supported.
_PLATFORM = "hackerone"


def user_agent() -> str:
    """Build the current User-Agent string from operator + workspace context.

    User-Agent header semantics are defined in RFC 9110 section 10.1.5
    (https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5). The
    structured "<product>; <key>: <value>; ..." shape below is a deliberate
    departure from the typical product-token convention: every field a SOC
    operator needs to identify the request, the programme, and the operator
    is parseable from the value without correlating to external metadata.
    """
    parts = [f"platform: {_PLATFORM}"]
    handle = runtime.programme_handle
    if handle:
        parts.append(f"programme: {handle}")
    parts.append(f"researcher: {config.h1.api_username}")
    parts.append(f"contact: {config.contact_email}")
    return f"cybersquad (authorised research; {'; '.join(parts)})"


def _inject_headers(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Merge our User-Agent into the caller's headers dict.

    The merged value is a ``requests.structures.CaseInsensitiveDict``
    (https://requests.readthedocs.io/en/latest/api/#requests.structures.CaseInsensitiveDict
    - source at https://github.com/psf/requests/blob/main/src/requests/structures.py).
    Setting ``"User-Agent"`` and ``"user-agent"`` on a plain ``dict``
    produces two entries; HTTP header semantics treat field names as
    case-insensitive (RFC 9110 section 5.1) so the second send wins
    silently. ``CaseInsensitiveDict`` dedupes by lower-cased key, so
    the safe default never accidentally ships duplicate headers.

    A header-mutation probe that NEEDS to send literal duplicate
    headers (HTTP request smuggling, header-injection / CRLF probes,
    duplicate-Host attacks) deliberately works around this safe
    default - that is the explicit override, auditable as such in the
    probe's source. The unsafe pattern to avoid (and the reason this
    helper exists rather than letting callers build headers raw):

        # unsafe - silent dedupe by send order; the second wins
        headers = {"User-Agent": "ours", "user-agent": "theirs"}

    A caller-supplied User-Agent wins (test fixtures occasionally pin
    one); the default for every request is our traceable UA.
    """
    headers: CaseInsensitiveDict[str] = CaseInsensitiveDict(kwargs.get("headers") or {})
    if "User-Agent" not in headers:
        headers["User-Agent"] = user_agent()
    kwargs["headers"] = headers
    return kwargs


# Pass-through wrappers. Each delegates to requests.<verb> so existing test
# patches against ``requests.get`` and friends continue to intercept calls
# without modification. Timeout is an explicit parameter so callers cannot
# accidentally omit it; the configured default applies when omitted.


def request(method: str, url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.request(method, url, timeout=_timeout, **_inject_headers(kwargs))


def get(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.get(url, timeout=_timeout, **_inject_headers(kwargs))


def post(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.post(url, timeout=_timeout, **_inject_headers(kwargs))


def put(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.put(url, timeout=_timeout, **_inject_headers(kwargs))


def delete(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.delete(url, timeout=_timeout, **_inject_headers(kwargs))


def head(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.head(url, timeout=_timeout, **_inject_headers(kwargs))


def patch(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.patch(url, timeout=_timeout, **_inject_headers(kwargs))


def options(url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
    _timeout = config.recon.http_timeout if timeout is None else timeout
    return requests.options(url, timeout=_timeout, **_inject_headers(kwargs))


def inject_query_param(url: str, name: str, value: str) -> str:
    """Splice ``name=value`` into ``url``'s query string so the *server* receives it.

    A probe that injects a payload into a URL query has two ways to build a
    silently-broken request, and this helper closes both. It is the single
    shared implementation the injection probes call rather than assembling a
    query with an f-string; keep the safety in one place so every probe
    inherits it.

    URL query-component grammar is RFC 3986 section 3.4
    (https://www.rfc-editor.org/rfc/rfc3986.html#section-3.4); percent-encoding
    is section 2.1.

    **A second ``?`` never registers the parameter.** The naive
    ``f"{url}?{name}={value}"`` produces ``...?a=1?name=value`` when ``url``
    already carries a query string. There is only one query component - it
    begins at the first ``?`` and runs to the end (or the fragment) - so the
    literal second ``?`` and everything after it is read as part of the
    *previous* parameter's value. The injected parameter never appears as its
    own key, the probe's payload never reaches the server as a parameter, and
    the probe reports nothing on exactly the endpoints most worth probing (the
    ones that already take parameters). This helper splits the URL with
    ``urlsplit``, and when a query is already present it joins the new pair on
    with ``&`` - the query-component separator - never a second ``?``.

    **Query-significant bytes must survive to the server.** A raw payload
    containing query metacharacters is mangled in transit unless it is
    percent-encoded: ``#`` opens the fragment (the payload after it is dropped
    before the request is even sent), ``&`` starts the next parameter
    (truncating the value), ``+`` decodes to a space under
    ``application/x-www-form-urlencoded``, and ``;`` / space / ``( ) *`` are
    likewise reserved or delimiting in practice. ``name`` and ``value`` are
    percent-encoded with ``quote(..., safe="")`` - an empty ``safe`` so even
    ``/`` is encoded - so each of these bytes reaches the server as the literal
    character the payload intended, not as query structure.

    The function is pure: it reads ``url``/``name``/``value`` and returns a new
    URL string, issuing no request and mutating nothing. Appending a parameter
    whose name already occurs is intentional and preserved - both pairs survive
    in order (e.g. an HPP probe adding a second ``p=2`` to an existing ``p=1``
    yields ``...?p=1&p=2``), because the query is spliced textually rather than
    merged into a dict that would collapse the duplicate.

    Args:
        url: The target URL, with or without an existing query string. Any
            fragment is preserved and the parameter is placed in the query
            component ahead of it.
        name: The parameter name to inject. Percent-encoded before splicing.
        value: The parameter value to inject. Percent-encoded before splicing,
            so query-significant bytes reach the server intact.

    Returns:
        ``url`` with ``name=value`` appended to its query component - joined
        with ``&`` when a query already exists, introduced with ``?`` when it
        did not.
    """
    pair = f"{quote(name, safe='')}={quote(value, safe='')}"
    parts = urlsplit(url)
    query = f"{parts.query}&{pair}" if parts.query else pair
    return urlunsplit(parts._replace(query=query))
