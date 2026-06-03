"""
models.primitives.http_url - the ``HttpUrl`` typed-string primitive.

URL-shape validation delegated to ``pydantic.HttpUrl``; the host component
runs through ``fqdn._validate_fqdn`` so RFC 1123 strictness holds inside URLs
too (the one intra-package edge in ``models.primitives``).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator

from models.primitives.fqdn import _validate_fqdn

# ``HttpUrl`` - URL validation delegated to Pydantic's built-in
# ``pydantic.HttpUrl`` (the canonical RFC-3986 parser); runtime type
# stays ``str`` so every call site that does
# ``endpoint.url.startswith(...)`` / ``.lower()`` / ``urlparse(ep.url)``
# / f-string interpolation keeps working with no audit tax.
#
# Pydantic's HttpUrl reference:
# https://docs.pydantic.dev/2.12/api/networks/#pydantic.networks.HttpUrl
#
# Deliberate departure from upstream: ``pydantic.HttpUrl``'s runtime
# type is ``Url`` (a wrapper exposing ``.host`` / ``.scheme`` / ``.port``
# properties), not ``str``. We keep the ``str`` runtime intentionally:
# the structured accessors are mostly cosmetic wins, and migrating
# would force ``str(ep.url)`` at every f-string / dict-key / comparison
# site (~50 across ``tools/pentest/*``) plus a cascade through
# ``RawFinding.target`` and siblings. Cite: #163 closed as not-planned.


def _validate_endpoint_url(value: str) -> str:
    """Validate that ``value`` is a parseable HTTP / HTTPS URL.

    URL shape (scheme / authority / RFC-3986 well-formedness) delegates
    to ``pydantic.HttpUrl``; the host component then runs through
    ``_validate_fqdn`` so RFC 1123 hostname strictness (no leading
    hyphens, no oversized labels) holds inside URLs too. The FQDN
    primitive guards "the LLM handed us a URL when we asked for a
    hostname" - the same RFC 1123 contract should hold when a hostname
    is wrapped in a URL, otherwise ``-evil.example.com`` rejects but
    ``https://-evil.example.com`` doesn't, giving the LLM a trivial
    bypass. Defense-in-depth, not belt-and-braces.

    Keeps the input as ``str`` so every downstream consumer that uses
    string methods on ``ep.url`` keeps working; see the module
    docstring above for why the ``str`` runtime is intentional.

    One workaround sits in front of the upstream call: stdlib
    ``urlparse`` reports an empty netloc for ``https:///path``, but
    Pydantic interprets the same input as ``https://path/`` (treats
    the path segment as the host). That LLM-facing contract should
    reject the empty-authority case rather than silently probe a host
    called "path".
    """
    from urllib.parse import urlparse

    from pydantic import HttpUrl as _PydanticHttpUrl

    if not isinstance(value, str):  # pragma: no cover - Pydantic enforces str upstream
        raise ValueError(f"url must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("url cannot be empty")
    if not urlparse(cleaned).netloc:
        raise ValueError(f"url must include an authority component: {value!r}")
    # Pydantic raises ``ValidationError`` on RFC-3986 violations; the
    # AfterValidator chain propagates it to the calling model as a
    # field-level error.
    parsed = _PydanticHttpUrl(cleaned)
    if parsed.host:
        _validate_fqdn(parsed.host)
    return cleaned


HttpUrl = Annotated[str, AfterValidator(_validate_endpoint_url)]
