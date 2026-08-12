"""HTTP-response fixtures.

``make_response`` is the canonical mock-Response factory - use it
instead of hand-rolling ``MagicMock(); resp.status_code = ...; resp.text
= ...`` at every probe test. ``clean_response_body`` is an HTML body
verified at setup time to contain no pentest probe marker; use it for
"nothing of interest in the response" cases so an unlucky literal
does not trip an unrelated probe's detection.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests
from requests.structures import CaseInsensitiveDict


@pytest.fixture
def make_response():
    """Factory for building MagicMock objects shaped like requests.Response.

    Use this instead of local _resp/_mock_resp helpers in individual test files.
    Tool-specific builders that carry extra logic stay local - the cookie-aware
    _resp in test_cookies.py (exposes ``.raw.headers.getlist`` for multiple
    Set-Cookie headers) and the POST-context _post_resp in test_csrf.py
    (intended naming convenience for ``requests.post`` return-value mocks).

    The mock is ``spec``'d to ``requests.Response`` (reading an attribute the
    real Response lacks raises ``AttributeError`` rather than returning a
    truthy mock), and ``headers`` is a case-insensitive ``CaseInsensitiveDict``
    as it is in production.

    ``raise_for_status()`` is status-aware: a ``status`` of 400 or above wires
    it to raise ``requests.HTTPError`` (carrying ``.response``), and anything
    below is a no-op - matching a real ``requests.Response``. Pass the error
    ``status`` and let the fixture raise; do not hand-wire
    ``resp.raise_for_status.side_effect`` (that makes ``status`` decorative).
    """

    def _make(
        status: int = 200,
        body: str = "",
        headers: dict | None = None,
        cookies: dict | None = None,
        json: object = None,
        url: str = "https://mock.invalid/",
    ) -> MagicMock:
        # spec=requests.Response so a read of an attribute the real Response
        # does not have (a production typo like `resp.stauts_code`, or an
        # attribute lost in a refactor) raises AttributeError instead of
        # returning a truthy child mock that sails a broken test through -
        # the structural form of the same faithfulness the raise_for_status
        # wiring gives by enumeration. spec (not spec_set) still permits
        # assignment, so `resp.json.return_value = ...` below and the
        # `.raw.headers.getlist` locals keep working - json and raw are both
        # real Response members.
        resp = MagicMock(spec=requests.Response)
        resp.status_code = status
        resp.text = body
        # Response headers are case-insensitive in production; a plain dict
        # here would let a test set {"Content-Type": ...} pass against a line
        # reading headers.get("content-type") in the fixture but fail live.
        resp.headers = CaseInsensitiveDict(headers or {})
        resp.cookies = cookies or {}
        # ``resp.url`` is a real string by default so ``urljoin(resp.url, ...)``
        # in Webpage form-action resolution does not trip on the MagicMock
        # auto-attribute. Tests that need a specific page URL pass ``url=``.
        resp.url = url
        if json is not None:
            resp.json.return_value = json
        # Faithful to requests.Response.raise_for_status(): raise HTTPError
        # for 4xx/5xx, no-op for anything below 400. This makes `status`
        # load-bearing for any code that gates on raise_for_status() - the
        # scope-guard equivalent for HTTP-error handling - instead of leaving
        # every author to hand-wire the side_effect (making `status` decorative)
        # or, worse, silently not exercising the guard at all because the bare
        # MagicMock never raises. The message mirrors requests' own
        # "<code> Client Error" / "<code> Server Error" split, and the error
        # carries `.response` so `except HTTPError as e: e.response...` works.
        if status >= 400:
            kind = "Client Error" if status < 500 else "Server Error"
            resp.raise_for_status.side_effect = requests.HTTPError(
                f"{status} {kind}", response=resp
            )
        else:
            resp.raise_for_status.return_value = None
        return resp

    return _make


@pytest.fixture()
def imds_metadata_body() -> str:
    """A fabricated-but-realistic AWS instance-metadata listing - the body a
    server vulnerable to SSRF echoes back when coerced into fetching
    ``http://169.254.169.254/latest/meta-data/``.

    Fabricated, never gathered: this is the real *shape* of the ``/latest/
    meta-data/`` key listing (many canonical keys on their own lines) with no
    real host contacted. Used by the SSRF tests so detection is exercised
    against genuine metadata rather than a bare marker literal.
    """
    return (
        "ami-id\n"
        "ami-launch-index\n"
        "ami-manifest-path\n"
        "block-device-mapping/\n"
        "hostname\n"
        "iam/\n"
        "instance-action\n"
        "instance-id\n"
        "instance-type\n"
        "local-hostname\n"
        "local-ipv4\n"
        "mac\n"
        "placement/\n"
        "public-hostname\n"
        "public-ipv4\n"
        "reservation-id\n"
        "security-groups\n"
    )


@pytest.fixture()
def clean_response_body() -> str:
    """An HTML response body verified to contain none of the strings any
    pentest probe uses as a positive detection marker. Use this for tests
    that need a generic 'nothing of interest in the response' body.

    These exist so tests for "no finding" cases don't accidentally
    include a string that one of the pentest probes uses as a positive
    detection marker. We caught one of those (an SSRF test where the
    body "not metadata" tripped the "metadata" marker); the assertion
    below catches the next one at setup time instead of at assertion
    time.
    """
    body = "<html><body><h1>Hello</h1><p>Welcome.</p></body></html>"

    from tools.pentest.cmd_injection import _CANARY as _CMD_CANARY
    from tools.pentest.ldap_injection import _LDAP_ERROR_MARKERS
    from tools.pentest.path_traversal import _PROBES as _PATH_PROBES
    from tools.pentest.prompt_injection import (
        _CANARY as _PROMPT_CANARY,
    )
    from tools.pentest.prompt_injection import (
        _SYSTEM_PROMPT_MARKERS,
    )
    from tools.pentest.prototype_pollution import _CANARY as _PP_CANARY
    from tools.pentest.ssrf import _SSRF_MARKERS
    from tools.pentest.ssti import _EXPECTED as _SSTI_EXPECTED
    from tools.pentest.xxe import _LINUX_MARKER, _WIN_MARKER, _XML_ERROR_MARKERS

    forbidden: list[str] = [
        _CMD_CANARY,
        _PROMPT_CANARY,
        _PP_CANARY,
        _LINUX_MARKER,
        _WIN_MARKER,
        _SSTI_EXPECTED,
        *_SSRF_MARKERS,
        *_LDAP_ERROR_MARKERS,
        *_XML_ERROR_MARKERS,
        *_SYSTEM_PROMPT_MARKERS,
        *(marker for _payload, marker in _PATH_PROBES.values()),
    ]

    for marker in forbidden:
        assert marker not in body, (
            f"clean_response_body fixture contains pentest marker {marker!r}; "
            "rewrite the body so no probe would treat it as a finding."
        )

    return body
