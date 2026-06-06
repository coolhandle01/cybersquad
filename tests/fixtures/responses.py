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


@pytest.fixture
def make_response():
    """Factory for building MagicMock objects shaped like requests.Response.

    Use this instead of local _resp/_mock_resp helpers in individual test files.
    Tool-specific builders that carry extra logic stay local - the cookie-aware
    _resp in test_cookies.py (exposes ``.raw.headers.getlist`` for multiple
    Set-Cookie headers) and the POST-context _post_resp in test_csrf.py
    (intended naming convenience for ``requests.post`` return-value mocks).
    """

    def _make(
        status: int = 200,
        body: str = "",
        headers: dict | None = None,
        cookies: dict | None = None,
        json: object = None,
    ) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.text = body
        resp.headers = headers or {}
        resp.cookies = cookies or {}
        if json is not None:
            resp.json.return_value = json
        return resp

    return _make


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
