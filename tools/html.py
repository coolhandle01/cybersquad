"""HTML fetch-and-parse helper.

Wraps http.get and returns a (Response, BeautifulSoup) pair so call sites
do not repeat the two-step get + parse pattern. Only parses when the response
Content-Type is text/html; returns an empty soup otherwise.
"""

from __future__ import annotations

import requests
from bs4 import BeautifulSoup

from tools import http


def fetch(url: str, **kwargs: object) -> tuple[requests.Response, BeautifulSoup]:
    """GET url and parse the response body as HTML.

    Use this instead of calling http.get + BeautifulSoup separately.
    Pass any http.get kwargs (timeout, allow_redirects, headers, etc.) through.

    Returns a (response, soup) pair. soup is empty when the Content-Type is
    not text/html - callers can treat an empty soup as a skip condition rather
    than checking the header themselves.
    """
    resp = http.get(url, **kwargs)  # type: ignore[arg-type]
    ct = resp.headers.get("Content-Type", "")
    body = resp.text if "text/html" in ct else ""
    return resp, BeautifulSoup(body, "html.parser")
