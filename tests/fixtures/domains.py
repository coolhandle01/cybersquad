"""Domain / URL / hostname fixtures.

The single knob for retargeting the suite is ``target_url``; every
other in-scope fixture (``target_apex``, ``target_sld``, the cloud-
storage hostname factories, the scope items, the programme) derives
from it. Flip ``target_url`` and the chain follows.

``bystander_url`` is the canonical out-of-scope host; tests that
exercise the scope guard take this fixture so the intent
("bystander, hands off") is readable at the call site.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def target_url() -> str:
    return "https://victim.example.com"


@pytest.fixture()
def bystander_url() -> str:
    return "https://bystander.example.org"


@pytest.fixture()
def callback_url() -> str:
    """OOB receiver placeholder until #77 lands real interactsh infrastructure."""
    return "https://callback.cybersquad.com"


@pytest.fixture()
def target_apex(target_url: str) -> str:
    """Apex domain derived from ``target_url``.

    Every fixture that builds an in-scope ScopeItem, hostname, or URL
    derives from this rather than embedding the apex literal. Flipping
    ``target_url`` (e.g. to point the suite at DVWA on localhost)
    propagates through every dependent fixture - no per-fixture
    hardcoded ``example.com`` left to chase.
    """
    from urllib.parse import urlparse

    host = urlparse(target_url).hostname or ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


@pytest.fixture()
def target_sld(target_apex: str) -> str:
    """Second-level-domain prefix of ``target_apex`` (``example`` from
    ``example.com``). Cloud bucket / account names take this rather
    than the full apex - DNS labels in a bucket name cannot contain
    the apex's dot, so the bare SLD is what carries cleanly into
    ``<sld>-assets.s3...`` / ``<sld>storage.blob...``."""
    return target_apex.split(".")[0]


@pytest.fixture()
def make_html_page(target_url: str):
    """Factory for minimal HTML pages containing script tags.

    Returns a callable: make_html_page(scripts=[...]) -> str.
    Defaults to a single <script> pointing at {target_url}/app.js.
    """

    def _make(scripts: list[str] | None = None) -> str:
        _scripts = scripts if scripts is not None else [f"{target_url}/app.js"]
        tags = "".join(f'<script src="{s}"></script>' for s in _scripts)
        return f"<html><head>{tags}</head></html>"

    return _make
