"""
models/owasp.py - typed OWASP catalogue shapes.

``OWASPCategory`` is the 2021 Top 10 enum the squad uses for the
``@owasp(...)`` decorator stamp on pentest probes. Lives here (not in
``tools/pentest/owasp.py``) so the typed stamp reader
``tools/pentest/_stamps.py`` and ``models/framework.py`` can import it
without the package-level circular-import trap that
``from tools.pentest.owasp`` triggers (loading ``tools/pentest/__init__.py``
which imports a dozen probe modules, each of which imports ``models``).

``OWASPEntry`` is the typed shape for a single OWASP Cheat Sheet
row. The Cheat Sheet catalogue data and the substring-match lookup
live in ``tools/owasp_data.py``; this module is the row contract
consumers import to type-check return shapes against.

Canonical reference for the Top 10: https://owasp.org/Top10/2021/.
The A01..A10 codes and the ``<code>:2021 - <Title>`` string format
encoded in OWASPCategory members track the landing page above.
Per-category pages live at .../Top10/2021/A01_2021-Broken_Access_Control/
and equivalents; do not reword the enum values when a tool's category
shifts - add the new edition's enum members and migrate references.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, computed_field

_BASE_URL = "https://cheatsheetseries.owasp.org/cheatsheets"


class OWASPCategory(StrEnum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_SOFTWARE_DATA_INTEGRITY = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"


class OWASPEntry(BaseModel):
    """A single OWASP Cheat Sheet entry."""

    topic: str  # canonical slug, used to build URL
    title: str
    key_principles: list[str]
    aliases: list[str] = []  # short keywords the TA may use to find this sheet

    # Exposed as a computed_field rather than a plain @property so it appears
    # in model_dump output - the @tool wrapper returns list[OWASPEntry] direct
    # and the agent sees the cheatsheetseries.owasp.org URL it cites.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        return f"{_BASE_URL}/{self.topic}_Cheat_Sheet.html"


__all__ = ["OWASPCategory", "OWASPEntry"]
