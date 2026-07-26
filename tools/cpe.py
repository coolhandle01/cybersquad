"""
tools/cpe.py - CPE (Common Platform Enumeration) parsing + normalisation.

CPE is NIST's standardised product-identity naming scheme (part of SCAP):
a structured ``cpe:2.3:<part>:<vendor>:<product>:<version>:...`` string that
keys directly into the NVD's CVE applicability data. It is the high-confidence
join from "what is running on this host" to "what is it vulnerable to" - the
counterpart to the looser ``name[:version]`` wappalyzer string httpx emits.

This module is the single coercion point for the two CPE bindings cybersquad
meets in the wild:

* nmap ``-sV`` emits the legacy **CPE 2.2 URI binding**
  (``cpe:/a:openbsd:openssh:7.4``) as ``<cpe>`` children of each ``<service>``.
* the NVD - and any hand-written reference - speaks the current **CPE 2.3
  formatted string** (``cpe:2.3:a:...:*:*:*:*:*:*:*``).

``normalize_cpe`` parses either binding (via the ``cpe`` library) and returns
the canonical 2.3 formatted string, so everything downstream - the typed
``cpe`` field on recon assets, the VR's CVE lookup - speaks one binding.

CPE strings arrive from external tool output (untrusted): a value the parser
cannot make sense of degrades to ``None`` rather than raising, matching the
defensive posture of the recon parsers that call in here.
"""

from __future__ import annotations

from cpe import CPE

from models.asset import Product, ProductRelease

# A CPE 2.3 formatted string tops out well under this; a longer value is junk
# or an injection riding in on a banner, not a CPE. Mirrors the ``max_length``
# cap on the typed ``cpe`` fields that store the normalised result.
_MAX_CPE_LEN = 255


def normalize_cpe(raw: str | None) -> str | None:
    """Parse a CPE in any binding and return its CPE 2.3 formatted string.

    Accepts the 2.2 URI binding nmap emits (``cpe:/a:vendor:product:version``)
    or an already-2.3 formatted string, and returns the canonical 2.3 form
    (``cpe:2.3:<part>:<vendor>:<product>:<version>:*:*:*:*:*:*:*``).

    Returns ``None`` for empty / over-long / unparseable input - CPE values
    come from external tool output, so a malformed one degrades quietly.
    """
    if not raw or not isinstance(raw, str):
        return None
    candidate = raw.strip()
    if not candidate or len(candidate) > _MAX_CPE_LEN:
        return None
    try:
        return str(CPE(candidate).as_fs())
    except (ValueError, NotImplementedError):
        # ``cpe`` raises NotImplementedError for an unrecognised binding and
        # ValueError for a structurally invalid one; both mean "not a CPE".
        return None


def pick_application_cpe(raws: list[str]) -> str | None:
    """Choose the single most relevant CPE from a service's ``<cpe>`` list.

    An nmap ``<service>`` can carry several CPEs - typically the application
    (``cpe:2.3:a:...``) plus the host OS (``cpe:2.3:o:...``). For a service
    asset the *application* CPE is the one that keys CVEs for the listening
    software, so prefer it; fall back to the first parseable CPE (e.g. an
    OS-only row) when no application CPE is present. ``None`` when nothing
    in the list parses.
    """
    normalized = [n for raw in raws if (n := normalize_cpe(raw))]
    if not normalized:
        return None
    for n in normalized:
        if n.startswith("cpe:2.3:a:"):
            return n
    return normalized[0]


def _first_component(values: list[str]) -> str:
    """First concrete value from a CPE component list (wildcards -> '')."""
    for value in values:
        cleaned = (value or "").strip()
        if cleaned and cleaned not in {"*", "-"}:
            return cleaned
    return ""


def product_release_from_cpe(cpe_fs: str) -> tuple[Product, ProductRelease] | None:
    """Decompose a CPE 2.3 string into OAM ``Product`` + ``ProductRelease``.

    ``cpe:2.3:a:nginx:nginx:1.25.3:*:...`` -> ``Product(name="nginx")`` +
    ``ProductRelease(name="nginx 1.25.3")``. The product name is the CVE-lookup
    key; the release name pins the exact version a ``VulnProperty`` hangs off.

    Returns ``None`` when the CPE names no usable product (a wildcard / OS-only
    row), matching the defensive posture of ``normalize_cpe`` - the input is
    external tool output, so an unusable value degrades quietly rather than
    raising.
    """
    try:
        parsed = CPE(cpe_fs)
    except (ValueError, NotImplementedError):
        return None
    product = _first_component(parsed.get_product())
    if not product:
        return None
    version = _first_component(parsed.get_version())
    release_name = f"{product} {version}".strip() if version else product
    return Product(name=product), ProductRelease(name=release_name)


__all__ = ["normalize_cpe", "pick_application_cpe", "product_release_from_cpe"]
