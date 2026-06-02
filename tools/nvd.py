"""
tools/nvd.py - low-level NVD (NIST National Vulnerability Database) REST client.

Two NVD REST APIs, JSON over HTTPS - the structured CVE / CPE data the
Vulnerability Researcher's triage reasons against:

* **CVE API 2.0** (``/rest/json/cves/2.0``) - the vulnerabilities. Queried by
  free-text keyword (``cves_for_keyword``) or by an exact CPE 2.3 name
  (``cves_for_cpe`` - the nmap-CPE -> CVEs path).
* **CPE API 2.0** (``/rest/json/cpes/2.0``) - the product dictionary. Queried
  by keyword (``search_cpes``) to resolve a product name to its canonical
  CPE 2.3 string.

NVD rate-limits hard: 5 requests / 30s without an API key, 50 with. The key is
read from ``config.scan.nvd_api_key`` (``NVD_API_KEY``) and sent as the
``apiKey`` header when set. Read fresh per call so an operator can rotate it
without a restart.

Every lookup degrades to an empty result on any error - a throttle, network
blip, or rough-shaped response never blocks the pipeline. Results are cached
in-process (keyed by query) so repeated lookups within a run do not re-hit the
rate-limited API; ``clear_cache()`` resets it (tests, long-lived processes).

References:
* CVE API 2.0: https://nvd.nist.gov/developers/vulnerabilities
* CPE API 2.0: https://nvd.nist.gov/developers/products
"""

from __future__ import annotations

import logging
from typing import Any

from config import config
from models import CVE
from models.nvd.cve import DESCRIPTION_MAX_LENGTH
from tools import http

logger = logging.getLogger(__name__)

_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# NVD's per-request timeout - the API is occasionally slow under load, and a
# throttled request can sit in a queue, so we allow more than the default
# recon HTTP timeout before giving up (and degrading to empty).
_TIMEOUT_S = 30

# In-process result cache, keyed by ``(endpoint-kind, query)``. Value is the
# parsed result list. Recon / triage runs share one cache for the process
# lifetime; ``clear_cache()`` resets it. Mirrors ``rdap._bootstrap_cache``.
_RESULT_CACHE: dict[tuple[str, str], list[Any]] = {}


def clear_cache() -> None:
    """Drop the in-process NVD result cache."""
    _RESULT_CACHE.clear()


def _headers() -> dict[str, str]:
    """Auth header for the NVD APIs. Read the key fresh so rotation works."""
    key = config.scan.nvd_api_key
    return {"apiKey": key} if key else {}


def _parse_cve(cve: dict[str, Any]) -> CVE:
    """Map one NVD ``cve`` object to a typed ``CVE``.

    Prefers the richest CVSS metric available (v3.1 > v3.0 > v2) and the
    English description. Missing pieces degrade to ``None`` / ``""`` - a CVE
    with no scored metric is still a real CVE worth surfacing.
    """
    metrics = cve.get("metrics", {})
    cvss_score: float | None = None
    cvss_vector: str | None = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            cvss_score = data.get("baseScore")
            cvss_vector = data.get("vectorString")
            break
    descriptions = [d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"]
    # Truncate to the model's boundary cap here rather than let an over-long
    # NVD description reject the CVE in ``CVE(...)`` - a rejection would be
    # swallowed by ``_get_cves`` and drop the whole batch, not just this row.
    description = (descriptions[0] if descriptions else "")[:DESCRIPTION_MAX_LENGTH]
    return CVE(
        id=cve.get("id", ""),
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        description=description,
        cwe_ids=_parse_cwe_ids(cve.get("weaknesses", [])),
    )


def _parse_cwe_ids(weaknesses: list[dict[str, Any]]) -> list[int]:
    """Extract the numeric CWE ids NVD attributes to a CVE (its ``weaknesses``).

    Each weakness carries ``description`` entries like ``{"value": "CWE-89"}``;
    NVD also emits non-numeric placeholders (``NVD-CWE-noinfo`` /
    ``NVD-CWE-Other``) which are dropped. Returns de-duplicated ids in first-seen
    order so the authoritative CPE -> CVE -> CWE link is preserved verbatim.
    """
    ids: list[int] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description", []):
            value = desc.get("value", "") if isinstance(desc, dict) else ""
            prefix, _, suffix = value.partition("-")
            if prefix == "CWE" and suffix.isdigit():
                cwe_id = int(suffix)
                if cwe_id not in ids:
                    ids.append(cwe_id)
    return ids


def _get_cves(params: dict[str, str | int], cache_key: tuple[str, str]) -> list[CVE]:
    """Shared CVE-API fetch + parse + cache. Degrades to ``[]`` on any error."""
    if cache_key in _RESULT_CACHE:
        return list(_RESULT_CACHE[cache_key])
    try:
        resp = http.get(_CVE_API_URL, params=params, headers=_headers(), timeout=_TIMEOUT_S)
        resp.raise_for_status()
        results = [
            _parse_cve(vuln["cve"])
            for vuln in resp.json().get("vulnerabilities", [])
            if isinstance(vuln, dict) and isinstance(vuln.get("cve"), dict)
        ]
    except Exception as exc:
        logger.warning("NVD CVE lookup failed for %s: %s", cache_key, exc)
        return []
    _RESULT_CACHE[cache_key] = results
    return list(results)


def cves_for_keyword(keyword: str, limit: int = 5) -> list[CVE]:
    """Search the NVD for CVEs matching a free-text keyword.

    The keyword path: broad, noisy, good for "what is known-bad about this
    technology class". Returns up to ``limit`` typed ``CVE`` rows; ``[]``
    on empty input or any error.
    """
    if not keyword.strip():
        return []
    params: dict[str, str | int] = {"keywordSearch": keyword, "resultsPerPage": limit}
    return _get_cves(params, ("cve:keyword", keyword))


def cves_for_cpe(cpe: str, limit: int = 5) -> list[CVE]:
    """Look up the CVEs that apply to an exact CPE 2.3 name.

    The CPE path: precise. Feed it the authoritative CPE nmap matched on a
    ``Service`` and NVD returns exactly the vulnerabilities whose
    applicability criteria cover it. Returns up to ``limit`` typed
    ``CVE`` rows; ``[]`` on empty input or any error.
    """
    if not cpe.strip():
        return []
    params: dict[str, str | int] = {"cpeName": cpe, "resultsPerPage": limit}
    return _get_cves(params, ("cve:cpe", cpe))


def search_cpes(keyword: str, limit: int = 10) -> list[str]:
    """Search the NVD CPE dictionary by keyword; return canonical CPE names.

    Resolves a loose product name ("Apache HTTP Server 2.4.41") to the
    canonical ``cpe:2.3:...`` strings NVD knows. The low-level primitive a
    later name -> CPE resolver builds on; returns the CPE name strings in NVD's
    relevance order. ``[]`` on empty input or any error.
    """
    if not keyword.strip():
        return []
    cache_key = ("cpe:keyword", keyword)
    if cache_key in _RESULT_CACHE:
        return list(_RESULT_CACHE[cache_key])
    params: dict[str, str | int] = {"keywordSearch": keyword, "resultsPerPage": limit}
    try:
        resp = http.get(_CPE_API_URL, params=params, headers=_headers(), timeout=_TIMEOUT_S)
        resp.raise_for_status()
        names = [
            name
            for product in resp.json().get("products", [])
            if isinstance(product, dict)
            if (name := product.get("cpe", {}).get("cpeName"))
        ]
    except Exception as exc:
        logger.warning("NVD CPE search failed for %r: %s", keyword, exc)
        return []
    _RESULT_CACHE[cache_key] = names
    return list(names)


__all__ = ["clear_cache", "cves_for_cpe", "cves_for_keyword", "search_cpes"]
