"""
models.nvd.cvss - the CVSS vector typed-string primitive.

A ``CvssVector`` validates a CVSS 3.x vector string at the boundary by parsing
it with the ``cvss`` library (the canonical RedHat implementation of the spec) -
so an unparseable vector, an unknown metric value (``AV:Z``), a missing
mandatory metric, or a non-3.x version rejects at args_schema validation time
rather than deep in score computation. Both this validator and
``tools.report_tools.calculate_cvss_score`` delegate to the same library: one
source of truth for the spec, used at two call sites (parse here, score there),
with no hand-rolled metric tables to drift.

Runtime stays ``str`` to match the ``FQDN`` / ``IpAddr`` convention, so existing
consumers that pass the vector to ``calculate_cvss_score`` or interpolate it into
a report keep working unchanged.
"""

from __future__ import annotations

from typing import Annotated

from cvss import CVSS3
from cvss.exceptions import CVSS3Error
from pydantic import AfterValidator


def _validate_cvss_vector(value: str) -> str:
    """Validate that ``value`` is a parseable CVSS 3.x base vector.

    Parses with ``cvss.CVSS3``; any spec violation (bad prefix, unknown metric
    value, missing mandatory metric, malformed token) surfaces as a
    ``ValueError`` to the calling model. Returns the stripped value unchanged -
    validate, do not canonicalise, so reports / comparisons see the agent's
    exact vector.
    """
    if not isinstance(value, str):  # pragma: no cover - Pydantic enforces str upstream
        raise ValueError(f"CVSS vector must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("CVSS vector cannot be empty")
    try:
        CVSS3(cleaned)
    except CVSS3Error as exc:
        raise ValueError(f"invalid CVSS 3.x vector {value!r}: {exc}") from exc
    return cleaned


CvssVector = Annotated[str, AfterValidator(_validate_cvss_vector)]
