"""
models.nvd.severity - the CVSS-derived severity rating.

A closed five-level scale (informational .. critical) - the shared vocabulary
for "how bad" across findings, triage, insight, and report. A CVSS-derived
rating, so it lives in the NVD / scoring domain rather than among the
asset-identity primitives in ``models.primitives``.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
