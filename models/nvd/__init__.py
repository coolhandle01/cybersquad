"""
models.nvd - the NVD / CVSS vocabulary: the vulnerability-scoring domain.

Distinct from the OAM asset graph (``models.asset``) and from MITRE's weakness
taxonomy (``models.mitre``). Houses the NIST National Vulnerability Database
shapes - the ``CVE`` record and the CVSS-derived ``Severity`` rating (and
the CVSS-vector primitive when it lands).

``Severity`` lived in ``models.primitives`` historically, but it is a
CVSS-derived rating, not an asset-identity typed-string, so it belongs here with
the scoring vocab. Leaf package: depends only on pydantic / stdlib, so any model
module can import from it without a cycle.
"""

from __future__ import annotations

from models.nvd.cve import CVE
from models.nvd.cvss import CvssVector
from models.nvd.severity import Severity

__all__ = ["CVE", "CvssVector", "Severity"]
