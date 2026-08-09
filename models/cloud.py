"""
models/cloud.py - typed shape for cloud providers the squad targets.

The ``Cloud`` StrEnum is the canonical vocabulary the recon pass cites,
the Vulnerability Researcher reasons over during research, and the
provider-specific cloud probes stamp via ``@cloud(...)`` from
``tools/pentest/cloud.py``. Sibling to ``models/framework.py`` - the
two enums together carry the asset-property vocabulary the agent
navigates.

Lives in ``models/`` (rather than next to its decorator in
``tools/pentest/cloud.py``) for the same reason ``Framework`` does:
the enum is read across the recon -> VR -> PT boundary, not only by
the decorator that stamps it.
"""

from __future__ import annotations

from enum import StrEnum


class Cloud(StrEnum):
    """Cloud providers the squad detects and targets via provider-specific probes.

    Append-only catalogue. Member values are lowercase short names so a
    recon string ``"aws"`` (from a CDN-fingerprint header or an AS
    organisation lookup) round-trips to ``Cloud.aws`` cleanly.

    Only providers with at least one provider-specific probe in
    ``tools/cloud/`` earn a member. Provider-agnostic exposure probes
    (databases, admin panels, dashboards) do not gate on this enum -
    they fire across any cloud and are not stamped with ``@cloud(...)``.
    """

    aws = "aws"
    azure = "azure"
    gcp = "gcp"


__all__ = ["Cloud"]
