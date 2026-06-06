"""
models.primitives - foundational typed-string and enum primitives shared
across the model graph.

The typed-string primitives here (``FQDN``, ``IpAddr``, ``Cidr``, ``HttpUrl``,
``Email``) and the ``IPType`` enum are asset-identity leaf dependencies - they
have no forward references into other model modules - so they live in the
deepest layer of the package. ``models.finding``, ``models.asset``,
``models.h1`` and the rest depend on them; nothing here depends on the others.
(``Severity`` used to live here too; it moved to ``models.nvd`` as a
CVSS-derived scoring rating, not an asset-identity primitive.)

Split one-concept-per-module (``fqdn``, ``http_url``, ``ip_addr``, ``cidr``,
``email``, ``ip_type``) mirroring the ``models.nvd`` / ``models.mitre`` layout;
the re-exports below keep ``from models.primitives import FQDN`` (and the
top-level ``from models import FQDN``) working unchanged. The one intra-package
edge is ``http_url`` -> ``fqdn`` (a URL's host runs through the FQDN validator).
"""

from __future__ import annotations

from models.primitives.cidr import Cidr
from models.primitives.email import Email
from models.primitives.fqdn import FQDN
from models.primitives.http_url import HttpUrl
from models.primitives.ip_addr import IpAddr
from models.primitives.ip_type import IPType

__all__ = ["FQDN", "Cidr", "Email", "HttpUrl", "IPType", "IpAddr"]
