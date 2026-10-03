"""
models/service.py - typed shape for named exposed services / products the
squad probes.

The ``Service`` StrEnum is the third asset-property vocabulary alongside
``Framework`` (web app stacks) and ``Cloud`` (cloud providers at the
provider level). It carries the long tail of named products that have
their own targeted probe: databases (Redis, MongoDB, PostgreSQL, ...),
dashboards (Grafana, Kibana, Portainer), control panels (cPanel, Plesk,
DirectAdmin, Webmin), and service-discovery systems (Consul, Vault).

Why a third enum rather than widening ``Framework`` to include all of
these: Django is a web framework; Redis is a database; cPanel is a
control panel. Different mental models. Keeping the three vocabularies
separate lets the agent reason about each axis independently - "the
target is a Spring web app fronted by Grafana on AWS" decomposes
cleanly into ``Framework.spring``, ``Service.grafana``, ``Cloud.aws``
without overloading any one enum.

Lives in ``models/`` (rather than next to its decorator in
``tools/pentest/service.py``) for the same reason ``Framework`` and
``Cloud`` do: the enum is read across the recon -> VR -> PT boundary,
not only by the decorator that stamps it.
"""

from __future__ import annotations

from enum import StrEnum


class Service(StrEnum):
    """Named services / products the squad detects and targets via product-specific probes.

    Append-only catalogue. Member values are lowercase short names that
    round-trip cleanly from recon strings (httpx tech-detect, nmap
    banners) to enum members via a future ``coerce_services(...)``
    helper.

    Only products with at least one product-specific probe in
    ``tools/cloud/`` or ``tools/pentest/`` earn a member. Generic
    exposure probes (the catch-all admin-panels / sensitive-files
    checks, the database-port sweep) do not gate on this enum.
    """

    # Databases
    couchdb = "couchdb"
    elasticsearch = "elasticsearch"
    mariadb = "mariadb"
    mongodb = "mongodb"
    mysql = "mysql"
    postgresql = "postgresql"
    redis = "redis"

    # Dashboards
    grafana = "grafana"
    kibana = "kibana"
    portainer = "portainer"

    # Hosting control panels
    cpanel = "cpanel"
    directadmin = "directadmin"
    plesk = "plesk"
    webmin = "webmin"

    # Service discovery / secret stores
    consul = "consul"
    vault = "vault"


__all__ = ["Service"]
