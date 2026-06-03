"""squad/penetration_tester/tools/cloud - ``@cyber_tool`` cloud / infra checks.

Split per-family across sibling sub-modules so each file owns one
cohesive exposure mechanism. Every wrapper in this package takes a
typed target the agent explicitly picks (``list[FQDN]`` for port-
or container-style probes, ``list[Endpoint]`` for path-style or URL-
inspection probes) and carries a single ``scope_filter`` so out-of-
scope targets reject at the wrapper boundary before any HTTP request
fires. Aligns with the pipeline split: PM transcribes scope; OSINT
inventories the surface; PT attacks the inventoried surface.

- ``storage`` - S3 Bucket Check, Azure Blob Container Check, Azure
  SAS Token Check.
- ``databases`` - Elasticsearch, CouchDB, Redis, MongoDB, PostgreSQL,
  MySQL / MariaDB.
- ``web_content`` - Sensitive Files Check, Admin Panels Check
  (endpoint-driven path probes).
- ``panels`` - cPanel/WHM, Plesk, DirectAdmin, Webmin (hosting
  control panels).
- ``dashboards`` - Grafana, Kibana, Portainer; each split into
  ``Port Check`` (typed ``list[FQDN]``) + ``Path Check`` (typed
  ``list[Endpoint]``) so each wrapper carries a single
  ``scope_filter``.
- ``service_discovery`` - Consul / Vault, same split as dashboards.

This module re-exports every wrapper + args_schema class so the parent
agent ``squad.penetration_tester.__init__`` keeps a single import site
(``from squad.penetration_tester.tools.cloud import ...``) and the public
surface of the agent module does not change.
"""

from squad.penetration_tester.tools.cloud.dashboards import (
    _GrafanaPathArgs,
    _GrafanaPortArgs,
    _KibanaPathArgs,
    _KibanaPortArgs,
    _PortainerPathArgs,
    _PortainerPortArgs,
    grafana_path_check_tool,
    grafana_port_check_tool,
    kibana_path_check_tool,
    kibana_port_check_tool,
    portainer_path_check_tool,
    portainer_port_check_tool,
)
from squad.penetration_tester.tools.cloud.databases import (
    _CouchdbCheckArgs,
    _ElasticsearchCheckArgs,
    _MongodbCheckArgs,
    _MysqlCheckArgs,
    _PostgresqlCheckArgs,
    _RedisCheckArgs,
    couchdb_tool,
    elasticsearch_tool,
    mongodb_tool,
    mysql_tool,
    postgresql_tool,
    redis_tool,
)
from squad.penetration_tester.tools.cloud.panels import (
    _CpanelArgs,
    _DirectadminArgs,
    _PleskArgs,
    _WebminArgs,
    cpanel_tool,
    directadmin_tool,
    plesk_tool,
    webmin_tool,
)
from squad.penetration_tester.tools.cloud.service_discovery import (
    _ConsulVaultPathArgs,
    _ConsulVaultPortArgs,
    consul_vault_path_check_tool,
    consul_vault_port_check_tool,
)
from squad.penetration_tester.tools.cloud.storage import (
    _AzureBlobContainerArgs,
    _AzureSasTokenArgs,
    _S3CheckArgs,
    azure_blob_container_check_tool,
    azure_sas_token_check_tool,
    s3_check_tool,
)
from squad.penetration_tester.tools.cloud.web_content import (
    _AdminPanelsArgs,
    _SensitiveFilesArgs,
    admin_panels_tool,
    sensitive_files_tool,
)

__all__ = [  # noqa: RUF022 - grouped by cloud-family sub-module, not alphabetised
    # dashboards
    "_GrafanaPathArgs",
    "_GrafanaPortArgs",
    "_KibanaPathArgs",
    "_KibanaPortArgs",
    "_PortainerPathArgs",
    "_PortainerPortArgs",
    "grafana_path_check_tool",
    "grafana_port_check_tool",
    "kibana_path_check_tool",
    "kibana_port_check_tool",
    "portainer_path_check_tool",
    "portainer_port_check_tool",
    # databases
    "_CouchdbCheckArgs",
    "_ElasticsearchCheckArgs",
    "_MongodbCheckArgs",
    "_MysqlCheckArgs",
    "_PostgresqlCheckArgs",
    "_RedisCheckArgs",
    "couchdb_tool",
    "elasticsearch_tool",
    "mongodb_tool",
    "mysql_tool",
    "postgresql_tool",
    "redis_tool",
    # panels
    "_CpanelArgs",
    "_DirectadminArgs",
    "_PleskArgs",
    "_WebminArgs",
    "cpanel_tool",
    "directadmin_tool",
    "plesk_tool",
    "webmin_tool",
    # service_discovery
    "_ConsulVaultPathArgs",
    "_ConsulVaultPortArgs",
    "consul_vault_path_check_tool",
    "consul_vault_port_check_tool",
    # storage
    "_AzureBlobContainerArgs",
    "_AzureSasTokenArgs",
    "_S3CheckArgs",
    "azure_blob_container_check_tool",
    "azure_sas_token_check_tool",
    "s3_check_tool",
    # web_content
    "_AdminPanelsArgs",
    "_SensitiveFilesArgs",
    "admin_panels_tool",
    "sensitive_files_tool",
]
