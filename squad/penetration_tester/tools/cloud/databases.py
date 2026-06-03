"""
Exposed database / search-index probes - look for unauthenticated
admin / data endpoints on Elasticsearch, CouchDB, Redis, MongoDB,
PostgreSQL, MySQL / MariaDB.

Each wrapper takes typed ``list[FQDN]`` picked by the agent from
recon (the host:port pairs surfaced by the nmap pass) and a wrapper-
level ``scope_filter`` drops anything outside the selected programme's
structured scope before the probe fires. See the recon-side precedent
in ``squad/osint_analyst/tools/discovery.py`` (``Probe FQDNs``).
"""

from pydantic import BaseModel, Field

from models import FQDN, RawFinding
from squad import cyber_tool
from tools.cloud import (
    check_couchdb,
    check_elasticsearch,
    check_mongodb,
    check_mysql,
    check_postgresql,
    check_redis,
)
from tools.recon.scope import TargetFQDNs


class _ElasticsearchCheckArgs(BaseModel):
    """Explicit args_schema for the Unauthenticated Elasticsearch Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 9200 open (or technologies mentioning"
            " Elasticsearch). Probes /_cluster/health on each; a 200 with"
            " cluster_name confirms no auth. The wrapper's scope filter"
            " drops any hostname outside the selected programme's"
            " structured scope before the probe fires."
        ),
    )


@cyber_tool("Unauthenticated Elasticsearch Check", args_schema=_ElasticsearchCheckArgs)
def elasticsearch_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an unauthenticated Elasticsearch instance on port 9200 on each
    supplied hostname. Probes /_cluster/health - a 200 response with
    cluster_name confirms no auth.

    Pick hostnames from the Recon Open Ports slicer where port 9200 shows
    open, or where Recon Endpoints / Annotate Host called out an
    Elasticsearch technology. The wrapper scope-filters the list against
    the selected programme; the body iterates whatever survives.
    """
    findings: list[RawFinding] = []
    for host in hostnames:
        findings.extend(check_elasticsearch(host))
    return findings


class _CouchdbCheckArgs(BaseModel):
    """Explicit args_schema for the Unauthenticated CouchDB Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 5984 open. Probes /_all_dbs on each;"
            " a 200 listing databases confirms no auth. The wrapper's"
            " scope filter drops out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("Unauthenticated CouchDB Check", args_schema=_CouchdbCheckArgs)
def couchdb_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an unauthenticated CouchDB instance on port 5984 on each
    supplied hostname. Probes /_all_dbs - a 200 response listing databases
    confirms no auth.

    Pick hostnames from the Recon Open Ports slicer where port 5984 shows
    open. The wrapper scope-filters the list.
    """
    findings: list[RawFinding] = []
    for host in hostnames:
        findings.extend(check_couchdb(host))
    return findings


class _RedisCheckArgs(BaseModel):
    """Explicit args_schema for the Unauthenticated Redis Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 6379 open. Sends a PING; a +PONG"
            " without AUTH confirms no password is set. The wrapper's"
            " scope filter drops out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("Unauthenticated Redis Check", args_schema=_RedisCheckArgs)
def redis_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an unauthenticated Redis instance on port 6379 via a PING
    command. A +PONG response without sending AUTH confirms no password
    is set.

    Pick hostnames from the Recon Open Ports slicer where port 6379 shows
    open. The wrapper scope-filters the list.
    """
    findings: list[RawFinding] = []
    for host in hostnames:
        findings.extend(check_redis(host))
    return findings


class _MongodbCheckArgs(BaseModel):
    """Explicit args_schema for the Unauthenticated MongoDB Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 27017 open. Sends a minimal isMaster"
            " wire query; a valid response without error confirms"
            " unauthenticated access. The wrapper's scope filter drops"
            " out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("Unauthenticated MongoDB Check", args_schema=_MongodbCheckArgs)
def mongodb_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an unauthenticated MongoDB instance on port 27017 on each
    supplied hostname. Sends a minimal isMaster wire-protocol query - a
    valid response without error confirms the instance accepts connections
    without credentials.

    Pick hostnames from the Recon Open Ports slicer where port 27017 shows
    open. The wrapper scope-filters the list.
    """
    findings: list[RawFinding] = []
    for host in hostnames:
        findings.extend(check_mongodb(host))
    return findings


class _PostgresqlCheckArgs(BaseModel):
    """Explicit args_schema for the Exposed PostgreSQL Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 5432 open. CRITICAL if trust"
            " authentication allows connection without a password;"
            " MEDIUM if the port is exposed but credentials are required"
            " (unnecessary internet exposure). The wrapper's scope filter"
            " drops out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("Exposed PostgreSQL Check", args_schema=_PostgresqlCheckArgs)
def postgresql_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for PostgreSQL on port 5432 on each supplied hostname. Returns
    CRITICAL if trust authentication allows connection without a password;
    MEDIUM if the port is exposed but credentials are required
    (unnecessary internet exposure).

    Pick hostnames from the Recon Open Ports slicer where port 5432 shows
    open. The wrapper scope-filters the list.
    """
    findings: list[RawFinding] = []
    for host in hostnames:
        findings.extend(check_postgresql(host))
    return findings


class _MysqlCheckArgs(BaseModel):
    """Explicit args_schema for the Exposed MySQL/MariaDB Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 3306 open. MEDIUM if the port is"
            " reachable and the server responds with a valid handshake"
            " (unnecessary internet exposure; verify anonymous login is"
            " disabled). The wrapper's scope filter drops out-of-scope"
            " hostnames before any probe."
        ),
    )


@cyber_tool("Exposed MySQL/MariaDB Check", args_schema=_MysqlCheckArgs)
def mysql_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for MySQL or MariaDB on port 3306 on each supplied hostname.
    Returns MEDIUM if the port is reachable and the server responds with a
    valid handshake (unnecessary internet exposure; verify anonymous
    login is disabled).

    Pick hostnames from the Recon Open Ports slicer where port 3306 shows
    open. The wrapper scope-filters the list.
    """
    findings: list[RawFinding] = []
    for host in hostnames:
        findings.extend(check_mysql(host))
    return findings
