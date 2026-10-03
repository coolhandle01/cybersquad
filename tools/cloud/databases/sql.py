"""Unauthenticated / exposed SQL database checks (PostgreSQL, MySQL, MariaDB)."""

from __future__ import annotations

import logging
import socket

from models import RawFinding, Severity
from models.service import Service
from tools.pentest.service import service

logger = logging.getLogger(__name__)

POSTGRES_PORT = 5432
MYSQL_PORT = 3306


@service(Service.postgresql)
def check_postgresql(host: str) -> list[RawFinding]:
    """Check PostgreSQL on port 5432.

    Returns CRITICAL if the server accepts a connection without a password
    (AuthenticationOk with method 0 - trust auth). Returns MEDIUM if the port
    is open and responds but requires credentials (unnecessary exposure).
    """
    try:
        with socket.create_connection((host, POSTGRES_PORT), timeout=3) as sock:
            # StartupMessage: length(4) + protocol 3.0(4) + "user\0postgres\0\0"
            params = b"user\x00postgres\x00\x00"
            length = (8 + len(params)).to_bytes(4, "big")
            sock.sendall(length + b"\x00\x03\x00\x00" + params)
            data = sock.recv(128)

        if not data:
            return []

        if data[0:1] == b"R" and len(data) >= 9:
            method = int.from_bytes(data[5:9], "big")
            if method == 0:
                # AuthenticationOk - no password required
                return [
                    RawFinding(
                        title=f"Unauthenticated PostgreSQL - {host}",
                        vuln_class="ExposedService",
                        target=f"postgresql://{host}:{POSTGRES_PORT}",
                        evidence=(
                            "PostgreSQL accepted the connection without a password "
                            "(trust authentication)."
                        ),
                        tool="postgresql_check",
                        severity_hint=Severity.CRITICAL,
                    )
                ]
            # Auth required but port is directly reachable
            return [
                RawFinding(
                    title=f"PostgreSQL Exposed - {host}",
                    vuln_class="ExposedService",
                    target=f"postgresql://{host}:{POSTGRES_PORT}",
                    evidence=(
                        "PostgreSQL port 5432 is reachable from the internet. "
                        "Authentication is required but the service should not be "
                        "directly exposed."
                    ),
                    tool="postgresql_check",
                    severity_hint=Severity.MEDIUM,
                )
            ]
    except Exception as exc:
        logger.debug("PostgreSQL check failed for %s: %s", host, exc)
    return []


@service(Service.mysql, Service.mariadb)
def check_mysql(host: str) -> list[RawFinding]:
    """Check MySQL / MariaDB on port 3306.

    Both speak the MySQL wire protocol on the same port, but they are
    distinct products with distinct advisory streams (MariaDB forked at
    5.5 and no longer shares CVEs with MySQL). The server greeting tells
    them apart: MariaDB stamps ``MariaDB`` into its version string (e.g.
    ``5.5.5-10.6.0-MariaDB``). The finding names whichever product the
    banner identifies so the VR/PT targets the right CVE set rather than
    lumping both under one label.

    Returns MEDIUM if the port is open and the server responds with a valid
    handshake (port directly reachable). Emitting MEDIUM rather than
    CRITICAL because completing the anonymous-login flow requires full
    handshake implementation; the agent should follow up manually if needed.
    """
    try:
        with socket.create_connection((host, MYSQL_PORT), timeout=3) as sock:
            data = sock.recv(256)
        # Protocol v10 = \x0a; v9 = \x09. MariaDB self-identifies in the
        # version string, so accept that as a valid handshake too and use it
        # to distinguish the product.
        is_mariadb = b"mariadb" in data.lower()
        if len(data) >= 5 and (data[4:5] in (b"\x0a", b"\x09") or is_mariadb):
            version_end = data.find(b"\x00", 5)
            version = (
                data[5:version_end].decode("ascii", errors="replace")
                if version_end > 5
                else "unknown"
            )
            product = "MariaDB" if is_mariadb else "MySQL"
            return [
                RawFinding(
                    title=f"{product} Exposed - {host}",
                    vuln_class="ExposedService",
                    target=f"mysql://{host}:{MYSQL_PORT}",
                    evidence=(
                        f"{product} port 3306 is reachable from the internet "
                        f"(server version: {version}). Verify anonymous login is "
                        f"disabled and the service should not be directly exposed."
                    ),
                    tool="mysql_check",
                    severity_hint=Severity.MEDIUM,
                )
            ]
    except Exception as exc:
        logger.debug("MySQL check failed for %s: %s", host, exc)
    return []
