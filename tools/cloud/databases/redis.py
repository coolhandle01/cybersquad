"""Unauthenticated Redis check."""

from __future__ import annotations

import logging
import socket

from models import RawFinding, Severity

logger = logging.getLogger(__name__)

PORT = 6379


def check_redis(host: str) -> list[RawFinding]:
    """Return a CRITICAL finding if Redis on port 6379 responds to PING without auth."""
    try:
        with socket.create_connection((host, PORT), timeout=3) as sock:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            data = sock.recv(128)
        if b"+PONG" in data:
            return [
                RawFinding(
                    title=f"Unauthenticated Redis - {host}",
                    vuln_class="ExposedService",
                    target=f"redis://{host}:{PORT}",
                    evidence="Redis responded to PING without authentication.",
                    tool="redis_check",
                    severity_hint=Severity.CRITICAL,
                )
            ]
    except Exception as exc:
        logger.debug("Redis check failed for %s: %s", host, exc)
    return []
