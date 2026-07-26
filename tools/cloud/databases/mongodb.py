"""Unauthenticated MongoDB check."""

from __future__ import annotations

import logging
import socket

from models import RawFinding, Severity

logger = logging.getLogger(__name__)

PORT = 27017


def check_mongodb(host: str) -> list[RawFinding]:
    """Return a CRITICAL finding if MongoDB on port 27017 answers isMaster without auth."""
    try:
        with socket.create_connection((host, PORT), timeout=3) as sock:
            # Minimal OP_QUERY against admin.$cmd: {isMaster: 1}
            bson_doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
            header = (
                b"\x00\x00\x00\x00"  # messageLength placeholder
                b"\x01\x00\x00\x00"  # requestID
                b"\x00\x00\x00\x00"  # responseTo
                b"\xd4\x07\x00\x00"  # opCode OP_QUERY
                b"\x00\x00\x00\x00"  # flags
            )
            coll = b"admin.$cmd\x00"
            skip_return = b"\x00\x00\x00\x00\x01\x00\x00\x00"
            body = header + coll + skip_return + bson_doc
            length = (len(body) + 4).to_bytes(4, "little")
            sock.sendall(length + body)
            data = sock.recv(256)
        if b"ismaster" in data.lower() or b"iswritableprimary" in data.lower():
            return [
                RawFinding(
                    title=f"Unauthenticated MongoDB - {host}",
                    vuln_class="ExposedService",
                    target=f"mongodb://{host}:{PORT}",
                    evidence=("MongoDB answered an isMaster query without authentication."),
                    tool="mongodb_check",
                    severity_hint=Severity.CRITICAL,
                )
            ]
    except Exception as exc:
        logger.debug("MongoDB check failed for %s: %s", host, exc)
    return []
