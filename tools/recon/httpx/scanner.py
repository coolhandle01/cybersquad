"""Httpx orchestration: subprocess invocation, evidence dir handling, public surface.

Two callable surfaces re-exported through ``tools/recon/httpx/__init__.py``:

* ``httpx_scan(hosts, mode, with_screenshots, with_responses)`` - the
  rich entry point. Returns ``HttpxScanResult`` with the typed
  endpoint list, the mode the scan ran in, and a relative-path
  pointer to the evidence directory under ``runtime.run_dir()``.
* ``probe_endpoints(hosts)`` - backwards-compatible thin shim returning
  ``list[Endpoint]`` (mode=TECH_DETECT, no evidence). Preserves the
  signature ``run_recon`` and legacy tests rely on.

Composes flags via ``tools.recon.httpx.flags._assemble_flags``; parses
NDJSON via ``tools.recon.httpx.parser._parse_ndjson``. This file owns
only the subprocess invocation, the evidence-dir setup, and the public
function signatures.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import runtime
from models.asset import Endpoint
from models.primitives import FQDN
from models.scanner import HttpxMode, HttpxScanResult
from tools._helpers import _require_binary, _run
from tools.recon.httpx.flags import _assemble_flags
from tools.recon.httpx.parser import _parse_ndjson

logger = logging.getLogger(__name__)


def _evidence_dirname(hosts: list[FQDN], mode: HttpxMode) -> str:
    """Stable directory name under runtime.run_dir() for one scan's evidence."""
    host_hash = hashlib.sha256("\n".join(sorted(hosts)).encode()).hexdigest()[:12]
    return f"httpx-{host_hash}-{mode.value}"


def _resolve_evidence_dir(dirname: str) -> Path | None:
    """Resolve the absolute evidence-dir path; None if no run is bound.

    During tests (and CLI / library usage outside a pipeline run) the
    programme + run_id binding is absent. We return None so callers
    skip evidence-writing gracefully rather than raising.
    """
    try:
        return runtime.run_dir() / dirname
    except RuntimeError:
        return None


def httpx_scan(
    hosts: list[FQDN],
    mode: HttpxMode = HttpxMode.TECH_DETECT,
    *,
    with_screenshots: bool = False,
    with_responses: bool = False,
) -> HttpxScanResult:
    """Run httpx against ``hosts`` with the typed ``HttpxMode`` selector.

    Returns an ``HttpxScanResult`` carrying:

    * ``endpoints`` - one ``Endpoint`` per live host, with mode-
      appropriate fields populated (see ``HttpxMode`` for the
      escalation: LIVE -> TECH_DETECT -> WEB_INVENTORY).
    * ``evidence_dir`` - relative path under ``runtime.run_dir()``
      pointing at the directory httpx wrote screenshot PNGs and / or
      stored response bodies to. ``None`` when neither
      ``with_screenshots`` nor ``with_responses`` was requested, or
      when no pipeline run was bound (tests, library usage).

    Degrades gracefully on subprocess failure - returns an empty
    ``HttpxScanResult`` rather than raising. Recon should keep moving
    with whatever signal IS available.
    """
    if not hosts:
        return HttpxScanResult(mode=mode, endpoints=[])

    # Resolve the evidence dir BEFORE we shell out, so the flag list
    # can include -srd / -screenshot / -store-response coherently.
    evidence_dir: Path | None = None
    evidence_rel: str | None = None
    if with_screenshots or with_responses:
        dirname = _evidence_dirname(hosts, mode)
        target = _resolve_evidence_dir(dirname)
        if target is not None:
            try:
                target.mkdir(parents=True, exist_ok=True)
                evidence_dir = target
                evidence_rel = dirname
            except OSError as exc:  # pragma: no cover - defensive: mkdir on rundir
                logger.warning("Failed to create httpx evidence dir %s: %s", target, exc)

    httpx_bin = _require_binary("httpx")
    flags = _assemble_flags(
        mode,
        with_screenshots=with_screenshots,
        with_responses=with_responses,
        evidence_dir=str(evidence_dir) if evidence_dir is not None else None,
    )
    input_data = "\n".join(hosts)
    try:
        result = _run(
            [httpx_bin, *flags],
            timeout=300,
            input=input_data,
        )
    except Exception as exc:
        logger.warning("httpx scan failed: %s", exc)
        return HttpxScanResult(mode=mode, endpoints=[], evidence_dir=evidence_rel)

    endpoints = _parse_ndjson(result.stdout, mode)
    logger.info(
        "httpx %s: %d hosts -> %d live endpoints (evidence=%s)",
        mode.value,
        len(hosts),
        len(endpoints),
        evidence_rel or "none",
    )
    return HttpxScanResult(mode=mode, endpoints=endpoints, evidence_dir=evidence_rel)


def probe_endpoints(hosts: list[FQDN]) -> list[Endpoint]:
    """Backwards-compatible shim - ``httpx_scan(hosts, TECH_DETECT)``.

    The historical entry point the recon orchestrator and the legacy
    tests use. Matches the today-default behaviour: tech-detect on
    every probed endpoint, no evidence-file persistence. New callers
    should prefer ``httpx_scan`` with an explicit ``HttpxMode`` for
    the broad-then-narrow pattern.
    """
    return httpx_scan(hosts, mode=HttpxMode.TECH_DETECT).endpoints


__all__ = ["httpx_scan", "probe_endpoints"]
