"""Httpx flag composition - the config-tables layer.

No I/O. Maps ``HttpxMode`` (+ orthogonal evidence toggles) to the final
CLI flag list httpx is invoked with. Composition is the only thing
this file does; ``scanner`` orchestrates around it.
"""

from __future__ import annotations

from config import config
from models.scanner import HttpxMode

# Per-mode httpx signal-flag bundles. Each layer adds to the previous
# so escalation is monotone: WEB_INVENTORY > TECH_DETECT > LIVE in
# signal depth, payload weight, and time-per-host.
#
# Deliberately omits ``-asn`` (defers to ``tools/recon/asn.py`` / Cymru)
# and ``-cname`` (defers to ``tools/recon/dnsx.py``). One way to get
# each data point.
_MODE_FLAGS: dict[HttpxMode, list[str]] = {
    HttpxMode.LIVE: [
        "-status-code",
    ],
    HttpxMode.TECH_DETECT: [
        "-status-code",
        "-tech-detect",
        "-server",
        "-title",
    ],
    HttpxMode.WEB_INVENTORY: [
        "-status-code",
        "-tech-detect",
        "-server",
        "-title",
        "-favicon",
        "-tls-grab",
        "-content-type",
        "-method",
    ],
}


def _assemble_flags(
    mode: HttpxMode,
    *,
    with_screenshots: bool = False,
    with_responses: bool = False,
    evidence_dir: str | None = None,
) -> list[str]:
    """Compose the final httpx flag list for the given mode + toggles.

    Common flags (``-silent`` / ``-json`` / ``-timeout``) are always
    present; ``_MODE_FLAGS[mode]`` adds the per-mode signal flags;
    ``with_screenshots`` / ``with_responses`` layer on the per-URL
    evidence-writing flags (``-screenshot`` + ``-store-response``) and
    point httpx at ``evidence_dir`` via ``-srd``.

    If ``with_screenshots`` or ``with_responses`` is True but
    ``evidence_dir`` is None (no pipeline run bound), the evidence
    flags are silently omitted - the scan still produces structured
    signal, just no files-on-disk.
    """
    # Rate / retry / thread caps live on ``config.scan`` and pick their
    # values from the operator's scan-mode dial in ``ScanConfig.__post_init__``.
    # Stealth scales them down, raid scales them up; one source of truth.
    flags: list[str] = [
        "-silent",
        "-json",
        "-timeout",
        str(config.recon.http_timeout),
        "-rate-limit",
        str(config.scan.httpx_rate_limit),
        "-retries",
        str(config.scan.httpx_retries),
        "-threads",
        str(config.scan.httpx_threads),
        *_MODE_FLAGS[mode],
    ]
    if (with_screenshots or with_responses) and evidence_dir is not None:
        flags += ["-srd", evidence_dir]
        if with_screenshots:
            flags.append("-screenshot")
        if with_responses:
            flags.append("-store-response")
    return flags


__all__ = ["_assemble_flags"]
