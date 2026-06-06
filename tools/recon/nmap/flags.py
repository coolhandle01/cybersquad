"""Nmap flag composition - the config-tables layer.

No I/O. Maps ``(NmapMode, NmapBanner, NmapScripts, ConfigScanMode)``
to the final CLI flag list nmap is invoked with. Composition is the
only thing this file does; ``scanner`` orchestrates around it.

Refuses incompatible combinations at this layer rather than letting
nmap surface them mid-scan:

* ``NmapScripts.VULN`` under ``ScanMode.STEALTH`` raises ``ValueError``
  - loud script bundle against an explicit stealth posture.
"""

from __future__ import annotations

from config import ScanMode as ConfigScanMode
from models.scanner import NmapBanner, NmapMode, NmapScripts

# Per-mode base flags. Banner / scripts / scan_mode layer on top.
_MODE_FLAGS: dict[NmapMode, list[str]] = {
    NmapMode.QUICK_PORTS: ["-sS", "--open", "-F"],
    NmapMode.SERVICE_VERSION: ["-sS", "--open", "-F", "-sV"],
    NmapMode.FULL_INVENTORY: ["-sS", "--open", "-F", "-sV"],
    NmapMode.OS_DETECT: ["-O"],
}

# Banner depth maps to nmap's --version-intensity (0-9). Only applies
# when the mode runs -sV (SERVICE_VERSION / FULL_INVENTORY).
_BANNER_INTENSITY: dict[NmapBanner, str | None] = {
    NmapBanner.NONE: None,
    NmapBanner.LIGHT: "2",
    NmapBanner.FULL: "9",
}

# Script bundles. Each value is the argument to --script=.
_SCRIPTS_EXPR: dict[NmapScripts, str | None] = {
    NmapScripts.NONE: None,
    NmapScripts.HTTP_HEADERS: "banner,http-server-header,http-title",
    NmapScripts.DEFAULT: "default",  # nmap's -sC bundle, via the uniform --script= path
    NmapScripts.SAFE: "safe",
    NmapScripts.VULN: "vuln",
}

# Per-scan-mode timing knobs. Maps the operator's stealth dial
# (config.scan.scan_mode) to nmap's -T timing template + retry /
# timeout / rate caps.
_SCAN_MODE_FLAGS: dict[ConfigScanMode, list[str]] = {
    ConfigScanMode.STEALTH: ["-T2", "--max-retries", "1", "--host-timeout", "60s"],
    ConfigScanMode.NORMAL: ["-T3"],
    ConfigScanMode.RAID: ["-T4", "--min-rate", "1000", "--max-retries", "3"],
}


def _assemble_flags(
    mode: NmapMode,
    banner: NmapBanner,
    scripts: NmapScripts,
    scan_mode: ConfigScanMode,
    ports: list[int] | None = None,
) -> list[str]:
    """Compose the final nmap flag list from the four axes.

    ``ports`` is the optional focused-target list: when non-empty it
    swaps the mode's ``-F`` (top-100) for an explicit ``-p <csv>``, the
    "deep scan a host's known-open ports" case. Empty / ``None`` keeps
    the mode's default breadth so every existing caller is unaffected.

    Refuses incompatible combinations at the boundary rather than
    letting nmap surface them mid-scan:

    * ``NmapScripts.VULN`` under ``ScanMode.STEALTH`` - loud script
      bundle against an explicit stealth posture; raise ``ValueError``
      so the OA sees the refusal and can dial back.
    """
    if scripts == NmapScripts.VULN and scan_mode == ConfigScanMode.STEALTH:
        raise ValueError(
            "NmapScripts.VULN is incompatible with ScanMode.STEALTH "
            "(vuln scripts are loud; pick SAFE or HTTP_HEADERS for stealth runs)"
        )

    flags = list(_MODE_FLAGS[mode])

    # Focused port targeting: replace the mode's top-100 (-F) with an
    # explicit -p list. Guard on a non-empty list so an empty list
    # degrades to the mode default rather than emitting a bare -p.
    if ports:
        if "-F" in flags:
            flags.remove("-F")
        flags += ["-p", ",".join(str(p) for p in ports)]

    # Banner intensity only meaningful when -sV is in the base flag list.
    if "-sV" in flags:
        intensity = _BANNER_INTENSITY[banner]
        if intensity is not None:
            flags += ["--version-intensity", intensity]

    scripts_expr = _SCRIPTS_EXPR[scripts]
    if scripts_expr is not None:
        flags += [f"--script={scripts_expr}"]

    flags += _SCAN_MODE_FLAGS[scan_mode]
    return flags


__all__ = ["_assemble_flags"]
