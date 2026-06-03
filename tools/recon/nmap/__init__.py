"""Nmap orchestration package.

Public surface re-exported here so callers continue to do
``from tools.recon.nmap import nmap_scan, port_scan`` unchanged after
the file -> package split (the historical module was a single file at
``tools/recon/nmap.py``).

Internal layout splits the orchestration across three implementation
files, each tight and individually grep-able:

* ``flags`` - the config-tables layer. ``_MODE_FLAGS`` /
  ``_BANNER_INTENSITY`` / ``_SCRIPTS_EXPR`` / ``_SCAN_MODE_FLAGS`` and
  the ``_assemble_flags(mode, banner, scripts, scan_mode)`` composer.
  No I/O; pure flag-composition logic.
* ``parser`` - ``_parse_xml(xml_text)``. Defusedxml-backed nmap XML ->
  ``list[NmapHostResult]``. Defensive; skips mis-shaped rows.
* ``scanner`` - the imperative orchestrator: ``nmap_scan`` (the rich
  entry point), ``port_scan`` (legacy shim), and the evidence-path
  helpers.

LLM-facing typed shapes (``NmapMode`` / ``NmapBanner`` / ``NmapScripts``
/ ``NmapService`` / ``NmapHostResult`` / ``NmapScanResult``) deliberately
live in ``models/network.py`` (not inside this package). That is the
cybersquad-models convention: typed contracts that cross the agent
boundary live under ``models/``; implementation lives in ``tools/``.
The dependency direction is one-way (``tools.recon.nmap.*`` imports
from ``models.network``, never the reverse) which keeps the layering
non-circular.
"""

from __future__ import annotations

from tools.recon.nmap.scanner import nmap_scan, port_scan
from tools.recon.nmap.service import NmapAssets, services_from_nmap

__all__ = ["NmapAssets", "nmap_scan", "port_scan", "services_from_nmap"]
