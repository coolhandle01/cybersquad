"""Httpx (ProjectDiscovery) orchestration package.

Public surface re-exported here so callers continue to do
``from tools.recon.httpx import httpx_scan, probe_endpoints`` after the
single-file -> package split.

Wraps the ``httpx`` **CLI binary** that ProjectDiscovery ships - **not**
the PyPI ``httpx`` HTTP library. The Python HTTP library used throughout
cybersquad is ``requests``; the OS-level binary is what we shell out to
here. No actual masking risk - no code anywhere does ``import httpx``,
and Python 3 absolute imports do not search the local package first.
If we ever DO need the PyPI lib in this package, prefer
``import httpx as _httpx_lib`` to make intent explicit.

Internal layout splits the orchestration across three files (same
pattern as ``tools/recon/nmap/``):

* ``flags`` - mode -> flag-bundle composition + the orthogonal
  ``with_screenshots`` / ``with_responses`` toggles. No I/O.
* ``parser`` - ``_parse_ndjson`` - NDJSON lines -> ``list[Endpoint]``.
  Defensive; degrades a row's optional fields rather than dropping it
  on the floor.
* ``scanner`` - ``httpx_scan`` (the rich entry point returning
  ``HttpxScanResult``) + ``probe_endpoints`` (the backwards-compat shim
  returning ``list[Endpoint]``) + the evidence-dir resolution helpers.

LLM-facing typed shapes (``HttpxMode``, ``HttpxScanResult``) live in
``models/scanner.py`` because they cross the agent boundary. The
dependency direction is one-way (``tools.recon.httpx.*`` imports from
``models.scanner``, never the reverse).
"""

from __future__ import annotations

from tools.recon.httpx.scanner import httpx_scan, probe_endpoints

__all__ = ["httpx_scan", "probe_endpoints"]
