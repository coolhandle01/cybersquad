"""Nmap XML output parser.

``_parse_xml(xml_text) -> list[NmapHostResult]`` is the only public
function. Uses ``defusedxml.ElementTree`` (security-hardened parser,
already in the dep chain via the XXE probe) rather than stdlib
``xml.etree`` to avoid XXE / billion-laughs surface.

Defensive throughout - skips hosts / ports / services with mis-shaped
fields rather than failing the whole scan. Real-world runs occasionally
produce truncated output (timeout mid-scan, host going down mid-probe)
and the parser should land what's parseable rather than reject the lot.

Each ``<service>``'s ``<cpe>`` children (the NIST product identifier nmap
matched) are normalised to the CPE 2.3 formatted string via ``tools.cpe``
and carried on the ``NmapService``.
"""

from __future__ import annotations

import logging

from defusedxml import ElementTree as ET

from models.scanner import NmapHostResult, NmapService
from tools.cpe import pick_application_cpe

logger = logging.getLogger(__name__)


def _parse_xml(xml_text: str) -> list[NmapHostResult]:
    """Parse nmap's XML output into ``NmapHostResult`` rows.

    Defensive - skips hosts / ports / services with mis-shaped fields
    rather than failing the whole scan. Nmap's XML format is stable
    (the DTD has not changed materially since nmap 5.x), but real-world
    runs occasionally produce truncated output (timeout mid-scan, host
    going down mid-probe).
    """
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("nmap XML parse failed: %s", exc)
        return []

    results: list[NmapHostResult] = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        host_addr = addr_el.get("addr")
        if not host_addr:
            continue

        services: list[NmapService] = []
        for port_el in host_el.findall("ports/port"):
            try:
                port_num = int(port_el.get("portid") or "")
            except ValueError:
                continue
            protocol = port_el.get("protocol") or "tcp"
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"

            svc_el = port_el.find("service")
            service_name = svc_el.get("name") if svc_el is not None else None
            product = svc_el.get("product") if svc_el is not None else None
            version = svc_el.get("version") if svc_el is not None else None
            extra = svc_el.get("extrainfo") if svc_el is not None else None
            # nmap's per-match confidence (1-10); absent / non-numeric -> 0.
            conf_attr = svc_el.get("conf") if svc_el is not None else None
            conf = int(conf_attr) if conf_attr and conf_attr.isdigit() else 0
            # nmap emits one or more ``<cpe>`` children (2.2 URI binding) per
            # service when -sV matches; prefer the application CPE and
            # normalise to the 2.3 formatted string.
            cpe_raws = (
                [el.text for el in svc_el.findall("cpe") if el.text] if svc_el is not None else []
            )
            service_cpe = pick_application_cpe(cpe_raws)

            try:
                services.append(
                    NmapService(
                        port=port_num,
                        protocol=protocol,
                        state=state or "unknown",
                        service=service_name,
                        product=product,
                        version=version,
                        extra_info=extra,
                        cpe=service_cpe,
                        conf=conf,
                    )
                )
            except ValueError as exc:
                logger.debug("nmap port row skipped: %s", exc)
                continue

        try:
            results.append(
                NmapHostResult(
                    host=host_addr,
                    services=services,
                )
            )
        except ValueError as exc:
            logger.debug("nmap host row skipped (addr %s): %s", host_addr, exc)
            continue
    return results


__all__ = ["_parse_xml"]
