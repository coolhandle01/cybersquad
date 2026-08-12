"""
tools/research_vocab.py - Extension-point registries for the Vulnerability
Researcher's ``Finalise Research`` tool docstring.

The agent that drafts the attack plan sees five pieces of vocabulary in
the tool's docstring:

* PROBE_VOCABULARY - the canonical name-shapes a ``probe`` field can take.
* RECON_EVIDENCE_KINDS - the kinds of recon signal the agent should cite
  in ``recon_evidence``.
* Framework vocabulary - the typed ``Framework`` members the agent may
  cite in ``recon_evidence`` ("framework=django") or in ``rationale``.
* Cloud vocabulary - the typed ``Cloud`` members the agent may cite the
  same way ("cloud=aws").
* Service vocabulary - the typed ``Service`` members the agent may cite
  the same way ("service=redis", "service=grafana").

All four are composed into the tool's docstring by ``research_brief_tool``
in ``squad/vulnerability_researcher/__init__.py`` at decoration time,
mirroring the way ``pentest_tool`` weaves OWASP categories from ``@owasp``
into the agent-visible docstring of each pentest tool.

Append-only contract. When a new exploit family lands (issue #88, the typed
``Exploit`` interface), append each canonical ``Exploit.name`` to
PROBE_VOCABULARY. When AttackGraph grows new evidence-bearing fields (issue
#45, OWASP Amass adds ASN/CIDR), append the new kinds to
RECON_EVIDENCE_KINDS. Framework, Cloud, and Service vocabularies are
read live from their StrEnums - new enum members appear in the
docstring automatically.
"""

from __future__ import annotations

from models.cloud import Cloud
from models.framework import Framework
from models.service import Service

ProbeVocabularyEntry = tuple[str, str]  # (name shape, when to use it)
ReconEvidenceKind = tuple[str, str]  # (kind name, where it comes from in recon)


PROBE_VOCABULARY: list[ProbeVocabularyEntry] = [
    (
        "CVE id",
        'a published CVE identifier, e.g. "CVE-2022-22965"',
    ),
    (
        "vulnerability-class",
        'a named class, e.g. "reflected XSS", "SSTI", "SSRF"',
    ),
]


RECON_EVIDENCE_KINDS: list[ReconEvidenceKind] = [
    (
        "host",
        "a hostname or subdomain (recon.subdomains[*], host of endpoints[*].url)",
    ),
    (
        "tech",
        "a technology label (recon.technologies[*], host_insights[*].technologies[*])",
    ),
    (
        "port",
        "an open port number (recon.open_ports[host])",
    ),
    (
        "endpoint",
        "an endpoint URL or path pattern (recon.endpoints[*].url)",
    ),
    (
        "framework",
        'a typed Framework member, e.g. "framework=django"; see Framework vocabulary below',
    ),
    (
        "cloud",
        'a typed Cloud member, e.g. "cloud=aws"; see Cloud vocabulary below',
    ),
    (
        "service",
        'a typed Service member, e.g. "service=redis"; see Service vocabulary below',
    ),
]


def compose_research_brief_doc(base_doc: str) -> str:
    """Append the four vocabulary sections to ``base_doc``.

    Reads the live module-level registries (and the ``Framework`` /
    ``Cloud`` StrEnums) on every call so monkey-patched fixtures and
    future appends are picked up without a re-import. ``base_doc`` is
    right-stripped before the sections are appended so the agent sees
    no trailing whitespace gap.
    """
    # Re-read at call time so test monkey-patches and runtime appends land.
    import tools.research_vocab as _self  # local to dodge the self-cycle

    probe_lines = "\n".join(f"  - {name} - {desc}" for name, desc in _self.PROBE_VOCABULARY)
    evidence_lines = "\n".join(
        f"  - {kind} - {where}" for kind, where in _self.RECON_EVIDENCE_KINDS
    )
    framework_lines = "\n".join(f"  - {f.value}" for f in Framework)
    cloud_lines = "\n".join(f"  - {c.value}" for c in Cloud)
    service_lines = "\n".join(f"  - {s.value}" for s in Service)
    return (
        base_doc.rstrip()
        + "\n\nProbe vocabulary (use one of these shapes for `probe`):\n"
        + probe_lines
        + "\n\nRecon evidence kinds (cite one or more in each `recon_evidence` entry):\n"
        + evidence_lines
        + "\n\nFramework vocabulary (cite as ``framework=<name>`` in `recon_evidence`):\n"
        + framework_lines
        + "\n\nCloud vocabulary (cite as ``cloud=<name>`` in `recon_evidence`):\n"
        + cloud_lines
        + "\n\nService vocabulary (cite as ``service=<name>`` in `recon_evidence`):\n"
        + service_lines
        + "\n"
    )


__all__ = [
    "PROBE_VOCABULARY",
    "RECON_EVIDENCE_KINDS",
    "ProbeVocabularyEntry",
    "ReconEvidenceKind",
    "compose_research_brief_doc",
]
