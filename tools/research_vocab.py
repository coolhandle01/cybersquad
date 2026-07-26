"""
tools/research_vocab.py - Extension-point registries for the Vulnerability
Researcher's ``Finalise Research`` tool docstring.

The agent that drafts the attack plan sees two pieces of vocabulary in the
tool's docstring:

* PROBE_VOCABULARY - the canonical name-shapes a ``probe`` field can take.
* RECON_EVIDENCE_KINDS - the kinds of recon signal the agent should cite
  in ``recon_evidence``.

Both are composed into the tool's docstring by ``research_brief_tool`` in
``squad/vulnerability_researcher/__init__.py`` at decoration time, mirroring
the way ``pentest_tool`` weaves OWASP categories from ``@owasp`` into the
agent-visible docstring of each pentest tool.

Append-only contract. When a new exploit family lands (issue #88, the typed
``Exploit`` interface), append each canonical ``Exploit.name`` to
PROBE_VOCABULARY. When AttackGraph grows new evidence-bearing fields (issue
#45, OWASP Amass adds ASN/CIDR), append the new kinds to
RECON_EVIDENCE_KINDS. No edits to the tool body are needed - the composed
docstring picks them up.
"""

from __future__ import annotations

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
]


def compose_research_brief_doc(base_doc: str) -> str:
    """Append the probe-vocabulary and recon-evidence-kind sections to ``base_doc``.

    Reads the live module-level registries on every call so monkey-patched
    fixtures and future appends are picked up without a re-import. ``base_doc``
    is right-stripped before the sections are appended so the agent sees no
    trailing whitespace gap.
    """
    # Re-read at call time so test monkey-patches and runtime appends land.
    import tools.research_vocab as _self  # local to dodge the self-cycle

    probe_lines = "\n".join(f"  - {name} - {desc}" for name, desc in _self.PROBE_VOCABULARY)
    evidence_lines = "\n".join(
        f"  - {kind} - {where}" for kind, where in _self.RECON_EVIDENCE_KINDS
    )
    return (
        base_doc.rstrip()
        + "\n\nProbe vocabulary (use one of these shapes for `probe`):\n"
        + probe_lines
        + "\n\nRecon evidence kinds (cite one or more in each `recon_evidence` entry):\n"
        + evidence_lines
        + "\n"
    )


__all__ = [
    "PROBE_VOCABULARY",
    "RECON_EVIDENCE_KINDS",
    "ProbeVocabularyEntry",
    "ReconEvidenceKind",
    "compose_research_brief_doc",
]
