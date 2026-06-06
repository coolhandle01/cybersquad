"""
tests/tools/test_research_vocab.py - unit tests for tools/research_vocab.py.

The vocab module is two lists plus a small docstring-composition helper. The
agent-visible docstring of ``Finalise Research`` is built from these lists at
decoration time, so the tests guard two contracts:

* The registries carry today's baseline (CVE / vulnerability-class for probes;
  host / tech / port / endpoint for recon evidence). Removing one is a breaking
  change to the agent prompt.
* ``compose_research_brief_doc`` weaves every registered entry into the
  composed docstring, and an appended entry (simulating a future #88 / #45 PR)
  also lands without further edits.
"""

from __future__ import annotations

import pytest

from tools.research_vocab import (
    PROBE_VOCABULARY,
    RECON_EVIDENCE_KINDS,
    compose_research_brief_doc,
)

pytestmark = pytest.mark.unit


# Registry baselines


class TestProbeVocabularyBaseline:
    def test_carries_cve_and_vulnerability_class(self) -> None:
        names = {name for name, _ in PROBE_VOCABULARY}
        assert "CVE id" in names
        assert "vulnerability-class" in names

    def test_every_entry_has_description(self) -> None:
        for name, description in PROBE_VOCABULARY:
            assert name.strip(), "probe vocab entry has empty name"
            assert description.strip(), f"probe vocab entry {name!r} has empty description"


class TestReconEvidenceKindsBaseline:
    def test_carries_host_tech_port_endpoint(self) -> None:
        kinds = {kind for kind, _ in RECON_EVIDENCE_KINDS}
        assert {"host", "tech", "port", "endpoint"} <= kinds

    def test_every_entry_has_description(self) -> None:
        for kind, where in RECON_EVIDENCE_KINDS:
            assert kind.strip(), "recon evidence kind has empty name"
            assert where.strip(), f"recon evidence kind {kind!r} has empty 'where'"


# Composition


class TestComposeResearchBriefDoc:
    def test_appends_both_sections_after_base_doc(self) -> None:
        composed = compose_research_brief_doc("base doc body")
        assert composed.startswith("base doc body")
        assert "Probe vocabulary" in composed
        assert "Recon evidence kinds" in composed
        # Probe section appears before recon section (matches the order the
        # agent fills the dict in).
        assert composed.index("Probe vocabulary") < composed.index("Recon evidence kinds")

    def test_lists_every_probe_vocabulary_entry(self) -> None:
        composed = compose_research_brief_doc("")
        for name, description in PROBE_VOCABULARY:
            assert name in composed
            assert description in composed

    def test_lists_every_recon_evidence_kind(self) -> None:
        composed = compose_research_brief_doc("")
        for kind, where in RECON_EVIDENCE_KINDS:
            assert kind in composed
            assert where in composed

    def test_picks_up_appended_probe_entry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulates #88 landing: a new canonical Exploit name appended to the
        # registry must appear in the composed doc without touching the
        # Finalise Research tool source.
        future_entry = ("ssti-jinja2", "canonical Exploit name from tools/pentest/exploit.py")
        monkeypatch.setattr(
            "tools.research_vocab.PROBE_VOCABULARY",
            [*PROBE_VOCABULARY, future_entry],
        )
        composed = compose_research_brief_doc("")
        assert "ssti-jinja2" in composed

    def test_picks_up_appended_recon_evidence_kind(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulates #45 landing: ASN/CIDR added to AttackGraph and registered
        # here, must appear in the composed doc without touching the Finalise
        # Research tool source.
        future_entry = ("asn", "an AS number from recon.asns[*]")
        monkeypatch.setattr(
            "tools.research_vocab.RECON_EVIDENCE_KINDS",
            [*RECON_EVIDENCE_KINDS, future_entry],
        )
        composed = compose_research_brief_doc("")
        assert "asn" in composed

    def test_strips_trailing_whitespace_on_base_doc(self) -> None:
        # Trailing newlines on the base doc are normalised before the vocab
        # sections are appended, otherwise the agent sees a gap.
        composed = compose_research_brief_doc("base doc\n\n   \n")
        assert "base doc\n\nProbe vocabulary" in composed

    def test_empty_base_doc_still_emits_sections(self) -> None:
        composed = compose_research_brief_doc("")
        assert "Probe vocabulary" in composed
        assert "Recon evidence kinds" in composed
