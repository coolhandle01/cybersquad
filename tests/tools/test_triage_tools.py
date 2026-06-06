"""
tests/tools/test_triage_tools.py - unit tests for tools/triage_tools.py.

Coverage targets the four primitive layers the Vulnerability Researcher
depends on:

* Severity / scope gates (above_floor, in_scope)
* Per-finding validation (validate_assessment)
* Draft persistence (save_assessment, save_discard, mutual eviction)
* Finalisation (finalise_triage)
"""

from __future__ import annotations

import json

import pytest

from models import RawFinding, Severity, VerifiedVulnerability
from tools.triage_tools import (
    DiscardEntry,
    DiscardReason,
    SeverityDecision,
    TriageAssessment,
    TriageFinalisationError,
    finalise_triage,
    in_scope,
    load_assessments,
    load_discards,
    save_assessment,
    save_discard,
    validate_assessment,
)

pytestmark = pytest.mark.unit


# Severity / scope gates


class TestAboveFloor:
    """The floor reads ``config.scan.min_severity`` at call time, so swap the
    underlying ScanConfig rather than reloading the module - reloading replaces
    class identities (TriageAssessment, TriageFinalisationError, ...) and
    breaks other tests' isinstance / pytest.raises matching."""

    def _floor_at(self, monkeypatch, floor: Severity) -> None:
        from tools import triage_tools

        original_scan = triage_tools.config.scan

        class _Scan:
            def __getattr__(self, name):
                if name == "min_severity":
                    return floor.value
                return getattr(original_scan, name)

        monkeypatch.setattr(triage_tools.config, "scan", _Scan())

    def test_high_above_low_floor(self, monkeypatch):
        from tools.triage_tools import above_floor

        self._floor_at(monkeypatch, Severity.LOW)
        assert above_floor(Severity.HIGH) is True

    def test_low_below_medium_floor(self, monkeypatch):
        from tools.triage_tools import above_floor

        self._floor_at(monkeypatch, Severity.MEDIUM)
        assert above_floor(Severity.LOW) is False


class TestInScope:
    def test_in_scope(self, programme, target_url):
        assert in_scope(f"{target_url}/x", programme) is True

    def test_out_of_scope(self, programme, bystander_url):
        assert in_scope(f"{bystander_url}/x", programme) is False


# Fixtures


def _good_assessment(raw: RawFinding, target_apex: str, **overrides) -> TriageAssessment:
    base: dict = {
        "finding_index": 0,
        "target": raw.target,
        "vuln_class": raw.vuln_class,
        "severity_hint": raw.severity_hint,
        "severity_decision": SeverityDecision.KEEP,
        "severity": raw.severity_hint,
        "severity_rationale": (
            "Unauthenticated SQLi at a public endpoint with full DB read - "
            "blast radius is every row in users table."
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "title": "SQL Injection in /search?q allows full database extraction",
        "description": (
            "The /search endpoint concatenates the q parameter directly into a "
            "SELECT statement without parameterisation. sqlmap exploited classic "
            "UNION-based injection to extract arbitrary rows from the users table."
        ),
        "steps_to_reproduce": [
            f"GET https://api.{target_apex}/search?q=test' UNION SELECT 1,2,3-- ",
            "Observe the response body returns the union'd rows alongside legitimate hits.",
        ],
        "impact": (
            "An unauthenticated attacker dumps the entire users table including "
            "bcrypt hashes and emails, enabling offline cracking and full "
            "account takeover."
        ),
        "remediation": (
            "Use parameterised queries throughout. See "
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ),
    }
    base.update(overrides)
    if "severity" in overrides or "severity_hint" in overrides:
        # severity_decision must agree with the severity vs severity_hint relation
        if base["severity"] != base["severity_hint"]:
            base.setdefault("severity_decision", SeverityDecision.RAISE)
    return TriageAssessment(**base)


@pytest.fixture
def in_scope_raw(target_apex) -> RawFinding:
    return RawFinding(
        title=f"SQL Injection - https://api.{target_apex}/search",
        vuln_class="SQLi",
        target=f"https://api.{target_apex}/search",
        evidence="sqlmap detected injection at parameter q",
        tool="sqlmap",
        severity_hint=Severity.HIGH,
    )


@pytest.fixture
def oos_raw(bystander_url) -> RawFinding:
    return RawFinding(
        title="Header issue",
        vuln_class="Headers",
        target=f"{bystander_url}/x",
        evidence="missing X-Frame-Options",
        tool="nuclei",
        severity_hint=Severity.HIGH,
    )


# Validation


class TestValidateAssessment:
    def test_clean_assessment_passes(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(in_scope_raw, target_apex)
        report = validate_assessment(a, in_scope_raw, programme)
        assert report.ok is True
        assert all(i.severity != "error" for i in report.issues)

    def test_rejects_target_rewrite(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(
            in_scope_raw, target_apex, target=f"https://api.{target_apex}/different"
        )
        report = validate_assessment(a, in_scope_raw, programme)
        assert report.ok is False
        assert any(i.section == "target" and "do not rewrite" in i.message for i in report.issues)

    def test_rejects_vuln_class_rewrite(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(in_scope_raw, target_apex, vuln_class="SomethingElse")
        report = validate_assessment(a, in_scope_raw, programme)
        assert report.ok is False
        assert any(i.section == "vuln_class" for i in report.issues)

    def test_rejects_out_of_scope_target(self, oos_raw, programme, target_apex):
        a = _good_assessment(oos_raw, target_apex)
        report = validate_assessment(a, oos_raw, programme)
        assert report.ok is False
        assert any(
            i.section == "target" and "out of programme scope" in i.message for i in report.issues
        )

    def test_rejects_below_floor(self, in_scope_raw, programme, monkeypatch, target_apex):
        # Below-LOW: with default floor (low), informational is below.
        a = _good_assessment(
            in_scope_raw,
            target_apex,
            severity=Severity.INFORMATIONAL,
            severity_hint=Severity.INFORMATIONAL,
            severity_decision=SeverityDecision.KEEP,
        )
        # Need raw to match severity_hint
        raw = in_scope_raw.model_copy(update={"severity_hint": Severity.INFORMATIONAL})
        report = validate_assessment(a, raw, programme)
        assert any(i.section == "severity" for i in report.issues)

    def test_rejects_keep_with_mismatched_severity(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(
            in_scope_raw,
            target_apex,
            severity=Severity.CRITICAL,
            severity_decision=SeverityDecision.KEEP,
        )
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(i.section == "severity_decision" for i in report.issues)

    def test_rejects_raise_with_same_severity(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(in_scope_raw, target_apex, severity_decision=SeverityDecision.RAISE)
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(i.section == "severity_decision" for i in report.issues)

    def test_rejects_thin_severity_rationale(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(in_scope_raw, target_apex, severity_rationale="too short")
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(i.section == "severity_rationale" for i in report.issues)

    def test_rejects_stale_description(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(
            in_scope_raw,
            target_apex,
            description=f"Automated detection of SQLi at https://api.{target_apex}/search.",
        )
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(i.section == "description" and "boilerplate" in i.message for i in report.issues)

    def test_rejects_thin_description(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(in_scope_raw, target_apex, description="Too short.")
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(i.section == "description" for i in report.issues)

    def test_rejects_hand_wavy_impact(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(
            in_scope_raw,
            target_apex,
            impact="An attacker could compromise user data of various kinds in this app.",
        )
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(i.section == "impact" and "hand-wavy" in i.message for i in report.issues)

    def test_rejects_stale_impact_placeholder(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(
            in_scope_raw,
            target_apex,
            impact="Potential SQLi impact - pending manual review by the team here.",
        )
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(
            i.section == "impact" and "pending manual review" in i.message for i in report.issues
        )

    def test_rejects_remediation_without_url(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(
            in_scope_raw,
            target_apex,
            remediation="Use parameterised queries throughout the codebase.",
        )
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(i.section == "remediation" for i in report.issues)

    def test_rejects_stale_step_placeholder(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(
            in_scope_raw,
            target_apex,
            steps_to_reproduce=[
                f"GET https://api.{target_apex}/search?q=test' UNION SELECT 1,2,3-- ",
                "Observe the following evidence:",
            ],
        )
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(
            i.section == "steps_to_reproduce" and "placeholder" in i.message for i in report.issues
        )

    def test_rejects_cvss_mismatch(self, in_scope_raw, programme, target_apex):
        a = _good_assessment(in_scope_raw, target_apex, cvss_score=5.0)
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(i.section == "cvss" and i.severity == "error" for i in report.issues)

    def test_warns_when_cvss_band_disagrees_with_severity(
        self, in_scope_raw, programme, target_apex
    ):
        # Vector computes to 9.8 (critical) but severity says HIGH (keep matches hint)
        a = _good_assessment(in_scope_raw, target_apex)
        report = validate_assessment(a, in_scope_raw, programme)
        assert any(
            i.section == "cvss" and i.severity == "warning" and "implies severity" in i.message
            for i in report.issues
        )


# Persistence


class TestPersistence:
    def test_save_assessment_writes_indexed_file(self, in_scope_raw, run_dir, target_apex):
        path = save_assessment(_good_assessment(in_scope_raw, target_apex, finding_index=4))
        assert path == run_dir / "assessments" / "004.json"
        assert path.exists()

    def test_save_discard_writes_indexed_file(self, in_scope_raw, run_dir):
        d = DiscardEntry(
            finding_index=2,
            target=in_scope_raw.target,
            vuln_class=in_scope_raw.vuln_class,
            severity_hint=in_scope_raw.severity_hint,
            reason=DiscardReason.FALSE_POSITIVE,
            rationale="Tool fired but evidence does not demonstrate exploitability.",
        )
        path = save_discard(d)
        assert path == run_dir / "discards" / "002.json"

    def test_assessment_evicts_discard(self, in_scope_raw, run_dir, target_apex):
        # First discard, then change mind and assess
        d = DiscardEntry(
            finding_index=1,
            target=in_scope_raw.target,
            vuln_class=in_scope_raw.vuln_class,
            severity_hint=in_scope_raw.severity_hint,
            reason=DiscardReason.FALSE_POSITIVE,
            rationale="Initial review thought this was noise.",
        )
        save_discard(d)
        save_assessment(_good_assessment(in_scope_raw, target_apex, finding_index=1))
        assert not (run_dir / "discards" / "001.json").exists()
        assert (run_dir / "assessments" / "001.json").exists()

    def test_discard_evicts_assessment(self, in_scope_raw, run_dir, target_apex):
        save_assessment(_good_assessment(in_scope_raw, target_apex, finding_index=1))
        d = DiscardEntry(
            finding_index=1,
            target=in_scope_raw.target,
            vuln_class=in_scope_raw.vuln_class,
            severity_hint=in_scope_raw.severity_hint,
            reason=DiscardReason.NON_EXPLOITABLE,
            rationale="On second look, requires admin auth that no user holds.",
        )
        save_discard(d)
        assert (run_dir / "discards" / "001.json").exists()
        assert not (run_dir / "assessments" / "001.json").exists()


# Finalisation


class TestFinaliseTriage:
    def test_writes_verified_json_for_clean_assessments(
        self, in_scope_raw, run_dir, programme, target_apex
    ):
        save_assessment(_good_assessment(in_scope_raw, target_apex, finding_index=0))
        path = finalise_triage(programme, [in_scope_raw])
        assert path == run_dir / "verified.json"
        verified = json.loads(path.read_text())
        assert len(verified) == 1
        assert verified[0]["target"] == in_scope_raw.target

    def test_refuses_unprocessed_findings(self, in_scope_raw, run_dir, programme, target_apex):
        save_assessment(_good_assessment(in_scope_raw, target_apex, finding_index=0))
        with pytest.raises(TriageFinalisationError, match=r"\[1\] have no assessment"):
            finalise_triage(programme, [in_scope_raw, in_scope_raw])

    def test_refuses_on_validation_errors(self, in_scope_raw, run_dir, programme, target_apex):
        save_assessment(
            _good_assessment(in_scope_raw, target_apex, finding_index=0, description="Too short.")
        )
        with pytest.raises(TriageFinalisationError, match="unresolved errors"):
            finalise_triage(programme, [in_scope_raw])

    def test_discards_only_yields_empty_verified(self, in_scope_raw, run_dir, programme):
        save_discard(
            DiscardEntry(
                finding_index=0,
                target=in_scope_raw.target,
                vuln_class=in_scope_raw.vuln_class,
                severity_hint=in_scope_raw.severity_hint,
                reason=DiscardReason.FALSE_POSITIVE,
                rationale="Confirmed false positive after manual reproduction.",
            )
        )
        path = finalise_triage(programme, [in_scope_raw])
        verified = json.loads(path.read_text())
        assert verified == []

    def test_builds_verified_vulnerability(self, in_scope_raw, run_dir, programme, target_apex):
        save_assessment(_good_assessment(in_scope_raw, target_apex, finding_index=0))
        finalise_triage(programme, [in_scope_raw])
        verified = load_assessments()
        assert verified[0].finding_index == 0

    def test_carries_raw_evidence_into_verified(
        self, in_scope_raw, run_dir, programme, target_apex
    ):
        # The VR's authored fields go into description/impact/remediation; the
        # evidence belongs to the PT and is carried through untouched (the TA
        # sanitises it later).
        save_assessment(_good_assessment(in_scope_raw, target_apex, finding_index=0))
        path = finalise_triage(programme, [in_scope_raw])
        loaded = [VerifiedVulnerability.model_validate(v) for v in json.loads(path.read_text())]
        assert loaded[0].evidence == in_scope_raw.evidence


# Discard entry validity


class TestDiscardEntry:
    def test_serialises_round_trip(self, in_scope_raw):
        d = DiscardEntry(
            finding_index=3,
            target=in_scope_raw.target,
            vuln_class=in_scope_raw.vuln_class,
            severity_hint=in_scope_raw.severity_hint,
            reason=DiscardReason.OUT_OF_SCOPE,
            rationale="FQDN not in structured scope; test asset belonging to vendor.",
        )
        again = DiscardEntry.model_validate_json(d.model_dump_json())
        assert again.reason == DiscardReason.OUT_OF_SCOPE


# Helper: load_discards


class TestLoadDiscards:
    def test_returns_empty_when_no_dir(self, run_dir):
        assert load_discards() == []


# The `programme` and `target_url` / `bystander_url` fixtures come from
# tests/conftest.py - the shared `programme` includes `*.example.com` which
# covers `target_url` (https://victim.example.com), and `bystander_url`
# (https://bystander.example.org) sits cleanly outside it for the scope-guard
# tests.
