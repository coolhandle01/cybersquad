"""
tests/tools/test_report_tools.py - unit tests for tools/report_tools.py.

Coverage targets the four primitive layers the Technical Author depends on:

* CVSS scoring (calculate_cvss_score)
* Evidence sanitisation (sanitise_evidence)
* Draft validation (validate_draft)
* Draft persistence and finalisation (save_draft / finalise_drafts)

The DC compatibility surface (save_report) is covered at the end.
"""

from __future__ import annotations

import json

import pytest

from models import Severity, VerifiedVulnerability
from tools.report_tools import (
    FinalisationError,
    ReportDraft,
    calculate_cvss_score,
    finalise_drafts,
    load_drafts,
    render_draft_markdown,
    sanitise_evidence,
    save_draft,
    save_report,
    validate_draft,
)

pytestmark = pytest.mark.unit


# Sanitisation


class TestSanitiseEvidence:
    def test_preserves_xss_payload(self):
        text = "<script>alert(document.cookie)</script>"
        report = sanitise_evidence(text)
        assert "<script>alert(document.cookie)</script>" in report.sanitised
        assert report.redactions == []

    def test_redacts_authorization_header(self):
        text = "GET / HTTP/1.1\nAuthorization: Bearer abc.def.ghi\n"
        report = sanitise_evidence(text)
        assert "Bearer abc.def.ghi" not in report.sanitised
        assert "Authorization: <redacted>" in report.sanitised
        kinds = {r["kind"] for r in report.redactions}
        assert "authorization_header" in kinds

    def test_redacts_cookie_header(self):
        text = "Cookie: session=abc; csrf=xyz"
        report = sanitise_evidence(text)
        assert "session=abc" not in report.sanitised
        assert "Cookie: <redacted>" in report.sanitised

    def test_redacts_set_cookie(self):
        text = "Set-Cookie: session=abcd; HttpOnly"
        report = sanitise_evidence(text)
        assert "session=abcd" not in report.sanitised
        assert "Set-Cookie: <redacted>" in report.sanitised

    def test_redacts_bearer_outside_header(self):
        text = "curl -H 'Auth: Bearer abcdefghijklmnop'"
        report = sanitise_evidence(text)
        assert "Bearer abcdefghijklmnop" not in report.sanitised
        assert "Bearer <redacted>" in report.sanitised

    def test_redacts_jwt(self):
        # Three dot-separated base64 segments beginning ``eyJ`` (canonical JWT
        # header start).
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij"
        report = sanitise_evidence(f"token={jwt}")
        assert jwt not in report.sanitised

    def test_redacts_aws_access_key(self):
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        report = sanitise_evidence(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in report.sanitised
        kinds = {r["kind"] for r in report.redactions}
        assert "aws_access_key" in kinds

    def test_redacts_secret_kv(self):
        text = "password=hunter2 api_key=sk-livesecretvaluexx"
        report = sanitise_evidence(text)
        assert "hunter2" not in report.sanitised
        assert "sk-livesecretvaluexx" not in report.sanitised

    def test_truncates_long_text(self):
        report = sanitise_evidence("X" * 5000, limit=2000)
        assert len(report.sanitised) < 5000
        assert report.warnings
        assert "truncated" in report.warnings[0]

    def test_empty_input_returns_clean(self):
        report = sanitise_evidence("")
        assert report.sanitised == ""
        assert report.redactions == []
        assert report.warnings == []


# CVSS


class TestCalculateCvssScore:
    def test_known_vector_critical(self):
        assert calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8

    def test_known_vector_medium(self):
        assert calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1

    def test_known_vector_low(self):
        assert calculate_cvss_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N") == 3.1

    def test_zero_impact_returns_zero(self):
        assert calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0

    def test_version_30_accepted(self):
        assert calculate_cvss_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8

    # The three reject cases assert the boundary contract the recompute call
    # sites rely on: a bad vector surfaces as ``ValueError``. The match pins the
    # wrapper's stable prefix, not the underlying ``cvss`` library's wording.
    def test_malformed_version_raises(self):
        with pytest.raises(ValueError, match="invalid CVSS vector"):
            calculate_cvss_score("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C")

    def test_missing_metric_raises(self):
        with pytest.raises(ValueError, match="invalid CVSS vector"):
            calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

    def test_malformed_component_raises(self):
        with pytest.raises(ValueError, match="invalid CVSS vector"):
            calculate_cvss_score("CVSS:3.1/AV:N/BADCOMPONENT/PR:N/UI:N/S:U/C:H/I:H/A:H")


# Draft fixtures


def _good_draft(target_apex: str, **overrides) -> ReportDraft:
    base: dict = {
        "finding_index": 0,
        "target": f"https://api.{target_apex}/search",
        "vuln_class": "SQLi",
        "severity": Severity.HIGH,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "cwe_id": 89,
        "title": "SQL Injection in /search?q allows full database extraction",
        "summary": (
            "The /search endpoint concatenates the q parameter directly into a "
            "SELECT statement. An unauthenticated attacker can exfiltrate the "
            "entire database, including hashed passwords."
        ),
        "description": (
            "The handler at routes/search.py builds the SQL by string concatenation: "
            "`SELECT * FROM products WHERE name LIKE '%' + q + '%'`. There is no "
            "parameterisation and no allow-list. Any attacker can inject arbitrary SQL "
            "via the q querystring parameter and extract arbitrary tables."
        ),
        "steps_to_reproduce": [
            f"Issue GET https://api.{target_apex}/search?q=test' UNION SELECT 1,2,3-- ",
            "Observe the response includes the union'd rows alongside legitimate data.",
        ],
        "evidence": 'HTTP/1.1 200 OK\n\n[{"username":"alice"}]',
        "impact": (
            "An unauthenticated attacker can dump the entire users table, including "
            "bcrypt password hashes and email addresses, enabling offline cracking "
            "and account takeover of every user."
        ),
        "remediation": (
            "Use parameterised queries via the ORM driver. See the OWASP SQL "
            "Injection Prevention Cheat Sheet: "
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ),
    }
    base.update(overrides)
    return ReportDraft(**base)


# Validation


class TestValidateDraft:
    def test_clean_draft_passes(self, target_apex):
        report = validate_draft(_good_draft(target_apex))
        assert report.ok is True
        assert report.issues == []

    def test_empty_title_errors(self, target_apex):
        report = validate_draft(_good_draft(target_apex, title=""))
        assert report.ok is False
        assert any(i.section == "title" and "empty" in i.message for i in report.issues)

    def test_title_without_formula_errors(self, target_apex):
        report = validate_draft(_good_draft(target_apex, title="SQL injection bug"))
        assert report.ok is False
        assert any(i.section == "title" and "does not match" in i.message for i in report.issues)

    def test_thin_description_errors(self, target_apex):
        report = validate_draft(_good_draft(target_apex, description="Too short."))
        assert report.ok is False
        assert any(i.section == "description" for i in report.issues)

    def test_single_step_errors(self, target_apex):
        report = validate_draft(
            _good_draft(target_apex, steps_to_reproduce=["only one step that is long enough"])
        )
        assert report.ok is False
        assert any(i.section == "steps_to_reproduce" for i in report.issues)

    def test_hand_wavy_impact_errors(self, target_apex):
        report = validate_draft(
            _good_draft(target_apex, impact="An attacker could compromise user data of the system.")
        )
        assert report.ok is False
        assert any(i.section == "impact" and "hand-wavy" in i.message for i in report.issues)

    def test_remediation_without_url_errors(self, target_apex):
        report = validate_draft(
            _good_draft(
                target_apex, remediation="Use parameterised queries throughout the codebase."
            )
        )
        assert report.ok is False
        assert any(i.section == "remediation" for i in report.issues)

    def test_unsanitised_evidence_errors(self, target_apex):
        bad = _good_draft(
            target_apex, evidence="Authorization: Bearer leaked.token.here\nGET / HTTP/1.1\n"
        )
        report = validate_draft(bad)
        assert report.ok is False
        assert any(i.section == "evidence" for i in report.issues)

    def test_cvss_score_mismatch_errors(self, target_apex):
        # vector computes to 9.8 but score claims 5.0
        bad = _good_draft(target_apex, cvss_score=5.0)
        report = validate_draft(bad)
        assert report.ok is False
        assert any(i.section == "cvss" for i in report.issues)

    def test_unknown_cwe_warns(self, target_apex):
        # warning, not error
        report = validate_draft(_good_draft(target_apex, cwe_id=99999))
        assert any(i.section == "cwe" and i.severity == "warning" for i in report.issues)
        # still ok since only warning
        assert report.ok is True


# Rendering


class TestRenderDraftMarkdown:
    def test_contains_title(self, target_apex):
        md = render_draft_markdown(_good_draft(target_apex))
        assert "/search?q allows full database extraction" in md

    def test_contains_cwe_name(self, target_apex):
        md = render_draft_markdown(_good_draft(target_apex))
        # The name is sourced from the MITRE corpus (cwe2), not a hand-written
        # short label, so assert the id plus the canonical short form MITRE
        # embeds in CWE-89's name ("...('SQL Injection')") rather than pinning
        # the full verbose name string.
        assert "CWE-89" in md
        assert "SQL Injection" in md

    def test_steps_are_numbered(self, target_apex):
        md = render_draft_markdown(_good_draft(target_apex))
        assert "1. " in md
        assert "2. " in md

    def test_evidence_block_present(self, target_apex):
        md = render_draft_markdown(_good_draft(target_apex))
        assert "HTTP/1.1 200 OK" in md


# Persistence


class TestSaveAndLoadDraft:
    def test_save_writes_indexed_file(self, run_dir, target_apex):
        path = save_draft(_good_draft(target_apex, finding_index=2))
        assert path == run_dir / "drafts" / "002.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["finding_index"] == 2

    def test_load_drafts_orders_by_index(self, run_dir, target_apex):
        save_draft(_good_draft(target_apex, finding_index=1))
        save_draft(_good_draft(target_apex, finding_index=0))
        drafts = load_drafts()
        assert [d.finding_index for d in drafts] == [0, 1]

    def test_load_drafts_empty_when_no_dir(self, run_dir):
        assert load_drafts() == []


# Finalisation


class TestFinaliseDrafts:
    def test_writes_reports_json_for_clean_drafts(self, run_dir, target_apex):
        save_draft(_good_draft(target_apex, finding_index=0))
        path = finalise_drafts("test-programme", "Summary line.", expected_count=1)
        assert path == run_dir / "reports.json"
        contents = json.loads(path.read_text())
        assert len(contents) == 1
        assert contents[0]["programme_handle"] == "test-programme"

    def test_refuses_when_drafts_missing(self, run_dir, target_apex):
        save_draft(_good_draft(target_apex, finding_index=0))
        with pytest.raises(FinalisationError, match="expected 2 drafts, found 1"):
            finalise_drafts("test-programme", "Summary.", expected_count=2)

    def test_refuses_on_validation_errors(self, run_dir, target_apex):
        save_draft(_good_draft(target_apex, finding_index=0, title="bad title"))
        with pytest.raises(FinalisationError, match="unresolved errors"):
            finalise_drafts("test-programme", "Summary.", expected_count=1)


# DC compatibility


class TestSaveReport:
    def test_creates_file(self, disclosure_report, tmp_path, monkeypatch):
        monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
        import importlib

        import config as cfg

        importlib.reload(cfg)
        import tools.report_tools as rt

        rt.config = cfg.AppConfig()

        path = save_report(disclosure_report)
        assert path.exists()
        assert path.suffix == ".md"

    def test_filename_contains_handle(self, disclosure_report, tmp_path, monkeypatch):
        monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
        import importlib

        import config as cfg

        importlib.reload(cfg)
        import tools.report_tools as rt

        rt.config = cfg.AppConfig()

        path = save_report(disclosure_report)
        assert "test-programme" in path.name


# Helper: verified-finding round-trip


class TestVerifiedRoundTrip:
    def test_load_verified(self, tmp_path, verified_vuln: VerifiedVulnerability):
        from tools.report_tools import load_verified

        path = tmp_path / "verified.json"
        path.write_text(json.dumps([verified_vuln.model_dump(mode="json")]))
        loaded = load_verified(path)
        assert len(loaded) == 1
        assert loaded[0].vuln_class == verified_vuln.vuln_class
