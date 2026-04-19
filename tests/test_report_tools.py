"""
tests/test_report_tools.py — unit tests for tools/report_tools.py
"""

from __future__ import annotations

import pytest

from tools.report_tools import (
    _VULN_CLASS_TO_CWE,
    build_report_markdown,
    create_disclosure_report,
    save_report,
)

pytestmark = pytest.mark.unit


class TestCweMapping:
    def test_sqli_maps_to_cwe_89(self):
        assert _VULN_CLASS_TO_CWE["SQLi"] == 89

    def test_xss_maps_to_cwe_79(self):
        assert _VULN_CLASS_TO_CWE["XSS"] == 79

    def test_cors_maps_to_cwe_942(self):
        assert _VULN_CLASS_TO_CWE["CORS"] == 942

    def test_ssrf_maps_to_cwe_918(self):
        assert _VULN_CLASS_TO_CWE["SSRF"] == 918


class TestBuildReportMarkdown:
    def test_contains_title(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Test summary.")
        assert verified_vuln.title in md

    def test_contains_summary(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "My executive summary.")
        assert "My executive summary." in md

    def test_contains_cvss_score(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Summary.")
        assert str(verified_vuln.cvss_score) in md

    def test_contains_cvss_vector(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Summary.")
        assert verified_vuln.cvss_vector in md

    def test_contains_cwe(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Summary.")
        assert "CWE-89" in md

    def test_contains_reproduction_steps(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Summary.")
        for step in verified_vuln.steps_to_reproduce:
            assert step in md

    def test_steps_are_numbered(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Summary.")
        assert "1." in md
        assert "2." in md

    def test_contains_target(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Summary.")
        assert verified_vuln.target in md

    def test_contains_severity_label(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Summary.")
        assert "High" in md

    def test_evidence_truncated_to_2000_chars(self, verified_vuln):
        long_vuln = verified_vuln.model_copy(update={"evidence": "X" * 5000})
        md = build_report_markdown("test-programme", long_vuln, "Summary.")
        assert md.count("X") <= 2000

    def test_timestamp_present(self, verified_vuln):
        md = build_report_markdown("test-programme", verified_vuln, "Summary.")
        assert "UTC" in md


class TestCreateDisclosureReport:
    def test_returns_disclosure_report(self, verified_vuln):
        from models import DisclosureReport

        report = create_disclosure_report("test-programme", verified_vuln, "Summary.")
        assert isinstance(report, DisclosureReport)

    def test_programme_handle_set(self, verified_vuln):
        report = create_disclosure_report("test-programme", verified_vuln, "Summary.")
        assert report.programme_handle == "test-programme"

    def test_weakness_id_from_vuln_class(self, verified_vuln):
        report = create_disclosure_report("test-programme", verified_vuln, "Summary.")
        assert report.weakness_id == 89

    def test_body_markdown_is_nonempty(self, verified_vuln):
        report = create_disclosure_report("test-programme", verified_vuln, "Summary.")
        assert len(report.body_markdown) > 100

    def test_impact_statement_from_vuln(self, verified_vuln):
        report = create_disclosure_report("test-programme", verified_vuln, "Summary.")
        assert report.impact_statement == verified_vuln.impact

    def test_unknown_vuln_class_weakness_id_is_none(self, verified_vuln):
        unknown_vuln = verified_vuln.model_copy(update={"vuln_class": "WeirdCustomVuln"})
        report = create_disclosure_report("test-programme", unknown_vuln, "Summary.")
        assert report.weakness_id is None


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

    def test_file_contains_report_body(self, disclosure_report, tmp_path, monkeypatch):
        monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
        import importlib

        import config as cfg

        importlib.reload(cfg)
        import tools.report_tools as rt

        rt.config = cfg.AppConfig()

        path = save_report(disclosure_report)
        content = path.read_text()
        assert disclosure_report.body_markdown in content

    def test_filename_contains_handle(self, disclosure_report, tmp_path, monkeypatch):
        monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
        import importlib

        import config as cfg

        importlib.reload(cfg)
        import tools.report_tools as rt

        rt.config = cfg.AppConfig()

        path = save_report(disclosure_report)
        assert "test-programme" in path.name
