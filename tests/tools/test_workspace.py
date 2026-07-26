"""
tests/tools/test_workspace.py - tools/workspace/ helpers.

Covers the two safety invariants: path containment (no escape from
runtime.run_dir()) and correct file reads.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from tools import workspace

pytestmark = pytest.mark.unit


class TestListRunFiles:
    def test_empty_dir(self, run_dir: Path) -> None:
        assert workspace.list_run_files() == []

    def test_missing_dir_returns_empty(self, tmp_path: Path) -> None:
        # ``run_dir`` always returns an existing path; this test wants a
        # non-existent one, so it stays on the explicit ``with patch``.
        absent = tmp_path / "not-yet-created"
        with patch("runtime.run_dir", return_value=absent):
            assert workspace.list_run_files() == []

    def test_lists_files_with_sizes(self, run_dir: Path) -> None:
        (run_dir / "recon.json").write_text("a" * 12, encoding="utf-8")
        (run_dir / "findings.json").write_text("b" * 5, encoding="utf-8")
        result = workspace.list_run_files()
        assert result == [
            {"name": "findings.json", "size_bytes": 5},
            {"name": "recon.json", "size_bytes": 12},
        ]

    def test_recurses_subdirs(self, run_dir: Path) -> None:
        sub = run_dir / "evidence"
        sub.mkdir()
        (sub / "screenshot.txt").write_text("x", encoding="utf-8")
        result = workspace.list_run_files()
        assert result == [{"name": "evidence/screenshot.txt", "size_bytes": 1}]


class TestReadRunFile:
    def test_reads_full_file(self, run_dir: Path) -> None:
        recon_path = run_dir / "recon.json"
        recon_path.write_text("hello world", encoding="utf-8")
        result = workspace.read_run_file("recon.json")
        assert result["content"] == "hello world"
        assert result["size_bytes"] == 11
        assert result["name"] == "recon.json"

    def test_rejects_parent_traversal(self, run_dir: Path) -> None:
        with pytest.raises(ValueError, match=r"must not contain '\.\.'"):
            workspace.read_run_file("../secret.txt")

    def test_rejects_absolute_path(self, run_dir: Path) -> None:
        with pytest.raises(ValueError, match="must be relative, not absolute"):
            workspace.read_run_file("/etc/passwd")

    def test_rejects_empty_path(self, run_dir: Path) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            workspace.read_run_file("")

    def test_rejects_symlink_escape(self, run_dir: Path) -> None:
        # Belt-and-braces: the shape check above only inspects the input.
        # A symlink inside run_dir pointing outside passes the shape check,
        # so the resolve-and-verify step has to catch it.
        outside = run_dir.parent / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        try:
            (run_dir / "link").symlink_to(outside)
            with pytest.raises(ValueError, match="resolves outside the run directory"):
                workspace.read_run_file("link")
        finally:
            outside.unlink()

    def test_missing_file_raises(self, run_dir: Path) -> None:
        with pytest.raises(FileNotFoundError):
            workspace.read_run_file("nope.json")
