"""tests/test_approval.py — unit tests for the approval gate and callback."""

from __future__ import annotations

import pytest

from tools.approval import (
    ApprovalDecision,
    ApprovalGate,
    CliApprovalGate,
    PipelineHalted,
    make_approval_callback,
)

pytestmark = pytest.mark.unit


def _approving_gate() -> ApprovalGate:
    class _Gate(ApprovalGate):
        def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
            return ApprovalDecision(approved=True, reason="approved")

    return _Gate()


def _rejecting_gate(reason: str = "denied") -> ApprovalGate:
    class _Gate(ApprovalGate):
        def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
            return ApprovalDecision(approved=False, reason=reason)

    return _Gate()


class TestCliApprovalGate:
    def test_approves_on_y(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = CliApprovalGate()
        responses = iter(["y", "looks good"])
        monkeypatch.setattr("builtins.input", lambda *_: next(responses))
        decision = gate.request("test", "summary")
        assert decision.approved is True
        assert "looks good" in decision.reason

    def test_approves_with_empty_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = CliApprovalGate()
        responses = iter(["y", ""])
        monkeypatch.setattr("builtins.input", lambda *_: next(responses))
        decision = gate.request("test", "summary")
        assert decision.approved is True
        assert decision.reason  # falls back to default text

    def test_rejects_on_n(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = CliApprovalGate()
        responses = iter(["n", "too risky"])
        monkeypatch.setattr("builtins.input", lambda *_: next(responses))
        decision = gate.request("test", "summary")
        assert decision.approved is False
        assert "too risky" in decision.reason

    def test_rejects_on_eof(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = CliApprovalGate()

        def _raise(*_: object) -> str:
            raise EOFError

        monkeypatch.setattr("builtins.input", _raise)
        decision = gate.request("test", "summary")
        assert decision.approved is False


class TestMakeApprovalCallback:
    def test_non_checkpoint_tasks_pass_silently(self) -> None:
        cb = make_approval_callback(_approving_gate(), {2: "check"})
        cb("output0")
        cb("output1")

    def test_triggers_gate_at_checkpoint_index(self) -> None:
        hit: list[str] = []

        class _RecordingGate(ApprovalGate):
            def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
                hit.append(checkpoint)
                return ApprovalDecision(approved=True, reason="ok")

        cb = make_approval_callback(_RecordingGate(), {1: "scan-approval"})
        cb("task0")
        cb("task1")
        assert hit == ["scan-approval"]

    def test_raises_pipeline_halted_on_rejection(self) -> None:
        cb = make_approval_callback(_rejecting_gate(), {0: "scan-approval"})
        with pytest.raises(PipelineHalted, match="scan-approval"):
            cb("output")

    def test_passes_after_rejection_position_if_not_checkpoint(self) -> None:
        cb = make_approval_callback(_approving_gate(), {1: "check"})
        cb("task0")
        cb("task1")
        cb("task2")

    def test_multiple_checkpoints(self) -> None:
        hit: list[str] = []

        class _RecordingGate(ApprovalGate):
            def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
                hit.append(checkpoint)
                return ApprovalDecision(approved=True, reason="ok")

        cb = make_approval_callback(
            _RecordingGate(), {0: "scan-approval", 4: "submission-approval"}
        )
        for i in range(6):
            cb(f"task{i}")
        assert hit == ["scan-approval", "submission-approval"]
