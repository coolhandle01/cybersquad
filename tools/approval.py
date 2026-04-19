"""tools/approval.py — Approval gate for pipeline checkpoints.

The CliApprovalGate is the only production implementation. It blocks on stdin
and renders a rich panel so the operator can review context before approving.

In tests, pass a local ApprovalGate stub to make_approval_callback() directly —
there is no module-level singleton and no bypass mode.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass


class PipelineHalted(RuntimeError):
    """Raised when an approval checkpoint rejects continuation."""


@dataclass
class ApprovalDecision:
    approved: bool
    reason: str


class ApprovalGate(ABC):
    @abstractmethod
    def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
        """Block until the operator approves or rejects this checkpoint."""


class CliApprovalGate(ApprovalGate):
    """Interactive gate: rich-formatted panel + stdin prompts."""

    def request(self, checkpoint: str, summary: str) -> ApprovalDecision:
        from rich.console import Console
        from rich.panel import Panel
        from rich.prompt import Confirm, Prompt
        from rich.text import Text

        console = Console()
        console.print()
        console.print(
            Panel(
                Text(summary[:1000]),
                title=f"[bold yellow]  {checkpoint}  [/bold yellow]",
                subtitle="[dim]approve to continue · reject to halt[/dim]",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print()
        try:
            approved = Confirm.ask("[bold]Approve and continue?[/bold]", default=False)
        except EOFError:
            return ApprovalDecision(approved=False, reason="Non-interactive stdin — rejected")
        if approved:
            reason = Prompt.ask("Reason [dim](optional — Enter to skip)[/dim]", default="")
            return ApprovalDecision(approved=True, reason=reason or "Approved by operator")
        reason = Prompt.ask("Rejection reason")
        return ApprovalDecision(approved=False, reason=reason or "Rejected by operator")


def make_approval_callback(
    gate: ApprovalGate,
    checkpoints: dict[int, str],
) -> Callable[[object], None]:
    """Return a task_callback that triggers approval at specified task indices.

    Each call advances an internal counter; when the counter matches a key in
    *checkpoints*, the gate is consulted. Raises PipelineHalted on rejection.
    """
    completed = [0]

    def _callback(output: object) -> None:  # noqa: ANN401
        idx = completed[0]
        completed[0] += 1
        checkpoint = checkpoints.get(idx)
        if checkpoint is None:
            return
        decision = gate.request(checkpoint, str(output)[:800])
        if not decision.approved:
            raise PipelineHalted(f"Pipeline halted at '{checkpoint}': {decision.reason}")

    return _callback
