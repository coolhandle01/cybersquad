"""Shared low-level helpers used across tools subpackages."""

from __future__ import annotations

import logging
import shutil
import subprocess
import time

from models import Severity

logger = logging.getLogger(__name__)

_SEVERITY_FLOOR_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _require_binary(name: str) -> str:
    """Return full path to a binary or raise OSError if not found."""
    path = shutil.which(name)
    if not path:
        raise OSError(
            f"Required binary '{name}' not found in PATH. "
            f"Please install it before running the pipeline."
        )
    return path


def adaptive_sleep(delay: float, status_code: int) -> float:
    """Sleep for delay seconds then adjust based on HTTP status.

    Returns the new delay to use for the next request. On 429 the delay
    doubles (capped at 60s); when the delay is elevated it recovers gradually
    back to config.scan.request_delay. Callers track the returned value:

        _delay = config.scan.request_delay
        for ...:
            resp = http.get(...)
            _delay = adaptive_sleep(_delay, resp.status_code)
    """
    from config import config  # deferred - config imports nothing from tools

    time.sleep(delay)
    if status_code == 429:
        new = min(delay * 2.0, 60.0)
        logger.debug("429 rate-limited - backing off to %.1fs", new)
        return new
    if delay > config.scan.request_delay:
        return max(delay * 0.9, config.scan.request_delay)
    return delay


def _run(
    cmd: list[str],
    timeout: int = 120,
    input: str | None = None,
) -> subprocess.CompletedProcess:
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input,
    )
    if result.returncode != 0:
        logger.warning("Command exited %d: %s", result.returncode, result.stderr[:500])
    return result
