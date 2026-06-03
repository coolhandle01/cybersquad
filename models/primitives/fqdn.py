"""
models.primitives.fqdn - the ``FQDN`` typed-string primitive.

The RFC 1123 hostname every scope-guard input flows through. ``http_url``
reuses ``_validate_fqdn`` so a URL's host obeys the same strictness.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator

# ``FQDN`` is the typed string every scope-guard input flows through.
# Using ``Annotated[str, AfterValidator(...)]`` keeps the runtime type as
# ``str`` (anything expecting ``str`` keeps working) while pydantic applies
# the validator at model_validate time - so the schema rejects URLs / ports /
# paths / garbage upstream of any DNS or HTTP request.
#
# The validator is intentionally strict: it rejects a value the moment it
# stops looking like a bare RFC 1123 hostname. The agent occasionally hands
# us a URL where we asked for a hostname; the strict reject is the signal
# that surfaces the mismatch, instead of the scope filter silently dropping
# the value and the run going quiet.

_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")


def _validate_fqdn(value: str) -> str:
    """Normalise and validate a hostname per RFC 1123.

    Lowercases and strips, then enforces: non-empty, no scheme (``://``),
    no path (``/``), no port (``:``), total <= 253 chars, every dot-
    separated label is 1-63 chars of alphanumerics or hyphens with no
    leading or trailing hyphen. Returns the normalised value so downstream
    comparisons are case-insensitive without each call site re-lowering.
    """
    if not isinstance(value, str):  # pragma: no cover - Pydantic enforces str upstream
        raise ValueError(f"hostname must be a string, got {type(value).__name__}")
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("hostname cannot be empty")
    if "://" in cleaned:
        raise ValueError(f"hostname must not include a scheme: {value!r}")
    if "/" in cleaned:
        raise ValueError(f"hostname must not include a path: {value!r}")
    if ":" in cleaned:
        raise ValueError(f"hostname must not include a port: {value!r}")
    if len(cleaned) > 253:
        raise ValueError(f"hostname too long ({len(cleaned)} > 253 chars)")
    for label in cleaned.split("."):
        if not _HOSTNAME_LABEL_RE.match(label):
            raise ValueError(f"invalid hostname label {label!r} in {value!r}")
    return cleaned


FQDN = Annotated[str, AfterValidator(_validate_fqdn)]
