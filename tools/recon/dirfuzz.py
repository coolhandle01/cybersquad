"""
Content/directory discovery via ffuf.

Probes live endpoints with a wordlist to surface hidden paths, admin panels,
API routes, and sensitive files that passive recon won't find.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile

from config import config
from models import Endpoint
from tools._helpers import _require_binary, _run

logger = logging.getLogger(__name__)

# Status codes worth reporting. 403 is included because it confirms a path
# exists and may be bypassable; 401 signals auth-gated resources.
_INTERESTING_CODES = {200, 204, 301, 302, 307, 401, 403}


def discover_paths(endpoints: list[Endpoint]) -> list[Endpoint]:
    """
    Run ffuf against each live endpoint and return newly discovered paths.

    Only probes endpoints with a successful (sub-500) status code.
    Limits to config.scan.dirfuzz_max_targets to avoid runaway scan times.
    Deduplicates against the input endpoint list so callers only receive net-new
    paths.
    """
    live = [ep for ep in endpoints if ep.status_code and ep.status_code < 500]
    if not live:
        return []

    ffuf = _require_binary("ffuf")
    wordlist = config.scan.dirfuzz_wordlist

    known_urls = {ep.url.rstrip("/") for ep in endpoints}
    discovered: list[Endpoint] = []

    for ep in live[: config.scan.dirfuzz_max_targets]:
        base = ep.url.rstrip("/")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            _run(
                [
                    ffuf,
                    "-u",
                    f"{base}/FUZZ",
                    "-w",
                    wordlist,
                    "-of",
                    "json",
                    "-o",
                    out_path,
                    "-mc",
                    ",".join(str(c) for c in sorted(_INTERESTING_CODES)),
                    "-t",
                    str(config.scan.dirfuzz_threads),
                    "-rate",
                    str(config.scan.dirfuzz_rate_limit),
                    "-timeout",
                    str(config.recon.http_timeout),
                    "-noninteractive",
                    "-s",
                ],
                timeout=config.scan.dirfuzz_timeout,
            )

            try:
                with open(out_path) as fh:
                    data = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                logger.debug("dirfuzz: could not read output for %s: %s", base, exc)
                continue

            for hit in data.get("results", []):
                url = hit.get("url", "").rstrip("/")
                status = hit.get("status")
                if url and url not in known_urls:
                    known_urls.add(url)
                    discovered.append(Endpoint(url=url, status_code=status))

        except Exception as exc:
            logger.debug("dirfuzz failed for %s: %s", base, exc)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(out_path)

    logger.info("dirfuzz discovered %d new paths across %d targets", len(discovered), len(live))
    return discovered
