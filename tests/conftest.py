"""
tests/conftest.py - top-level pytest configuration.

This file stays narrow on purpose: env-var seeding (must run at
import time so ``config.py``'s module-level singleton loads cleanly),
the ``pytest_plugins`` declaration that pulls fixtures in from
``tests/fixtures/*.py``, and the one project-wide autouse fixture
that patches ``time.sleep``.

The fixtures themselves live under ``tests/fixtures/`` by concern:

  domains.py    target_url, bystander_url, callback_url, target_apex,
                target_sld, make_html_page
  programme.py  scope_item_*, programme, programme_in_workspace,
                dvwa_*, run_dir
  recon.py      endpoint, recon_result, make_s3_hostname, s3_hostname,
                make_azure_blob_hostname, azure_blob_hostname,
                azure_sas_endpoint
  findings.py   raw_finding_*, verified_vuln, disclosure_report,
                attack_tree, attack_forest
  responses.py  make_response, clean_response_body
  tools.py      invoke_tool, reload_module
  task_output.py  make_task_output

The ``pytest_plugins`` mechanism is the upstream-blessed way to wire
fixture modules into the discovery path - documented at
https://docs.pytest.org/en/stable/how-to/fixtures.html#use-fixtures-from-other-projects.
Pytest's docs also note that ``pytest_plugins`` is only honoured at the
top-level conftest (this one), not at nested ones.
"""

from __future__ import annotations

# Seed the env vars that config.py reads at import time so test runs that
# do not export them on the command line still load the config singleton
# cleanly. These are placeholders only; production runs supply real values.
import os

os.environ.setdefault("H1_API_USERNAME", "ci-user")
os.environ.setdefault("H1_API_TOKEN", "ci-token")
os.environ.setdefault("CYBERSQUAD_CONTACT_EMAIL", "ci@example.invalid")

import pytest

pytest_plugins = [
    "tests.fixtures.domains",
    "tests.fixtures.programme",
    "tests.fixtures.recon",
    "tests.fixtures.findings",
    "tests.fixtures.responses",
    "tests.fixtures.tools",
    "tests.fixtures.task_output",
]


# Probe tools call tools._helpers.adaptive_sleep between requests for rate-limit
# politeness. Inside _helpers, adaptive_sleep calls time.sleep(delay) for real,
# which dominates unit-test wall-clock time (roughly 40% of the suite). Patch it
# once here for every test. Tests that need to observe sleep behaviour
# (TestAdaptiveSleep in test_scan_mode.py) re-patch time.sleep locally and the
# assertions still fire - the autouse lambda is below their inner patch.
@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args, **_kwargs: None)
