# ==============================================================================
# INDEPENDENT ground-truth suite for the CMDI Target.
#
# THIS FILE IS THE ORACLE. With NO involvement from the confirmation engine, it proves against
# the live app's real behavior that:
#   * GET /diag (REAL) executes an injected shell command — a payload that writes a MARKER FILE
#     actually creates it (proof the server's shell ran attacker-controlled commands), and
#   * GET /diag-safe (SECURE) refuses a payload carrying shell metacharacters with 400 and runs
#     NOTHING (the marker file is never created).
#
# A marker-file side effect stands in for the out-of-band server, so the canary needs no network
# and no interactsh. It must be green BEFORE the cmdi confirmer is pointed at this lab. Style
# mirrors the other labs' test_vulns.py (fastapi TestClient); no engine imports.
#
# Run:  pytest cmdi_target/test_vulns.py -v
# ==============================================================================
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cmdi_target.main import app  # noqa: E402


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# A command-injection payload: a shell separator (`&`, valid in cmd.exe AND sh) followed by a
# command that writes a marker file — the observable side effect that proves execution.
def _marker_payload(marker_path) -> str:
    return f'x & echo pwned> "{marker_path}"'


# -----------------------------------------------------------------------------
# REAL — GET /diag executes the injected command (the marker file appears).
# -----------------------------------------------------------------------------
def test_REAL_diag_executes_injected_command(client, tmp_path):
    marker = tmp_path / "cmdi_marker.txt"
    r = client.get("/diag", params={"host": _marker_payload(marker)})
    assert r.status_code == 200 and r.json()["ran"] is True
    assert marker.exists()                                  # the injected command RAN — cmdi
    assert "pwned" in marker.read_text(encoding="utf-8", errors="ignore").lower()


def test_REAL_diag_runs_a_benign_host_without_a_marker(client, tmp_path):
    # A plain host runs the base command and creates no marker (sanity: the marker only appears
    # when an injection payload is supplied, so the REAL test above is meaningful).
    marker = tmp_path / "none.txt"
    r = client.get("/diag", params={"host": "example.com"})
    assert r.status_code == 200 and r.json()["ran"] is True
    assert not marker.exists()


# -----------------------------------------------------------------------------
# SECURE — GET /diag-safe refuses a metacharacter payload and runs nothing.
# -----------------------------------------------------------------------------
def test_SAFE_refuses_injection_payload_and_never_runs_it(client, tmp_path):
    marker = tmp_path / "safe_marker.txt"
    r = client.get("/diag-safe", params={"host": _marker_payload(marker)})
    assert r.status_code == 400                             # refused up front (metacharacters)
    assert not marker.exists()                              # NOTHING ran — no side effect


def test_SAFE_allows_a_clean_host(client):
    r = client.get("/diag-safe", params={"host": "example.com"})
    assert r.status_code == 200 and r.json()["ran"] is True


def test_SAFE_refuses_spaces_and_separators(client, tmp_path):
    for bad in ("a b", "a;b", "a|b", "a&b", "a`b`", "a$(b)", "a\nb"):
        marker = tmp_path / "x.txt"
        r = client.get("/diag-safe", params={"host": bad})
        assert r.status_code == 400
        assert not marker.exists()
