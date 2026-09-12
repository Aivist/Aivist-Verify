# ==============================================================================
# INDEPENDENT ground-truth suite for the SSRF Target.
#
# THIS FILE IS THE ORACLE. With NO involvement from the confirmation engine, it proves
# against the live app's real behavior that:
#   * GET /fetch (REAL) actually issues a server-side request to whatever URL it is given
#     (SSRF — a local "canary" server receives the hit), and
#   * GET /fetch-safe (SECURE) refuses a non-allowlisted URL with 400 and makes NO request
#     (the canary is never hit).
#
# It must be green BEFORE the SSRF confirmer is pointed at this lab. No interactsh / no
# network beyond loopback: the canary stands in for the out-of-band server. Style mirrors
# the other labs' test_vulns.py (fastapi TestClient); no engine imports.
#
# Run:  pytest ssrf_target/test_vulns.py -v
# ==============================================================================
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ssrf_target.main import app  # noqa: E402

_HITS = []  # paths the canary server received (proof the SSRF sink actually reached out)


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
        yield f"http://127.0.0.1:{port}/ssrf-probe"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# -----------------------------------------------------------------------------
# REAL — GET /fetch actually fetches the injected URL server-side (the canary is hit).
# -----------------------------------------------------------------------------
def test_REAL_fetch_makes_server_side_request_to_injected_url(client, canary):
    r = client.get("/fetch", params={"url": canary})
    assert r.status_code == 200
    body = r.json()
    assert body["fetched"] is True and body["upstream_status"] == 200
    assert any("/ssrf-probe" in h for h in _HITS)          # the server really reached out — SSRF


def test_REAL_fetch_attempts_even_unreachable_host(client):
    # A non-existent host: the fetch is still ATTEMPTED server-side (the callback fires at DNS);
    # the endpoint reports the attempt rather than validating the URL away.
    r = client.get("/fetch", params={"url": "http://ssrf-nonexistent.invalid/x"})
    assert r.status_code == 200 and r.json()["fetched"] is True


# -----------------------------------------------------------------------------
# SECURE — GET /fetch-safe refuses a non-allowlisted URL and makes NO request.
# -----------------------------------------------------------------------------
def test_SAFE_refuses_non_allowlisted_url_and_never_fetches(client, canary):
    r = client.get("/fetch-safe", params={"url": canary})
    assert r.status_code == 400                            # refused up front
    assert _HITS == []                                     # canary NEVER hit — no server-side request


def test_SAFE_refuses_non_http_scheme(client):
    r = client.get("/fetch-safe", params={"url": "file:///etc/passwd"})
    assert r.status_code == 400
    assert _HITS == []


def test_SAFE_allows_only_allowlisted_host_shape(client):
    # A disallowed public host is refused BEFORE any request (host not in the allow-list).
    r = client.get("/fetch-safe", params={"url": "http://attacker.example.org/callback"})
    assert r.status_code == 400
    assert "not allowed" in r.json()["detail"]
