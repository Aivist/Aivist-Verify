# ==============================================================================
# HEAVY passive discovery (version B) — CLI-native LIVE mitmdump capture -> the LIGHT loader -> scan.
# The async web proxy stack (ProxyManager pipeline / ingest / WriterService / SQLite / SSE) is NOT
# used: a short-lived SYNC subprocess writes flows to a FILE, which the already-built light loader
# reads. These tests drive scan_capture with a FAKE mitmdump (backend/tests/_fake_mitmdump.py) so no
# real mitmproxy and no network are needed. They prove:
#   * lifecycle + CLEAN teardown: spawn -> capture-to-file -> stop -> flows fed to the loader -> scan
#     discovers candidates; after stop NO child survives (orphan heartbeat stops) and the port is freed.
#   * SCOPE: off-target captured flows are dropped by the light loader and NEVER reach the engine.
#   * fail-safe: mitmproxy not installed -> clear error (no crash); 0 flows -> honest-empty message.
#   * secrets: the capture addon writes only method/host/path (no auth headers / cookies).
# ==============================================================================
import os
import sys
import json
import time
import socket
import importlib

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli import scan_capture
from backend.app.cli.scan_capture import capture_to_file, run_scan_capture_from_file, CaptureError
from backend.tests.test_scan_run import _stub_provider, _ScriptedEngine
from backend.tests.test_scan_traffic import _spec_less_target_file

_FAKE = [sys.executable, os.path.join(os.path.dirname(__file__), "_fake_mitmdump.py")]
_TARGET = "http://127.0.0.1:5000"


@pytest.fixture
def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _try_bind(port, timeout=3.0):
    """True if the port can be bound within `timeout` (proves it was freed after teardown)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            s.close()
            time.sleep(0.1)
    return False


def _alive(pid):
    if sys.platform == "win32":
        out = __import__("subprocess").run(
            ["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
        return str(pid) in (out.stdout or "")
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ------------------------------------------------------------------ lifecycle + CLEAN teardown
def test_capture_lifecycle_writes_file_and_tears_down_cleanly(tmp_path, free_port):
    flow = str(tmp_path / "flows.http")
    hb = str(tmp_path / "hb.txt")
    open(flow, "w").close()

    capture_to_file(
        _TARGET, flow, listen_port=free_port,
        wait_for_stop=lambda: time.sleep(0.3),          # let the fake capture + heartbeat, then stop
        mitmdump_cmd=_FAKE, boot_grace=0.4, echo=lambda *a: None,
        env_extra={"FAKE_HEARTBEAT_FILE": hb})

    # capture-to-file happened
    text = open(flow, encoding="utf-8").read()
    assert "GET /books/v1/alicebook" in text and "GET /books/v1/bobbook" in text

    # CLEAN teardown: the orphan grandchild is dead -> the heartbeat file stops growing.
    time.sleep(0.1)
    s1 = os.path.getsize(hb)
    time.sleep(0.4)
    s2 = os.path.getsize(hb)
    try:
        assert s1 == s2, "orphaned child survived teardown (heartbeat still growing) -> process-tree leak"
        # and the listen PORT was freed (no leak)
        assert _try_bind(free_port), "listen port leaked after teardown"
    finally:
        # hygiene: if the assertion above failed, reap the runaway grandchild so it can't linger
        try:
            pid = int(open(hb + ".pid").read().strip())
            if _alive(pid):
                if sys.platform == "win32":
                    __import__("subprocess").run(["taskkill", "/F", "/PID", str(pid)],
                                                 stdout=-3, stderr=-3)
                else:
                    os.kill(pid, 9)
        except Exception:
            pass


# ------------------------------------------------------------------ SCOPE (off-target never scanned)
def _run_capture_cli(tmp_path, monkeypatch, **over):
    from pydantic import SecretStr
    from backend.app.core.config import settings
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    lines = []
    sink = lambda *a: lines.append(" ".join(str(x) for x in a))
    code = run_scan_capture_from_file(
        _spec_less_target_file(tmp_path, base_url=_TARGET),
        capture_port=over.pop("capture_port"),
        environ={"TARGET_ATTACKER_TOKEN": "A", "TARGET_OWNER_TOKEN": "O"},
        wait_for_stop=lambda: time.sleep(0.15), mitmdump_cmd=over.pop("mitmdump_cmd", _FAKE),
        boot_grace=0.4, echo=sink, err=sink, **over)
    return code, "\n".join(lines)


def test_capture_scope_offtarget_never_reaches_engine(tmp_path, monkeypatch, free_port):
    ids = str(tmp_path / "ids.json")
    with open(ids, "w") as fh:
        json.dump({"ids": {"/books/v1/{id}": {"attacker_id": "alicebook", "victim_id": "bobbook"},
                           "/secret/{id}": {"attacker_id": "1", "victim_id": "2"}}}, fh)
    # the model proposes BOTH the in-scope books endpoint AND the off-target secret endpoint; the
    # off-target flow was dropped by the loader, so /secret/{id} is not in the catalog and is fenced out.
    cands = [{"method": "GET", "path_template": "/books/v1/{id}", "id_location": "path", "id_param": "id"},
             {"method": "GET", "path_template": "/secret/{id}", "id_location": "path", "id_param": "id"}]
    eng = _ScriptedEngine()
    code, out = _run_capture_cli(
        tmp_path, monkeypatch, capture_port=free_port, id_source_file=ids,
        engine=eng, scan_provider_factory=_stub_provider(cands))

    assert code == 0 and "scan report:" in out
    assert eng.calls, "the in-scope books candidate should have been judged"
    assert all("secret" not in c["parsed_request"]["path"] for c in eng.calls)   # off-target NEVER scanned


# ------------------------------------------------------------------ fail-safe
def test_capture_missing_mitmproxy_clear_error(tmp_path, monkeypatch, free_port):
    # No override + nothing resolvable -> a clear, actionable error, not a crash.
    monkeypatch.setattr(scan_capture.settings, "MITMDUMP_PATH", "")
    monkeypatch.setattr(scan_capture.shutil, "which", lambda _n: None)
    code, out = _run_capture_cli(tmp_path, monkeypatch, capture_port=free_port, mitmdump_cmd=None)
    assert code == 2 and "mitmproxy" in out and "install" in out.lower()


def test_capture_zero_flows_honest_empty(tmp_path, monkeypatch, free_port):
    # The fake binds the port but captures NOTHING -> the honest-empty message, never a row of zeros.
    monkeypatch.setenv("FAKE_MODE", "empty")
    code, out = _run_capture_cli(tmp_path, monkeypatch, capture_port=free_port)
    assert code == 2 and "0 flows" in out and "no in-scope traffic" in out


def test_capture_bootfail_clear_error(tmp_path, monkeypatch, free_port):
    # mitmdump dies during boot -> boot-grace detects it -> a clear error, not a hang/crash.
    monkeypatch.setenv("FAKE_MODE", "bootfail")
    code, out = _run_capture_cli(tmp_path, monkeypatch, capture_port=free_port)
    assert code == 2 and "could not start" in out


# ------------------------------------------------------------------ addon secret hygiene + scope
class _FakeReq:
    def __init__(self, method, path, host, port, headers):
        self.method, self.path, self.pretty_host, self.host, self.port = method, path, host, host, port
        self.headers = headers


class _FakeFlow:
    def __init__(self, req):
        self.request = req


def test_capture_addon_writes_minimal_block_and_scopes(tmp_path, monkeypatch):
    flow = str(tmp_path / "cap.http")
    monkeypatch.setenv("CAPTURE_FLOW_FILE", flow)
    monkeypatch.setenv("CAPTURE_SCOPE", "127.0.0.1:5000")
    from backend.app.proxy import capture_addon
    importlib.reload(capture_addon)                     # re-read the env into module state
    try:
        addon = capture_addon.CaptureAddon()
        addon.request(_FakeFlow(_FakeReq(
            "GET", "/books/v1/x?q=1", "127.0.0.1", 5000,
            {"Authorization": "Bearer super-secret-token", "Cookie": "session=abc123"})))
        addon.request(_FakeFlow(_FakeReq("GET", "/evil", "cdn.example.com", 443, {})))  # off-target
        out = open(flow, encoding="utf-8").read()
        # in-scope request written as a MINIMAL block (query stripped); no secret bytes on disk
        assert "GET /books/v1/x HTTP/1.1" in out and "Host: 127.0.0.1:5000" in out
        assert "super-secret-token" not in out and "Authorization" not in out and "session=" not in out
        # off-target request dropped by scope
        assert "cdn.example.com" not in out and "/evil" not in out
    finally:
        monkeypatch.delenv("CAPTURE_FLOW_FILE", raising=False)
        monkeypatch.delenv("CAPTURE_SCOPE", raising=False)
        importlib.reload(capture_addon)                 # restore clean module state for other tests
