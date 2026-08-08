# ==============================================================================
# LIGHT passive discovery — `scan` reads a CAPTURED-TRAFFIC FILE (HAR or raw-HTTP dump), keeps ONLY
# in-scope (target-origin) requests, templatizes their concrete paths to {id} candidates, and feeds
# scan's EXISTING endpoints path. This is the CONNECTOR test-set. It proves:
#   * HAR -> candidates: id-bearing requests templatize (via endpoint_catalog) and scan discovers them
#     (accepted > 0), through the UNCHANGED discovery/confirm loop.
#   * SCOPE (load-bearing): off-target-host flows are DROPPED and NEVER scanned — the test FAILS if an
#     off-target endpoint is ever handed to the engine.
#   * fail-safe: malformed / empty / unreadable file -> clear TrafficFileError; 0 in-scope flows -> []
#     (the honest-empty path) and the CLI's honest-empty message (not a row of zeros).
#   * secrets: only (method, host, path) is read; auth headers / cookies never reach the catalog.
# Zero network / no API: the loader is pure; run_scan is driven with raw_candidates + tier-a ids and a
# fake engine, exactly like test_scan_run.
# ==============================================================================
import os
import sys
import json
import asyncio

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli.scan_traffic import endpoints_from_traffic_file, TrafficFileError
from backend.app.services.endpoint_catalog import templatize_endpoints
from backend.app.cli.scan_run import run_scan
from backend.tests.test_scan_run import _result, _ScriptedEngine, _stub_provider

_TARGET = "http://127.0.0.1:5000"


def _entry(method, url):
    return {"request": {"method": method, "url": url, "headers": [], "postData": {}}}


def _har(*entries):
    return {"log": {"version": "1.2", "entries": list(entries)}}


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


# ------------------------------------------------------------------ templatize (unit, pure)
def test_templatize_endpoints_variance_shape_and_idempotence():
    # VARIANCE: a trailing segment that varies across otherwise-identical paths is the id.
    assert templatize_endpoints(
        ["GET /books/v1/alicebook", "GET /books/v1/bobbook"]) == ["GET /books/v1/{id}"]
    # SHAPE: numeric / uuid segments fold even as singletons; a version token + resource noun stay.
    assert templatize_endpoints(["GET /orders/7"]) == ["GET /orders/{id}"]
    assert templatize_endpoints(
        ["GET /users/550e8400-e29b-41d4-a716-446655440000/profile"]) == ["GET /users/{id}/profile"]
    # a lone non-id word (single sample, no digits) stays CONCRETE — we don't guess it is an id.
    assert templatize_endpoints(["GET /books/v1/alicebook"]) == ["GET /books/v1/alicebook"]
    # IDEMPOTENT on an already-{templated} path.
    assert templatize_endpoints(["GET /orders/{order_id}"]) == ["GET /orders/{order_id}"]
    # methods are templatized independently (no cross-contamination).
    assert templatize_endpoints(
        ["GET /orders/7", "POST /orders/9"]) == ["GET /orders/{id}", "POST /orders/{id}"]


# ------------------------------------------------------------------ HAR -> candidates (end to end)
def test_har_traffic_templatizes_and_feeds_discovery(tmp_path):
    har = _har(_entry("GET", f"{_TARGET}/books/v1/alicebook"),
               _entry("GET", f"{_TARGET}/books/v1/bobbook"))
    cap = _write(tmp_path, "cap.har", json.dumps(har))

    eps = endpoints_from_traffic_file(cap, _TARGET)
    assert eps == ["GET /books/v1/{id}"]                      # concrete capture -> {id} catalog entry

    seen = []

    async def run_op(op):
        seen.append(op["baseline_path"])
        return _result(ai_verdict="failed")

    cands = [{"method": "GET", "path_template": "/books/v1/{id}", "id_location": "path", "id_param": "id"}]
    id_map = {"/books/v1/{id}": {"attacker_id": "alicebook", "victim_id": "bobbook"}}
    res = asyncio.run(run_scan(_TARGET, endpoints=eps, run_op=run_op, raw_candidates=cands, id_map=id_map))

    assert len(res["accepted"]) == 1 and res["accepted"][0]["path_template"] == "/books/v1/{id}"
    assert len(seen) == 1 and seen[0].startswith("/books/v1/")   # the discovered candidate reached the judge


# ------------------------------------------------------------------ SCOPE (load-bearing)
def test_offtarget_flows_are_dropped_and_never_scanned(tmp_path):
    har = _har(_entry("GET", f"{_TARGET}/books/v1/alicebook"),
               _entry("GET", f"{_TARGET}/books/v1/bobbook"),
               _entry("GET", "http://evil.example.com/secret/33"))       # off-target host
    cap = _write(tmp_path, "cap.har", json.dumps(har))

    eps = endpoints_from_traffic_file(cap, _TARGET)
    assert eps == ["GET /books/v1/{id}"]                     # off-target path is NOT present at all
    assert not any(("secret" in e or "evil" in e) for e in eps)

    seen = []

    async def run_op(op):
        seen.append(op["baseline_path"])
        return _result(ai_verdict="failed")

    # Even if the model proposes the off-target endpoint, it is NOT in the scoped catalog, so the
    # candidate fence drops it and it is NEVER scanned. This assertion FAILS if it ever runs.
    cands = [
        {"method": "GET", "path_template": "/books/v1/{id}", "id_location": "path", "id_param": "id"},
        {"method": "GET", "path_template": "/secret/{id}", "id_location": "path", "id_param": "id"},
    ]
    id_map = {"/books/v1/{id}": {"attacker_id": "alicebook", "victim_id": "bobbook"},
              "/secret/{id}": {"attacker_id": "1", "victim_id": "2"}}
    res = asyncio.run(run_scan(_TARGET, endpoints=eps, run_op=run_op, raw_candidates=cands, id_map=id_map))

    assert any(d.get("reason") == "failed_candidate_fence" for d in res["dropped"])   # off-target dropped
    assert seen and all("secret" not in bp for bp in seen)   # NOTHING off-target was ever scanned


# ------------------------------------------------------------------ raw-HTTP dump + secret hygiene
def test_raw_http_dump_scope_templatize_and_no_secret_leak(tmp_path):
    dump = (
        "GET /orders/7 HTTP/1.1\nHost: 127.0.0.1:5000\nAuthorization: Bearer secret-token-xyz\n\n"
        "GET /orders/8 HTTP/1.1\nHost: 127.0.0.1:5000\nCookie: session=abc123\n\n"
        "GET /admin/99 HTTP/1.1\nHost: evil.example.com\n\n"       # off-target host -> dropped
    )
    cap = _write(tmp_path, "cap.txt", dump)

    eps = endpoints_from_traffic_file(cap, _TARGET)
    assert eps == ["GET /orders/{id}"]                       # in-scope only, templatized
    blob = json.dumps(eps)
    assert "secret-token" not in blob and "session=" not in blob and "admin" not in blob


# ------------------------------------------------------------------ fail-safe (clear error / honest empty)
def test_malformed_empty_missing_and_nonhar(tmp_path):
    empty = _write(tmp_path, "empty.har", "   \n  ")
    with pytest.raises(TrafficFileError):
        endpoints_from_traffic_file(empty, _TARGET)

    bad_json = _write(tmp_path, "bad.har", "{ this is not: valid json")
    with pytest.raises(TrafficFileError):
        endpoints_from_traffic_file(bad_json, _TARGET)

    with pytest.raises(TrafficFileError):                    # unreadable / missing file
        endpoints_from_traffic_file(str(tmp_path / "does-not-exist.har"), _TARGET)

    # A JSON that parses but is NOT a HAR (no entries): 0 usable flows -> [] (honest-empty, not an error).
    nonhar = _write(tmp_path, "nonhar.har", json.dumps({"foo": "bar"}))
    assert endpoints_from_traffic_file(nonhar, _TARGET) == []

    # A HAR whose only requests are off-target: 0 IN-SCOPE flows -> [] (honest-empty).
    off = _write(tmp_path, "off.har", json.dumps(_har(_entry("GET", "http://cdn.example.com/x/1"))))
    assert endpoints_from_traffic_file(off, _TARGET) == []


# ------------------------------------------------------------------ CLI wiring (non-interactive)
def _spec_less_target_file(tmp_path, base_url=_TARGET):
    """A spec-less target file (spec_path blank => scan must use --traffic-file / --endpoints-file)."""
    fields = dict(name="scan-t", base_url=base_url, method="GET",
                  path_template="/books/v1/{id}", id_location="path", id_param="id",
                  attacker_id="a", victim_id="b", auth_spec_path="", spec_path="")
    lines = [f'{k} = "{v}"' for k, v in fields.items()]
    p = tmp_path / "target.toml"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def _run_cli(tmp_path, cap, monkeypatch, **over):
    from pydantic import SecretStr
    from backend.app.core.config import settings
    from backend.app.cli.scan_cli import run_scan_from_file
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    lines = []
    sink = lambda *a: lines.append(" ".join(str(x) for x in a))
    code = run_scan_from_file(
        _spec_less_target_file(tmp_path), traffic_file=cap,
        environ={"TARGET_ATTACKER_TOKEN": "A", "TARGET_OWNER_TOKEN": "O"},
        echo=sink, err=sink, **over)
    return code, "\n".join(lines)


def test_cli_traffic_discovers_and_confirms(tmp_path, monkeypatch):
    har = _har(_entry("GET", f"{_TARGET}/books/v1/alicebook"),
               _entry("GET", f"{_TARGET}/books/v1/bobbook"))
    cap = _write(tmp_path, "cap.har", json.dumps(har))
    ids = _write(tmp_path, "ids.json",
                 json.dumps({"ids": {"/books/v1/{id}": {"attacker_id": "alicebook", "victim_id": "bobbook"}}}))
    cands = [{"method": "GET", "path_template": "/books/v1/{id}", "id_location": "path", "id_param": "id"}]

    eng = _ScriptedEngine()
    code, out = _run_cli(tmp_path, cap, monkeypatch, id_source_file=ids, engine=eng,
                         scan_provider_factory=_stub_provider(cands))
    assert code == 0
    assert "scan report:" in out and "[REFUTED]" in out      # discovered /books candidate, judged
    assert len(eng.calls) == 1                               # the templatized candidate reached the engine


def test_cli_traffic_honest_empty_on_zero_inscope(tmp_path, monkeypatch):
    # Only off-target traffic -> 0 in-scope -> the honest-empty NOT-DATA message (never a row of zeros).
    cap = _write(tmp_path, "cap.har", json.dumps(_har(_entry("GET", "http://evil.example.com/secret/1"))))
    code, out = _run_cli(tmp_path, cap, monkeypatch)
    assert code == 2 and "no in-scope requests" in out
