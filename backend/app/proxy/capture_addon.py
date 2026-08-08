# ==============================================================================
# CLI LIVE-capture mitmdump addon (HEAVY passive discovery, version B).
#
# Runs INSIDE mitmproxy's own interpreter (`mitmdump -s capture_addon.py`), a separate process from
# the CLI. It is the file-writing counterpart of radar_addon.py — but with NONE of radar's async
# coupling: it does NOT ship flows to a FastAPI ingest endpoint / WriterService / SQLite / SSE. It
# appends each IN-SCOPE request to a plain FILE the LIGHT loader (scan_traffic) already reads, so the
# heavy live-capture front reuses the light back half verbatim.
#
# SCOPE (red line): a request whose host is not the target's origin is DROPPED here (belt to the
# loader's own scope drop), reusing the ONE audited ScopePolicy so passive capture and active
# confirmation never disagree on "in scope". SECRETS: only the request line + Host are written — never
# Authorization / Cookie / body — so NOTHING secret ever touches the capture file.
#
# Config via env (set by scan_capture.py):  CAPTURE_FLOW_FILE, CAPTURE_SCOPE (csv host[:port]).
# ==============================================================================

import os

# The audited ScopePolicy is PURE (stdlib + a vendored suffix list); importable in mitmproxy's own
# interpreter because scan_capture puts the repo root on PYTHONPATH. A last-resort inline fallback keeps
# the addon working standalone (same apex / host[:port] semantics).
try:
    from backend.app.services.scope import ScopePolicy
except Exception:  # pragma: no cover - defensive standalone fallback
    ScopePolicy = None


_FLOW_FILE = os.environ.get("CAPTURE_FLOW_FILE", "")
_SCOPE = [s.strip() for s in os.environ.get("CAPTURE_SCOPE", "").split(",") if s.strip()]


def _build_scope_check():
    """A netloc (host[:port]) in-scope predicate over _SCOPE, built ONCE. Uses the audited ScopePolicy
    when importable; else a last-resort inline matcher with the same apex / `*.host` semantics. Empty
    scope => everything in scope (unlocked)."""
    if ScopePolicy is not None:
        try:
            policy = ScopePolicy.from_declaration(_SCOPE)
            return lambda netloc: policy.netloc_allowed(netloc)
        except Exception:
            return lambda netloc: True   # never crash the proxy on a bad env
    def _fallback(netloc: str) -> bool:
        if not _SCOPE:
            return True
        h = (netloc or "").lower()
        h = h.rsplit(":", 1)[0] if ":" in h else h
        for raw in (x.lower() for x in _SCOPE):
            s = raw.rsplit(":", 1)[0] if ":" in raw else raw
            if s.startswith("*."):
                base = s[2:]
                if h == base or h.endswith("." + base):
                    return True
            elif h == s:
                return True
        return False
    return _fallback


_in_scope = _build_scope_check()


def _netloc(host: str, port) -> str:
    if port and port not in (80, 443):
        return f"{host}:{port}"
    return host


class CaptureAddon:
    """mitmproxy addon — writes ONE minimal request block per in-scope flow to CAPTURE_FLOW_FILE."""

    def request(self, flow) -> None:
        # Hooked on `request` (not `response`): discovery needs only method+path+host, so we never wait
        # for — or read — the response body. Exceptions are swallowed so capture never breaks browsing.
        try:
            if not _FLOW_FILE:
                return
            req = flow.request
            host = req.pretty_host or req.host or ""
            netloc = _netloc(host, req.port)
            if not _in_scope(netloc):
                return
            method = req.method or "GET"
            path = (req.path or "/").split("?", 1)[0]
            # MINIMAL raw-HTTP block: request line + Host ONLY. No auth headers / cookies / body — the
            # loader needs only method/host/path, and this guarantees no secret is ever written to disk.
            block = f"{method} {path} HTTP/1.1\nHost: {netloc}\n\n"
            with open(_FLOW_FILE, "a", encoding="utf-8") as fh:
                fh.write(block)
        except Exception:
            return


addons = [CaptureAddon()]
