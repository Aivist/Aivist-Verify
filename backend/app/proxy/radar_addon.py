# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Step 9 Proxy Radar — mitmdump Addon (Tier-1 inline filter + IPC)
#
# IMPORTANT: this file runs INSIDE mitmproxy's own Python interpreter (a separate
# process from FastAPI), loaded via `mitmdump -s radar_addon.py`. It must not
# import FastAPI/SQLAlchemy. It only:
#   * Tier-1 (inline, <5ms): host scope lock + static-asset veto. Anything out of
#     scope or static is released immediately — NO heavy work on the hook.
#   * Ships a truncated copy of in-scope dynamic flows to the FastAPI internal
#     ingest endpoint via a fire-and-forget loopback HTTP POST (so browser
#     latency is unaffected). Tier-2 scoring happens server-side.
#
# Config is passed via env vars by ProxyManager:
#   RADAR_INGEST_URL, RADAR_INGEST_TOKEN, RADAR_SCOPE (csv), RADAR_BODY_CAP
# ==============================================================================

import os
import asyncio
import datetime

import httpx

# --- shared Tier-1 helpers (single source of truth with the backend) ----------
# PYTHONPATH is set by ProxyManager so these resolve to the SAME code the active engine
# uses. Node 3: host-scope matching is the ONE audited ScopePolicy, so passive capture and
# active fuzzing never drift. The scope module is PURE (stdlib + a vendored suffix list; no
# FastAPI/SQLAlchemy), so importing it here in mitmproxy's own interpreter is clean.
# Fall back to local copies if the import can't be resolved, so the proxy still works
# standalone (last-resort only; the fallback mirrors the same apex / `*.host` semantics).
try:
    from backend.app.services.pruner import is_static_path
    from backend.app.services.scope import ScopePolicy
except Exception:  # pragma: no cover - defensive standalone fallback
    _STATIC_EXT = (
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
        ".svg", ".map", ".html", ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".pdf",
    )

    def is_static_path(path: str) -> bool:
        p = (path or "").lower().split("?", 1)[0]
        return any(p.endswith(e) for e in _STATIC_EXT)

    ScopePolicy = None


_INGEST_URL = os.environ.get("RADAR_INGEST_URL", "")
_INGEST_TOKEN = os.environ.get("RADAR_INGEST_TOKEN", "")
_SCOPE = [s.strip() for s in os.environ.get("RADAR_SCOPE", "").split(",") if s.strip()]


def _build_scope_check():
    """A host-level in-scope predicate over _SCOPE, built ONCE (the addon's hot path).
    Uses the audited ScopePolicy when importable; else a last-resort inline matcher with
    the SAME apex / `*.host` semantics. Host-level only (no resolution): the passive proxy
    never initiates connections, so the resolved-IP guard does not apply here. Empty scope
    => everything in scope (the active UNLOCKED convention)."""
    if ScopePolicy is not None:
        try:
            policy = ScopePolicy.from_declaration(_SCOPE)
            return lambda host: policy.netloc_allowed(host)
        except Exception:
            return lambda host: True   # defensive: never crash the proxy on a bad env
    def _fallback(host: str) -> bool:
        if not _SCOPE:
            return True
        h = (host or "").lower()
        for s in (x.lower().strip() for x in _SCOPE):
            if not s:
                continue
            if s.startswith("*."):
                base = s[2:]
                if h == base or h.endswith("." + base):
                    return True
            elif h == s:
                return True
        return False
    return _fallback


_host_allowed = _build_scope_check()
try:
    _BODY_CAP = int(os.environ.get("RADAR_BODY_CAP", "65536"))
except ValueError:
    _BODY_CAP = 65536


def _truncate(text, cap):
    if text is None:
        return None, False
    if len(text) > cap:
        return text[:cap], True
    return text, False


class RadarAddon:
    """mitmproxy addon — one instance is auto-registered by the `addons` list."""

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=2.0)

    async def response(self, flow) -> None:
        """
        Full request/response is available here. Tier-1 filter inline, then
        fire-and-forget the shippable flows. Exceptions are swallowed so the
        proxy never disrupts the user's browsing.
        """
        try:
            req = flow.request
            host = req.pretty_host or req.host or ""
            raw_path = req.path or "/"
            path = raw_path.split("?", 1)[0]

            # --- Tier-1: release immediately if out of scope or static ---------
            if not _host_allowed(host):
                return
            if is_static_path(path):
                return

            payload = self._build_payload(flow, host, path)
            # Fire-and-forget: do not block the browser on the IPC POST.
            asyncio.create_task(self._ship(payload))
        except Exception:
            return

    def _build_payload(self, flow, host: str, path: str) -> dict:
        req = flow.request
        resp = flow.response

        req_body, req_trunc = _truncate(_safe_text(req), _BODY_CAP)
        resp_body, resp_trunc = (None, False)
        status_code = None
        resp_headers = {}
        elapsed_ms = None
        if resp is not None:
            resp_body, resp_trunc = _truncate(_safe_text(resp), _BODY_CAP)
            status_code = resp.status_code
            resp_headers = {k: v for k, v in resp.headers.items()}
            try:
                if resp.timestamp_end and req.timestamp_start:
                    elapsed_ms = round((resp.timestamp_end - req.timestamp_start) * 1000.0, 2)
            except Exception:
                elapsed_ms = None

        return {
            "schema_version": 1,
            "flow_id": getattr(flow, "id", "")[:64],
            "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scheme": req.scheme or "http",
            "method": req.method or "GET",
            "host": host[:255],
            "port": req.port,
            "path": path[:4096],
            "tier1": {"in_scope": True, "is_static": False},
            "request": {
                "headers": {k: v for k, v in req.headers.items()},
                "query_params": {k: v for k, v in req.query.items()},
                "body": req_body,
                "body_truncated": req_trunc,
            },
            "response": {
                "status_code": status_code,
                "headers": resp_headers,
                "body": resp_body,
                "body_truncated": resp_trunc,
                "elapsed_ms": elapsed_ms,
            },
        }

    async def _ship(self, payload: dict) -> None:
        if not _INGEST_URL:
            return
        try:
            await self._client.post(
                _INGEST_URL,
                json=payload,
                headers={"X-Ingest-Token": _INGEST_TOKEN},
            )
        except Exception:
            # Backpressure (503) or transient errors: drop silently (passive radar).
            return

    def done(self) -> None:
        try:
            asyncio.get_event_loop().create_task(self._client.aclose())
        except Exception:
            pass


def _safe_text(message) -> str:
    """Best-effort decode of a mitmproxy message body to text; '' on failure."""
    try:
        return message.get_text(strict=False) or ""
    except Exception:
        try:
            return message.content.decode("utf-8", "replace") if message.content else ""
        except Exception:
            return ""


addons = [RadarAddon()]
