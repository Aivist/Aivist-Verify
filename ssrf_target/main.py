# ==============================================================================
# SSRF Target — a standalone practice target for OOB SSRF confirmation
#                                            (LOCAL PRACTICE TARGET — NEVER DEPLOY)
# ==============================================================================
#
# A deliberately-insecure, fully self-contained FastAPI app used as ground truth for the
# FIRST non-access-control vuln type: Server-Side Request Forgery, confirmed out-of-band.
#
#   GET /fetch?url=<url>       REAL — server-side-fetches ANY user-supplied URL with NO
#                              validation. Point it at an attacker domain and the SERVER
#                              reaches out to it (DNS + HTTP), which an interactsh session
#                              observes as a callback => CONFIRMED SSRF.
#   GET /fetch-safe?url=<url>  SECURE — validates the URL against a strict host ALLOW-LIST
#                              before fetching; a non-allowlisted host (loopback, an attacker
#                              domain, cloud metadata, …) is refused with 400 and NO request
#                              is ever made => no callback => never confirmed.
#
# THE ENGINE IS FROZEN while this target is used. If the confirmer false-positives on the
# SAFE endpoint or fails to confirm the REAL one, THAT divergence is the finding — do not
# "fix" the confirmer and do not relabel these cases. Ground truth is proven independently
# by ssrf_target/test_vulns.py (no engine imports).
#
# Run:
#   python -m uvicorn ssrf_target.main:app --host 127.0.0.1 --port 8004
# ==============================================================================
from __future__ import annotations

from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query

# Optional opaque-token auth (some SSRF sinks sit behind a login). A token is NOT required;
# if TARGET_SSRF_TOKEN-style headers are supplied they are accepted, else the endpoint is open.
VALID_TOKEN = "ssrf-target-token-aaaa"

# The SAFE endpoint fetches ONLY these hosts. Deliberately does NOT include loopback, private
# ranges, cloud-metadata, or any attacker domain — so a probe URL is always refused.
_ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

_FETCH_TIMEOUT = 5.0

app = FastAPI(
    title="SSRF Target",
    description="Deliberately-insecure SSRF practice target. Localhost only. Never deploy.",
    version="1.0.0",
)


async def optional_account(authorization: str | None = Header(default=None)) -> str:
    """Accept an optional bearer token; unauthenticated access is allowed (the SSRF bug does
    not depend on auth). A supplied-but-invalid token is rejected so an auth header is honored."""
    if authorization is None:
        return "anonymous"
    raw = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    if raw != VALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    return "authenticated"


async def _server_side_fetch(url: str) -> dict:
    """Actually fetch `url` from the SERVER. Errors are swallowed to a report — the DNS
    resolution + connection attempt (the SSRF callback) has already happened by then."""
    try:
        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT, verify=False,
                                     follow_redirects=False) as client:
            resp = await client.get(url)
        return {"fetched": True, "url": url, "upstream_status": resp.status_code, "error": None}
    except Exception as e:  # DNS/connect/TLS/timeout — the callback still fired
        return {"fetched": True, "url": url, "upstream_status": None, "error": type(e).__name__}


@app.get("/fetch", tags=["ssrf"])
async def fetch(url: str = Query(...), _who: str = Depends(optional_account)):
    """REAL SSRF. No validation whatsoever: the server fetches whatever URL it is given, so a
    probe URL pointed at an attacker domain triggers a real out-of-band callback."""
    return await _server_side_fetch(url)


@app.get("/fetch-safe", tags=["ssrf"])
async def fetch_safe(url: str = Query(...), _who: str = Depends(optional_account)):
    """SECURE. Validates the URL against a strict host ALLOW-LIST BEFORE any request is made.
    Only http(s) and an allowlisted host are fetched; anything else is refused with 400 and
    NO server-side request is issued, so no out-of-band callback can occur."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="only http(s) URLs are allowed")
    host = (parts.hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        # Refused BEFORE any network call — the whole point of the secure control.
        raise HTTPException(status_code=400, detail=f"url host not allowed: {host!r}")
    return await _server_side_fetch(url)


@app.get("/", tags=["meta"])
async def root():
    return {
        "service": "SSRF Target",
        "warning": "Deliberately insecure SSRF practice target. Localhost only. Never deploy.",
        "endpoints": {
            "real": "GET /fetch?url=<url> (no validation — server fetches any URL)",
            "safe": "GET /fetch-safe?url=<url> (host allow-list; refuses everything else)",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("ssrf_target.main:app", host="127.0.0.1", port=8004, reload=False)
