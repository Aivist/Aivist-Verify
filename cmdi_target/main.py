# ==============================================================================
# CMDI Target — a standalone practice target for OOB OS-command-injection confirmation
#                                            (LOCAL PRACTICE TARGET — NEVER DEPLOY)
# ==============================================================================
#
# A deliberately-insecure, fully self-contained FastAPI app used as ground truth for the
# THIRD vuln type: OS command injection, confirmed out-of-band (the same "did our uniquely-
# tokened callback fire" proof shape as SSRF).
#
#   GET /diag?host=<host>       REAL — concatenates the user-supplied `host` into a SHELL
#                               command string and runs it with shell=True, with NO
#                               sanitization. A payload carrying a shell separator
#                               (`; nslookup <domain>`, `& curl http://<domain>/`, ...) is
#                               executed by the server's shell, which resolves/fetches the
#                               attacker domain => an interactsh session observes the callback
#                               => CONFIRMED cmdi. It returns only a status (never the command
#                               output), so confirmation is purely out-of-band.
#   GET /diag-safe?host=<host>  SECURE — validates `host` against a strict allow-list regex
#                               (`[A-Za-z0-9.-]` only) BEFORE use; anything carrying a shell
#                               metacharacter, space, or newline is refused with 400 and NO
#                               command runs => no callback => never confirmed.
#
# THE ENGINE IS FROZEN while this target is used. If the confirmer false-positives on the SAFE
# endpoint or fails to confirm the REAL one, THAT divergence is the finding — do not "fix" the
# confirmer and do not relabel these cases. Ground truth is proven independently by
# cmdi_target/test_vulns.py (no engine imports; a marker-file side effect stands in for the OOB
# server, so the canary needs no network).
#
# Run:
#   python -m uvicorn cmdi_target.main:app --host 127.0.0.1 --port 8005
# ==============================================================================
from __future__ import annotations

import re
import subprocess

from fastapi import Depends, FastAPI, Header, HTTPException, Query

# Optional opaque-token auth (some injection sinks sit behind a login). A token is NOT required;
# if supplied it is honored, else the endpoint is open (the cmdi bug does not depend on auth).
VALID_TOKEN = "cmdi-target-token-aaaa"

# The SAFE endpoint accepts ONLY this shape — letters, digits, dot, hyphen (a hostname/IP). It
# deliberately excludes spaces and every shell metacharacter, so an injection payload is refused.
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")

_CMD_TIMEOUT = 8.0

app = FastAPI(
    title="CMDI Target",
    description="Deliberately-insecure OS command-injection practice target. Localhost only. Never deploy.",
    version="1.0.0",
)


async def optional_account(authorization: str | None = Header(default=None)) -> str:
    """Accept an optional bearer token; unauthenticated access is allowed. A supplied-but-invalid
    token is rejected so an auth header is honored."""
    if authorization is None:
        return "anonymous"
    raw = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    if raw != VALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    return "authenticated"


def _run_shell(cmd: str) -> dict:
    """Run `cmd` through the SHELL and report only whether it ran (never the output — so
    confirmation is purely out-of-band, not echoed). A bounded timeout keeps a hung/interactive
    injected command from wedging the target."""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=_CMD_TIMEOUT, text=True)
        return {"ran": True, "returncode": proc.returncode, "error": None}
    except subprocess.TimeoutExpired:
        return {"ran": True, "returncode": None, "error": "TimeoutExpired"}
    except Exception as e:
        return {"ran": True, "returncode": None, "error": type(e).__name__}


@app.get("/diag", tags=["cmdi"])
async def diag(host: str = Query(...), _who: str = Depends(optional_account)):
    """REAL command injection. The user-supplied `host` is concatenated straight into a shell
    command with NO sanitization, so a payload with a shell separator runs whatever it likes —
    e.g. an out-of-band callback that proves server-side command execution."""
    cmd = f"echo diag {host}"          # <- unsanitized concatenation into a shell string (the bug)
    return _run_shell(cmd)


@app.get("/diag-safe", tags=["cmdi"])
async def diag_safe(host: str = Query(...), _who: str = Depends(optional_account)):
    """SECURE. `host` is validated against a strict allow-list regex BEFORE use; anything
    carrying a space or a shell metacharacter is refused with 400 and NO command is run — so an
    injection payload can never reach the shell and no out-of-band callback can occur. (Because the
    validated value is metacharacter-free, the shell call below cannot be injected.)"""
    if not _SAFE_HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="invalid host (letters, digits, dot, hyphen only)")
    return _run_shell(f"echo diag {host}")


@app.get("/", tags=["meta"])
async def root():
    return {
        "service": "CMDI Target",
        "warning": "Deliberately insecure OS command-injection practice target. Localhost only. Never deploy.",
        "endpoints": {
            "real": "GET /diag?host=<host> (unsanitized shell concatenation — injectable)",
            "safe": "GET /diag-safe?host=<host> (strict allow-list; refuses metacharacters)",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("cmdi_target.main:app", host="127.0.0.1", port=8005, reload=False)
