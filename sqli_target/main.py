# ==============================================================================
# SQLI Target — a standalone practice target for OOB blind-SQL-injection confirmation
#                                            (LOCAL PRACTICE TARGET — NEVER DEPLOY)
# ==============================================================================
#
# A deliberately-insecure, fully self-contained FastAPI app used as ground truth for the FOURTH vuln
# type: blind SQL injection, confirmed out-of-band (the same "did our uniquely-tokened callback fire"
# proof shape as SSRF/cmdi).
#
#   GET /report?id=<id>       REAL — concatenates the user-supplied `id` straight into a SQL query
#                             STRING with NO parameterization. A tiny in-process "DBMS" then PARSES the
#                             final SQL text: if it contains an out-of-band primitive that references a
#                             host/URL (MySQL LOAD_FILE UNC, MSSQL xp_dirtree, Oracle UTL_INADDR/UTL_HTTP,
#                             PostgreSQL dblink), the DB reaches out to it (DNS/HTTP) — an interactsh
#                             session observes the callback => CONFIRMED blind SQLi. It returns only a
#                             row count (never data), so confirmation is purely out-of-band.
#   GET /report-safe?id=<id>  SECURE — a PARAMETERIZED query: the SQL text is fixed ("... WHERE id = ?")
#                             and `id` is bound as a DATA parameter, never concatenated into the text the
#                             DBMS parses. An injected primitive therefore stays inert data => no
#                             out-of-band lookup can occur => never confirmed.
#
# The "DBMS" here is a FAITHFUL SIMULATION, not a real database: it models the one property that matters
# for this proof — a DBMS executes SQL *text*, and parameterization keeps user data out of that text, so
# an OOB primitive only fires when the input was concatenated in. THE ENGINE IS FROZEN while this target
# is used: a false positive on /report-safe or a miss on /report is the finding, not a reason to tune the
# confirmer. Ground truth is proven independently by sqli_target/test_vulns.py (a local canary; no interactsh).
#
# Run:
#   python -m uvicorn sqli_target.main:app --host 127.0.0.1 --port 8006
# ==============================================================================
from __future__ import annotations

import re
import socket

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query

VALID_TOKEN = "sqli-target-token-aaaa"
_LOOKUP_TIMEOUT = 5.0

# What the simulated DBMS "reaches out to" when it parses an OOB primitive in the SQL TEXT: any http(s)
# URL, or a long-label host (an interactsh probe domain is a 33-char label + a registrable domain — the
# >=13 guard avoids matching ordinary hosts). This is how a real MySQL/MSSQL/Oracle/PG OOB primitive
# would resolve/fetch the attacker domain.
_URL_RE = re.compile(r"https?://[^\s'\"()\\<>]+")
_LONG_HOST_RE = re.compile(r"[A-Za-z0-9-]{13,}\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

app = FastAPI(
    title="SQLI Target",
    description="Deliberately-insecure blind-SQL-injection practice target. Localhost only. Never deploy.",
    version="1.0.0",
)


async def optional_account(authorization: str | None = Header(default=None)) -> str:
    """Accept an optional bearer token; unauthenticated access is allowed (the sqli bug does not depend
    on auth). A supplied-but-invalid token is rejected so an auth header is honored."""
    if authorization is None:
        return "anonymous"
    raw = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    if raw != VALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    return "authenticated"


def _dbms_execute(sql_text: str) -> dict:
    """Simulate a DBMS parsing + executing `sql_text`. Its ONLY observable side effect here is the
    out-of-band one: if the SQL text carries an OOB primitive that names a host/URL, the DB reaches out
    to it (DNS resolve + HTTP GET) — exactly the callback a real OOB primitive triggers. Errors are
    swallowed (the resolve/connect attempt IS the callback). Returns a benign row count, never data."""
    for url in _URL_RE.findall(sql_text):
        try:
            with httpx.Client(timeout=_LOOKUP_TIMEOUT, verify=False, follow_redirects=False) as c:
                c.get(url)
        except Exception:
            pass
    for host in _LONG_HOST_RE.findall(sql_text):
        try:
            socket.getaddrinfo(host, None)      # DNS resolution -> the OOB DNS callback
        except Exception:
            pass
    return {"executed": True, "rows": 0}


@app.get("/report", tags=["sqli"])
async def report(id: str = Query(...), _who: str = Depends(optional_account)):
    """REAL blind SQL injection. `id` is concatenated straight into the SQL text with NO
    parameterization, so an injected OOB primitive is parsed + executed by the DBMS."""
    sql_text = f"SELECT * FROM reports WHERE id = {id}"    # <- unparameterized concatenation (the bug)
    return _dbms_execute(sql_text)


@app.get("/report-safe", tags=["sqli"])
async def report_safe(id: str = Query(...), _who: str = Depends(optional_account)):
    """SECURE. A PARAMETERIZED query: the SQL text the DBMS parses is fixed and `id` is BOUND as a data
    parameter, never spliced into the text. An injected primitive therefore never reaches the parser, so
    no out-of-band lookup can occur. (We model binding by scanning only the fixed text, never the param.)"""
    sql_text = "SELECT * FROM reports WHERE id = ?"        # bound parameter; user data stays OUT of the text
    _params = (id,)                                        # noqa: F841 - bound data, never parsed as SQL
    return _dbms_execute(sql_text)


@app.get("/", tags=["meta"])
async def root():
    return {
        "service": "SQLI Target",
        "warning": "Deliberately insecure blind-SQL-injection practice target. Localhost only. Never deploy.",
        "endpoints": {
            "real": "GET /report?id=<id> (unparameterized concatenation — injectable)",
            "safe": "GET /report-safe?id=<id> (parameterized/bound — inert)",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("sqli_target.main:app", host="127.0.0.1", port=8006, reload=False)
