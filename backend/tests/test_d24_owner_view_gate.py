# ==============================================================================
# D24 — READ-SEMANTIC OWNER-VIEW DIFFERENTIAL GATE.
#
# Closes the SEV-1 found by the second target: read-semantic was the ONLY shape whose
# final verdict had no deterministic gate, so a securely-refused cross-account read was
# reported `verified` 20/20 on Depot purely because the model said so.
#
# These tests run the REAL execute_deep_verification against the REAL targets (in-process
# ASGI, no Gemini: only the model call is stubbed, so every HTTP request — attack, baseline
# and the code-issued owner-view read — is genuinely executed). The model is pinned to say
# `verified` on EVERY case, which is the point: it reproduces the exact failure mode, so
# only code can hold the line.
#
# ALLOWED-TO-FAIL ANCHORS — every one of these fails against the pre-gate engine:
#   * the three read-type SAFE cases must never end `verified`
#   * the two read-type VULN cases must still end `verified`
#   * the gate is downgrade-only and structurally cannot produce `verified`
#   * with no owner credential configured, behavior is exactly as before (degrade to
#     today's behavior, NOT to blocking everything)
# ==============================================================================

import os
import sys
import json
import asyncio
import importlib
import tempfile

import httpx
import pytest

pytest.importorskip("google.genai")

import backend.app.services.deep_verifier as dv
from backend.tests._llmstub import as_provider
from backend.app.core.config import settings
from backend.app.services.deep_verifier import (
    OwnerCredential,
    _apply_owner_view_gate,
    OWNER_VIEW_NOT_CORROBORATED_REASON,
)

DEPOT_OWNER = "Bearer bob-depot-token-bbbb"
DEPOT_ATTACKER = "Bearer alice-depot-token-aaaa"
VULN_OWNER = "Bearer bob-token-bbbb"
VULN_ATTACKER = "Bearer alice-token-aaaa"


@pytest.fixture(autouse=True)
def _enable_verifier(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _always_verified():
    """Pin the model to `verified` on every case — reproducing the exact SEV-1 failure
    mode, so anything that still comes out non-verified was held by CODE."""
    class _R:
        def __init__(self, text): self.text = text

    async def _gen(*args, **kwargs):
        return _R(json.dumps({
            "decision": "verdict", "next_request": None, "verdict": "verified",
            "confidence": 1.0, "evidence_path": "account_id",
            "reasoning": "d24-test-mock: model asserts verified",
        }))
    return _gen


def _load(module_name: str, env_var: str):
    db = os.path.join(tempfile.mkdtemp(), "d24.db")
    os.environ[env_var] = "sqlite+aiosqlite:///" + db.replace("\\", "/")
    if module_name in sys.modules:
        return importlib.reload(sys.modules[module_name])
    return importlib.import_module(module_name)


def _run_case(app, path, attacker, owner_raw, monkeypatch):
    """Drive the real verifier over the real app; only the model call is stubbed."""
    monkeypatch.setattr(dv, "get_provider", as_provider(_always_verified()))
    parsed = {"method": "GET", "path": path, "query_params": {}, "headers": {}, "body": None}

    async def _go():
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            real_client_cls = httpx.AsyncClient

            def _patched(*a, **kw):
                kw.pop("verify", None)
                kw["transport"] = transport
                return real_client_cls(*a, **kw)

            monkeypatch.setattr(dv.httpx, "AsyncClient", _patched)
            return await dv.execute_deep_verification(
                parsed_request=parsed,
                payload=None,                       # read-type: baseline == attack path
                base_url="http://testserver",
                approved_host="testserver",
                auth_context={"Authorization": attacker},
                available_endpoints=[f"GET {path}"],
                owner_credential=OwnerCredential.from_config(owner_raw) if owner_raw else None,
            )
    return asyncio.run(_go())


def _depot():
    return _load("depot_target.main", "DEPOT_TARGET_DATABASE_URL")


def _vuln():
    return _load("vulnerable_target.main", "VULN_TARGET_DATABASE_URL")


# -----------------------------------------------------------------------------
# The three read-type SAFE cases must NEVER end `verified`
# -----------------------------------------------------------------------------

def test_DP_READ_SAFE_never_verified(monkeypatch):
    d = _depot()
    res = _run_case(d.app, f"/depot/dockets/{d.ACCOUNT_BOB}", DEPOT_ATTACKER, DEPOT_OWNER, monkeypatch)
    assert res.ai_verdict_raw == "verified"        # the model DID say verified ...
    assert res.ai_verdict != "verified"            # ... and CODE refused it
    assert res.guard_override == OWNER_VIEW_NOT_CORROBORATED_REASON


def test_DP_READ_SAFE_ECHO_never_verified(monkeypatch):
    """The adversarial anchor: its denial echoes the attacker-supplied id into the
    owner-named field, which defeated the caller_identity candidate gate. The owner-view
    differential blocks it anyway, because an echo is still not the victim's data."""
    d = _depot()
    res = _run_case(d.app, f"/depot/bonds/{d.ACCOUNT_BOB}", DEPOT_ATTACKER, DEPOT_OWNER, monkeypatch)
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict != "verified"
    assert res.guard_override == OWNER_VIEW_NOT_CORROBORATED_REASON


def test_X_EQUIV_SAFE_never_verified(monkeypatch):
    v = _vuln()
    res = _run_case(v.app, "/api/ledgers/2", VULN_ATTACKER, VULN_OWNER, monkeypatch)
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict != "verified"
    assert res.guard_override == OWNER_VIEW_NOT_CORROBORATED_REASON


# -----------------------------------------------------------------------------
# The two read-type VULN cases must STILL end `verified`
# -----------------------------------------------------------------------------

def test_DP_READ_VULN_still_verified(monkeypatch):
    d = _depot()
    res = _run_case(d.app, f"/depot/waybills/{d.ACCOUNT_BOB}", DEPOT_ATTACKER, DEPOT_OWNER, monkeypatch)
    assert res.ai_verdict == "verified"            # a real leak survives the gate
    assert res.guard_override != OWNER_VIEW_NOT_CORROBORATED_REASON


def test_X_EQUIV_VULN_still_verified(monkeypatch):
    v = _vuln()
    res = _run_case(v.app, "/api/statements/2", VULN_ATTACKER, VULN_OWNER, monkeypatch)
    assert res.ai_verdict == "verified"
    assert res.guard_override != OWNER_VIEW_NOT_CORROBORATED_REASON


# -----------------------------------------------------------------------------
# Unset owner credential => today's behavior, NOT blocking everything
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("case", ["safe", "vuln"])
def test_no_owner_credential_degrades_to_todays_behavior(case, monkeypatch):
    """Deliberate choice: an unconfigured credential does NOT engage the gate. Blocking
    everything when unconfigured would regress every existing read-type verdict on both
    targets. Configuring the credential is the opt-in; fail-safe BLOCK applies to failures
    AFTER opting in, not to never having opted in."""
    d = _depot()
    path = (f"/depot/dockets/{d.ACCOUNT_BOB}" if case == "safe"
            else f"/depot/waybills/{d.ACCOUNT_BOB}")
    res = _run_case(d.app, path, DEPOT_ATTACKER, None, monkeypatch)
    # Pre-gate behavior: the model's verdict stands, ungated, for BOTH cases.
    assert res.ai_verdict == "verified"
    assert res.guard_override != OWNER_VIEW_NOT_CORROBORATED_REASON


def test_owner_view_failure_blocks_after_opting_in(monkeypatch):
    """Fail-safe: once a credential is configured, an owner view that cannot be obtained
    must BLOCK. Forced here by pointing the gate's fetch at a scope-violating host."""
    d = _depot()
    monkeypatch.setattr(
        dv, "fetch_owner_view",
        lambda *a, **k: _unavailable(),
    )
    res = _run_case(d.app, f"/depot/waybills/{d.ACCOUNT_BOB}", DEPOT_ATTACKER, DEPOT_OWNER, monkeypatch)
    assert res.ai_verdict != "verified"            # unverifiable => never permitted
    assert res.guard_override == OWNER_VIEW_NOT_CORROBORATED_REASON


async def _unavailable():
    return dv.OwnerViewResult(available=False, reason="forced_failure")


# -----------------------------------------------------------------------------
# Downgrade-only invariant — structural
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("verdict", ["failed", "inconclusive", "suspicious", None])
def test_DOWNGRADE_ONLY_never_creates_verified(verdict):
    """The gate can never manufacture or upgrade to `verified`, whatever it is handed and
    whatever the corroboration outcome."""
    for corroborated in (True, False):
        assert _apply_owner_view_gate(verdict, corroborated) == verdict
        assert _apply_owner_view_gate(verdict, corroborated) != "verified"


def test_DOWNGRADE_ONLY_verified_only_ever_weakens():
    assert _apply_owner_view_gate("verified", True) == "verified"     # unchanged
    assert _apply_owner_view_gate("verified", False) == "inconclusive"  # the only mutation


def test_DOWNGRADE_ONLY_source_never_returns_the_verified_literal():
    """Structural, checked on the AST rather than by substring: no `return` in the gate
    yields the literal 'verified'. The only literal it can return is the weaker
    'inconclusive'; every other path returns the verdict it was handed. So the function
    cannot manufacture a `verified` — it can only pass one through or take it away."""
    import ast, inspect, textwrap
    tree = ast.parse(textwrap.dedent(inspect.getsource(_apply_owner_view_gate)))
    returned_literals = [
        node.value.value for node in ast.walk(tree)
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant)
    ]
    assert "verified" not in returned_literals
    assert returned_literals == ["inconclusive"]
