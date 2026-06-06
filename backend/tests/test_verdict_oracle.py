# ==============================================================================
# Verdict-correctness tests for the rule oracle — backend/app/services/fuzzer.py
# :: _differential_verdict (a pure function).
#
# These are Bucket-(A) tests (per docs/audit/verdict_coverage_audit.md): each case
# feeds the oracle a realistic baseline/test_result pair and asserts the verdict.
#
# THE EXPECTED VERDICTS ARE HUMAN-OWNED GROUND TRUTH. They are fixed by the
# maintainers and must NOT be altered to make a test pass. If the oracle returns
# something else, the assertion stays as-is and the test fails — a failure is a
# signal, not something to fix here.
#
# Oracle contract (read from disk):
#   _differential_verdict(baseline, test_result, payload_instruction) -> dict
#     baseline / test_result: {"status_code", "content_length", "response_body",
#                              "elapsed_ms"}
#     payload_instruction:    {"type": "BOLA" | "IDOR" | ...}
#   returns dict; result["verdict"] in {"verified", "suspicious", "failed"}
# ==============================================================================

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.services.fuzzer import _differential_verdict


# -----------------------------------------------------------------------------
# Helpers — build a response dict; content_length is always len(response_body).
# -----------------------------------------------------------------------------

def _resp(status_code, body, elapsed_ms=10):
    return {
        "status_code": status_code,
        "content_length": len(body),
        "response_body": body,
        "elapsed_ms": elapsed_ms,
    }


def _verdict(baseline, test_result, vuln_type):
    return _differential_verdict(baseline, test_result, {"type": vuln_type})["verdict"]


# Realistic bodies ------------------------------------------------------------

# Case A — order objects: cross-user read returns a clearly larger/different body.
_ORDER_OWN = '{"order_id":1,"owner_id":1,"item":"Vintage Typewriter","amount":42,"currency":"USD"}'
_ORDER_OTHER = (
    '{"order_id":2,"owner_id":2,"item":"Mechanical Keyboard Set + Artisan Keycaps Bundle",'
    '"amount":1299,"currency":"EUR","gift_wrap":true,"notes":"deliver after 6pm"}'
)

# Case T-REAL — invoices: own ~89 bytes, other ~331 bytes (much larger).
_INVOICE_OWN = '{"invoice_id":1,"owner_id":1,"total":19.99,"status":"paid","line_items":1}'
_INVOICE_OTHER = (
    '{"invoice_id":2,"owner_id":2,"total":4821.50,"status":"overdue","currency":"USD",'
    '"line_items":[{"sku":"A-100","qty":12,"price":120.00},{"sku":"B-200","qty":3,"price":99.50},'
    '{"sku":"C-300","qty":40,"price":75.00}],"billing_address":"742 Evergreen Terrace"}'
)

# Case T-TRAP — own document body vs. a soft-200 denial body (exact).
_DOC_OWN = '{"document_id":1,"owner_id":1,"title":"Q1 Plan","content":"internal roadmap notes"}'
_DOC_DENIED = '{"error":"forbidden"}'

# Cases B / D / T-SILENT2 / SAFE — opaque, byte-identical success envelope (len 15).
_OK = '{"status":"ok"}'

# Case T-WEAK — notes of equal length (only the trailing word differs).
_NOTE_OWN = '{"id":1,"owner_id":1,"title":"Groceries","body":"milk"}'
_NOTE_OTHER = '{"id":2,"owner_id":2,"title":"Groceries","body":"eggs"}'


# =============================================================================
# Class 1 — definitive correctness (a wrong verdict here = real oracle bug)
# =============================================================================

def test_case_A_blatant_bola():
    """BOLA: own small order vs. clearly larger cross-user order. EXPECTED: verified."""
    baseline = _resp(200, _ORDER_OWN)
    test_result = _resp(200, _ORDER_OTHER)
    assert _verdict(baseline, test_result, "BOLA") == "verified"


def test_case_T_REAL_strong_idor():
    """IDOR: own small invoice (~89B) vs. much larger cross-user invoice (~331B).
    EXPECTED: verified."""
    baseline = _resp(200, _INVOICE_OWN)
    test_result = _resp(200, _INVOICE_OTHER)
    assert _verdict(baseline, test_result, "IDOR") == "verified"


def test_case_T_TRAP_soft200_denial():
    """IDOR: own document vs. a 200 body of exactly {"error":"forbidden"}.
    The denial keyword must demote it. EXPECTED: failed (false-POSITIVE killer)."""
    baseline = _resp(200, _DOC_OWN)
    test_result = _resp(200, _DOC_DENIED)
    assert _verdict(baseline, test_result, "IDOR") == "failed"


# =============================================================================
# Class 2 — single-shot ceiling (rule oracle physically cannot do better)
# =============================================================================

def test_case_B_silent_bola():
    """BOLA: byte-identical opaque 200 {"status":"ok"}. EXPECTED: suspicious."""
    baseline = _resp(200, _OK)
    test_result = _resp(200, _OK)
    assert _verdict(baseline, test_result, "BOLA") == "suspicious"


def test_case_D_silent_bola_regression():
    """BOLA: identical shape to case B (fresh endpoint). EXPECTED: suspicious."""
    baseline = _resp(200, _OK)
    test_result = _resp(200, _OK)
    assert _verdict(baseline, test_result, "BOLA") == "suspicious"


def test_case_T_SILENT2_silent_bola():
    """BOLA: identical shape to case B (theme family). EXPECTED: suspicious."""
    baseline = _resp(200, _OK)
    test_result = _resp(200, _OK)
    assert _verdict(baseline, test_result, "BOLA") == "suspicious"


def test_case_T_WEAK_weak_idor():
    """IDOR: own note vs. cross-user note of the SAME length (only the trailing
    word differs). Real vuln, but a faint signal. EXPECTED: suspicious."""
    baseline = _resp(200, _NOTE_OWN)
    test_result = _resp(200, _NOTE_OTHER)
    # Equal-length bodies are the whole point of this case.
    assert len(_NOTE_OWN) == len(_NOTE_OTHER)
    assert _verdict(baseline, test_result, "IDOR") == "suspicious"


def test_case_SAFE_secure_lookalike():
    """BOLA: byte-identical opaque 200 {"status":"ok"} — a SECURE control that
    looks exactly like the vulnerable case B. A single-shot oracle cannot
    exonerate it, only flag it. EXPECTED: suspicious."""
    baseline = _resp(200, _OK)
    test_result = _resp(200, _OK)
    assert _verdict(baseline, test_result, "BOLA") == "suspicious"


# =============================================================================
# Characterization — the gap the deep verifier exists to fill
# =============================================================================

def test_case_silent_bola_and_safe_are_indistinguishable():
    """The rule oracle returns the SAME verdict for a REAL silent BOLA (case B)
    and the SECURE look-alike (case SAFE) — it cannot tell them apart."""
    real = _verdict(_resp(200, _OK), _resp(200, _OK), "BOLA")
    safe = _verdict(_resp(200, _OK), _resp(200, _OK), "BOLA")
    assert real == safe == "suspicious"
