# ==============================================================================
# Human-owned offline unit tests for the D18 §5 B-2.2 structural backstop
# (deep_verifier._apply_cross_resource_guard / _normalize_path).
#
# THE EXPECTED VALUES ARE HUMAN-OWNED GROUND TRUTH (answer key §8). They must NOT
# be authored, relaxed, or "corrected" here to make a test pass. These are the first
# bucket-(A) verdict-PATH tests: they assert the deterministic guard logic directly,
# with NO live model and NO network.
#
# The guard (target-agnostic, structural): a decisive verdict that rests on a
# follow-up read-back of a DIFFERENT concrete resource/path than the one attacked is
# NOT decisive -> override to "inconclusive". Same-resource read-backs and no-follow-up
# cases are untouched. It compares two path strings only — no endpoint/field/object
# names, no audit-log knowledge.
# ==============================================================================

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from backend.app.services.deep_verifier import (
    _apply_cross_resource_guard,
    _normalize_path,
    CROSS_RESOURCE_OVERRIDE_REASON,
)

# Concrete paths mirroring the live shapes (cross-resource vs same-resource).
ATTACK_CROSSPATH = "/api/users/2/display-name"   # X-CROSS attack target
READBACK_OTHER = "/api/users/2/profile"          # a DIFFERENT resource exposing a same-named field
SAME_PATH = "/api/users/2/profile"               # P0-PROFILE: attack and read-back identical


# -----------------------------------------------------------------------------
# §8 truth table — wired verbatim from the human-owned answer key.
# -----------------------------------------------------------------------------

def test_verified_crosspath_readback_overridden_to_inconclusive():
    # verified + follow-up path != attack path -> inconclusive (overridden), raw preserved.
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_CROSSPATH, READBACK_OTHER, follow_up_performed=True
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_failed_crosspath_readback_overridden_to_inconclusive():
    # failed + follow-up path != attack path -> inconclusive (overridden).
    final, reason = _apply_cross_resource_guard(
        "failed", ATTACK_CROSSPATH, READBACK_OTHER, follow_up_performed=True
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_verified_samepath_readback_untouched():
    # verified + follow-up path == attack path -> verified (untouched).
    final, reason = _apply_cross_resource_guard(
        "verified", SAME_PATH, SAME_PATH, follow_up_performed=True
    )
    assert final == "verified"
    assert reason is None


def test_failed_samepath_readback_untouched():
    # failed + follow-up path == attack path -> failed (untouched).
    final, reason = _apply_cross_resource_guard(
        "failed", SAME_PATH, SAME_PATH, follow_up_performed=True
    )
    assert final == "failed"
    assert reason is None


def test_verified_no_followup_untouched():
    # verified + NO follow-up -> verified (untouched). Must not break read-type/GET BOLA.
    final, reason = _apply_cross_resource_guard(
        "verified", "/api/orders/2", None, follow_up_performed=False
    )
    assert final == "verified"
    assert reason is None


def test_failed_no_followup_untouched():
    # failed + NO follow-up -> failed (untouched).
    final, reason = _apply_cross_resource_guard(
        "failed", "/api/orders/2", None, follow_up_performed=False
    )
    assert final == "failed"
    assert reason is None


@pytest.mark.parametrize("verdict", ["suspicious", "inconclusive", None])
def test_non_decisive_verdicts_never_overridden(verdict):
    # suspicious / inconclusive / None + anything -> unchanged (guard only touches verified/failed).
    final, reason = _apply_cross_resource_guard(
        verdict, ATTACK_CROSSPATH, READBACK_OTHER, follow_up_performed=True
    )
    assert final == verdict
    assert reason is None


def test_raw_verdict_is_not_mutated_by_guard():
    # The guard is pure: it returns a (possibly new) verdict; the caller stores the raw
    # separately. The input value itself is never mutated.
    raw = "verified"
    final, reason = _apply_cross_resource_guard(
        raw, ATTACK_CROSSPATH, READBACK_OTHER, follow_up_performed=True
    )
    assert raw == "verified"          # input untouched
    assert final == "inconclusive"    # returned value overridden
    assert final != raw


# -----------------------------------------------------------------------------
# Normalization: concrete-path, method-agnostic, strip trailing slash, ignore query.
# -----------------------------------------------------------------------------

def test_normalize_strips_trailing_slash():
    assert _normalize_path("/api/users/2/profile/") == "/api/users/2/profile"


def test_normalize_ignores_query_string():
    assert _normalize_path("/api/users/2/profile?x=1&y=2") == "/api/users/2/profile"


def test_normalize_ignores_fragment():
    assert _normalize_path("/api/users/2/profile#frag") == "/api/users/2/profile"


def test_normalize_preserves_root():
    assert _normalize_path("/") == "/"


def test_normalize_none_is_empty():
    assert _normalize_path(None) == ""


def test_trailing_slash_difference_is_same_resource_untouched():
    # /a/b/ and /a/b are the SAME resource -> a decisive verdict must stay decisive.
    final, reason = _apply_cross_resource_guard(
        "verified", "/api/users/2/profile", "/api/users/2/profile/", follow_up_performed=True
    )
    assert final == "verified"
    assert reason is None


def test_query_only_difference_is_same_resource_untouched():
    final, reason = _apply_cross_resource_guard(
        "failed", "/api/users/2/profile", "/api/users/2/profile?cache=0", follow_up_performed=True
    )
    assert final == "failed"
    assert reason is None


def test_different_concrete_id_same_template_is_cross_resource():
    # Concrete-path comparison: /users/2/... vs /users/1/... are different resources.
    final, reason = _apply_cross_resource_guard(
        "failed", "/api/users/2/display-name", "/api/users/1/display-name", follow_up_performed=True
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON
