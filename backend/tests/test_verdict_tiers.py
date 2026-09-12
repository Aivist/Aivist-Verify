# ==============================================================================
# Tiered-verdict framework — offline tests.
#
# Proves: (1) access-control findings map to CONFIRMED exactly as confirm_render decides
# today (delegation, no drift); (2) CONFIRMED is RESERVED by construction — it cannot be
# minted without a DeterministicProof, and a detector cannot emit a tier above its declared
# ceiling; (3) a future inference-style detector renders SIGNAL and CANNOT become CONFIRMED.
# ==============================================================================
import os
import sys

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.services.verdict_tiers import (
    Tier, TierViolation, DeterministicProof, Verdict, Detector, classify,
    access_control_verdict, AccessControlDetector, InferenceSignalDetector, badge,
    tier_from_outcome,
)
from backend.app.cli.confirm_render import case_outcome, _BROKEN_FOR_ALL_REASON


# ---- access control maps to the SAME outcome as confirm_render (delegation) ------------------
_CONFIRMED_CHANNEL = {"final_verdict": "verified", "guard_override": "write_record_readback_decisive"}
_CONFIRMED_OWNERVIEW = {"final_verdict": "verified", "guard_override": None, "owner_view_corroborated": True}
_SIGNAL = {"final_verdict": "verified", "guard_override": None}
_REFUTED = {"final_verdict": "inconclusive", "guard_override": "owner_view_not_corroborated"}
_NOTDATA = {"final_verdict": None, "degraded": True, "degraded_reason": "rate-limited"}
_BROKEN = {"final_verdict": "inconclusive", "guard_override": _BROKEN_FOR_ALL_REASON}


@pytest.mark.parametrize("record,expected_tier,expected_outcome", [
    (_CONFIRMED_CHANNEL, Tier.CONFIRMED, "confirmed"),
    (_CONFIRMED_OWNERVIEW, Tier.CONFIRMED, "confirmed"),
    (_SIGNAL, Tier.SIGNAL, "signal"),
    (_REFUTED, Tier.REFUTED, "refuted"),
    (_NOTDATA, Tier.NOT_DATA, "notdata"),
])
def test_access_control_tier_matches_case_outcome(record, expected_tier, expected_outcome):
    assert case_outcome(record) == expected_outcome           # the shipped decision
    v = access_control_verdict(record)
    assert v.tier is expected_tier                            # the tiered layer agrees


def test_broken_for_all_is_inconclusive():
    assert access_control_verdict(_BROKEN).tier is Tier.INCONCLUSIVE


def test_confirmed_carries_a_deterministic_proof():
    v = access_control_verdict(_CONFIRMED_CHANNEL)
    assert v.tier is Tier.CONFIRMED
    assert isinstance(v.proof, DeterministicProof)
    assert v.proof.channel == "write_record_readback_decisive"


# ---- CONFIRMED is reserved by construction --------------------------------------------------
def test_confirmed_without_proof_is_refused():
    with pytest.raises(TierViolation):
        Verdict.confirmed("verified", None)                  # type: ignore[arg-type]


def test_confirmed_dataclass_cannot_be_forged_without_proof():
    with pytest.raises(TierViolation):
        Verdict(Tier.CONFIRMED, "verified", "forged", proof=None)


def test_proof_only_valid_on_confirmed():
    with pytest.raises(TierViolation):
        Verdict(Tier.SIGNAL, "suspected", "x",
                proof=DeterministicProof("chan", "basis"))


# ---- the extension point: a detector cannot exceed its declared ceiling ----------------------
def test_inference_stub_renders_signal_not_confirmed():
    v = classify(InferenceSignalDetector(), evidence="200 vs 403 length delta")
    assert v.tier is Tier.SIGNAL
    assert badge(v) == "[SIGNAL]"


def test_detector_emitting_above_ceiling_is_refused():
    class Rogue(Detector):
        name = "rogue-inference"
        max_tier = Tier.SIGNAL                                # declares it can only infer
        def assess(self, evidence):
            # even if it tries to mint a real proof, the ceiling refuses CONFIRMED
            proof = DeterministicProof("faked", "not actually deterministic")
            return Verdict.confirmed("verified", proof)
    with pytest.raises(TierViolation):
        classify(Rogue(), evidence=None)


def test_access_control_detector_may_reach_confirmed():
    v = classify(AccessControlDetector(), evidence=_CONFIRMED_CHANNEL)
    assert v.tier is Tier.CONFIRMED and badge(v) == "[CONFIRMED]"


def test_access_control_detector_refutes_safe_case():
    v = classify(AccessControlDetector(), evidence=_REFUTED)
    assert v.tier is Tier.REFUTED and badge(v) == "[REFUTED]"


# ---- interop with the existing tier strings --------------------------------------------------
def test_tier_from_outcome():
    assert tier_from_outcome("confirmed") is Tier.CONFIRMED
    assert tier_from_outcome("signal") is Tier.SIGNAL
    assert tier_from_outcome("refuted") is Tier.REFUTED
    assert tier_from_outcome("notdata") is Tier.NOT_DATA
    assert tier_from_outcome("broken_for_all") is Tier.INCONCLUSIVE
    assert tier_from_outcome("skipped") is Tier.SKIPPED
