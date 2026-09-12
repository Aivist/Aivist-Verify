# ==============================================================================
# Tiered-verdict framework — an explicit verdict-STRENGTH layer OVER the existing tiers.
#
# WHY: today the access-control confirmer already separates a deterministically-proven
# `verified` (rendered CONFIRMED) from a model-opinion `verified` (rendered SIGNAL) — see
# confirm_render._claim_tier. This module makes that strength model EXPLICIT and REUSABLE,
# so a FUTURE vuln type (e.g. a response-inference check) can report at the RIGHT strength
# without ever diluting the access-control zero-false-positive guarantee.
#
# IT CHANGES NO ACCESS-CONTROL VERDICT. `access_control_verdict()` DELEGATES to
# confirm_render.case_outcome — the single source of truth — so an access-control finding
# maps to CONFIRMED iff it is code-confirmed today, byte-for-byte. Nothing here is wired
# into the live confirm/scan output; it is a layer the CLI/future types can build on.
#
# THE RESERVED-CONFIRMED GUARANTEE (two structural locks, mirroring how the engine reserves
# `verified` for a deterministic code channel):
#   1. `Verdict.confirmed(...)` REQUIRES a `DeterministicProof`. There is no code path that
#      mints CONFIRMED without one; a model opinion cannot produce a proof, so it cannot
#      produce CONFIRMED.
#   2. Every finding is emitted through `classify(detector, evidence)`, which REFUSES
#      (raises `TierViolation`) any verdict stronger than the detector's DECLARED `max_tier`.
#      A non-deterministic detector declares `max_tier = SIGNAL`; if buggy code tried to
#      emit CONFIRMED from it, the framework rejects it. Reaching CONFIRMED therefore takes
#      a DELIBERATE, reviewable `max_tier = CONFIRMED` AND a real proof — never an accident.
#
# EXTENSION POINT: implement the `Detector` protocol (a `name`, a `max_tier`, and an
# `assess(evidence) -> Verdict`), then emit via `classify()`. A deterministic detector may
# declare `max_tier = CONFIRMED` and hand `Verdict.confirmed` a `DeterministicProof`; an
# inference/heuristic detector declares `max_tier = SIGNAL` and can only ever emit SIGNAL.
# `InferenceSignalDetector` below is a worked (non-wired) example.
# ==============================================================================
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Dict, Optional


class Tier(enum.IntEnum):
    """Verdict strength, ascending. The numeric order lets `classify()` compare a produced
    verdict against a detector's declared ceiling; the reservation that matters is that a
    positive claim can be CONFIRMED (deterministic proof) or, at most, SIGNAL (inferred)."""
    NOT_DATA = 0        # no usable verdict (challenge / rate-limit / transport failure)
    SKIPPED = 1         # not tested (e.g. no sourceable id)
    REFUTED = 2         # checked, no effect (a negative result)
    INCONCLUSIVE = 3    # a conditional finding requiring human review (e.g. broken-for-all)
    SIGNAL = 4          # POSITIVE but evidence-INFERRED / opinion — a lead, needs human review
    CONFIRMED = 5       # POSITIVE and proven by a DETERMINISTIC code channel (RESERVED)


class TierViolation(Exception):
    """Raised when a detector would emit a verdict stronger than it declared, or a CONFIRMED
    is attempted without a DeterministicProof. It is a structural guard, not a runtime option."""


@dataclass(frozen=True)
class DeterministicProof:
    """The token CONFIRMED requires. Holding one asserts a deterministic, code-checked basis
    (a physical effect the code re-observed — e.g. a write that persisted to an independent
    read-back, or an owner-view corroboration). A model opinion never has one, so it can never
    reach CONFIRMED. `channel` names the deterministic mechanism (for audit/logging)."""
    channel: str
    basis: str


@dataclass(frozen=True)
class Verdict:
    """One finding's verdict at an explicit strength. `token` is the raw engine verdict word
    (e.g. 'verified' / 'inconclusive'); `basis` is the human-readable evidence; `proof` is
    present iff `tier is CONFIRMED`."""
    tier: Tier
    token: Optional[str]
    basis: str
    proof: Optional[DeterministicProof] = None

    # -- constructors: CONFIRMED needs a proof; nothing else can produce one ------------
    @classmethod
    def confirmed(cls, token: Optional[str], proof: DeterministicProof,
                  basis: Optional[str] = None) -> "Verdict":
        if not isinstance(proof, DeterministicProof):
            raise TierViolation("CONFIRMED requires a DeterministicProof (a deterministic, "
                                "code-checked basis) - a model opinion cannot mint one.")
        return cls(Tier.CONFIRMED, token, basis or proof.basis, proof)

    @classmethod
    def signal(cls, token: Optional[str], basis: str) -> "Verdict":
        return cls(Tier.SIGNAL, token, basis, None)

    @classmethod
    def inconclusive(cls, token: Optional[str], basis: str) -> "Verdict":
        return cls(Tier.INCONCLUSIVE, token, basis, None)

    @classmethod
    def refuted(cls, token: Optional[str], basis: str) -> "Verdict":
        return cls(Tier.REFUTED, token, basis, None)

    @classmethod
    def not_data(cls, basis: str) -> "Verdict":
        return cls(Tier.NOT_DATA, None, basis, None)

    @classmethod
    def skipped(cls, basis: str) -> "Verdict":
        return cls(Tier.SKIPPED, None, basis, None)

    def __post_init__(self) -> None:
        # Belt-and-suspenders: a CONFIRMED without a proof, or a proof on a non-CONFIRMED,
        # is a construction bug. Reject it so the invariant cannot be bypassed by building
        # the dataclass directly instead of via the constructors above.
        if self.tier is Tier.CONFIRMED and not isinstance(self.proof, DeterministicProof):
            raise TierViolation("a CONFIRMED verdict must carry a DeterministicProof")
        if self.proof is not None and self.tier is not Tier.CONFIRMED:
            raise TierViolation("a DeterministicProof is only valid on a CONFIRMED verdict")


# ------------------------------------------------------------------------------
# The extension point: a detector declares its strongest attainable tier and assesses
# evidence into a Verdict. `classify` is the ONE emit path; it enforces the ceiling.
# ------------------------------------------------------------------------------
class Detector:
    """Base/extension point for a verdict contributor. Subclass it, set `name` and
    `max_tier`, and implement `assess`. Emit ONLY through `classify()` so the ceiling and
    the proof requirement are enforced."""
    name: str = "detector"
    max_tier: Tier = Tier.SIGNAL

    def assess(self, evidence: Any) -> Verdict:  # pragma: no cover - overridden
        raise NotImplementedError


def classify(detector: Detector, evidence: Any) -> Verdict:
    """Run a detector and STRUCTURALLY enforce its declared ceiling. A verdict stronger than
    `detector.max_tier` is refused (TierViolation) — this is what keeps CONFIRMED reserved:
    only a detector that deliberately declares `max_tier = CONFIRMED` and returns a
    proof-bearing Verdict can ever reach it."""
    verdict = detector.assess(evidence)
    if verdict.tier > detector.max_tier:
        raise TierViolation(
            f"detector {detector.name!r} declared max_tier={detector.max_tier.name} "
            f"but emitted {verdict.tier.name} - refused (CONFIRMED is reserved for "
            f"deterministic detectors)."
        )
    return verdict


# ------------------------------------------------------------------------------
# Access-control detector — maps an engine RECORD to a Verdict by DELEGATING to the existing
# confirm_render.case_outcome. This is the whole point of "access control maps to CONFIRMED
# exactly as today": there is no second verdict implementation to drift.
# ------------------------------------------------------------------------------
def access_control_verdict(record: Dict[str, Any]) -> Verdict:
    """The tiered Verdict for an access-control finding. CONFIRMED iff the deterministic code
    gate authorized it today (case_outcome == 'confirmed'); SIGNAL for a model-opinion
    'verified'; REFUTED / NOT_DATA / INCONCLUSIVE otherwise. Delegates to confirm_render so
    it cannot diverge from the shipped access-control behavior."""
    from backend.app.cli.confirm_render import case_outcome, _BROKEN_FOR_ALL_REASON  # pure module

    token = record.get("final_verdict")
    if token is None:
        token = record.get("ai_verdict")

    if record.get("guard_override") == _BROKEN_FOR_ALL_REASON:
        return Verdict.inconclusive(
            token, "every authenticated principal could read it but an anonymous one could not - "
                   "a conditional broken-for-all finding requiring human review.")

    outcome = case_outcome(record)          # confirmed | signal | refuted | notdata
    if outcome == "confirmed":
        channel = record.get("guard_override") or "read_semantic_owner_view_gate"
        proof = DeterministicProof(
            channel=channel,
            basis="a deterministic code channel proved a cross-user effect "
                  "(write-then-independent-read, or owner-view corroboration).")
        return Verdict.confirmed(token, proof)
    if outcome == "signal":
        return Verdict.signal(
            token, "the model called it 'verified' but NO deterministic code channel authorized "
                   "it - a lead to verify by hand, not a confirmation.")
    if outcome == "refuted":
        return Verdict.refuted(token, "no cross-user effect was confirmed.")
    return Verdict.not_data(
        record.get("degraded_reason") or "the run produced no usable verdict (NOT DATA).")


class AccessControlDetector(Detector):
    """The shipped access-control confirmer as a tiered detector. It MAY reach CONFIRMED
    because it is deterministic (the engine's code gate provides the proof)."""
    name = "access-control"
    max_tier = Tier.CONFIRMED

    def assess(self, evidence: Dict[str, Any]) -> Verdict:
        return access_control_verdict(evidence)


class InferenceSignalDetector(Detector):
    """WORKED EXAMPLE of a future response-inference detector — NOT wired to any real vuln
    type. Its evidence is heuristic (a response difference, a timing hint), so it declares
    `max_tier = SIGNAL`: `classify()` will refuse anything stronger. This is how a future
    non-deterministic check plugs in WITHOUT being able to emit CONFIRMED."""
    name = "inference-stub"
    max_tier = Tier.SIGNAL

    def assess(self, evidence: Any) -> Verdict:
        return Verdict.signal("suspected", f"response-inference evidence: {evidence}")


# ------------------------------------------------------------------------------
# Interop + rendering helpers (do not change any existing output; provided for the tiered
# layer and its demo).
# ------------------------------------------------------------------------------
_TIER_BY_OUTCOME = {
    "confirmed": Tier.CONFIRMED, "signal": Tier.SIGNAL, "refuted": Tier.REFUTED,
    "notdata": Tier.NOT_DATA, "broken_for_all": Tier.INCONCLUSIVE, "skipped": Tier.SKIPPED,
}

_BADGE = {
    Tier.CONFIRMED: "[CONFIRMED]", Tier.SIGNAL: "[SIGNAL]", Tier.INCONCLUSIVE: "[INCONCLUSIVE]",
    Tier.REFUTED: "[REFUTED]", Tier.NOT_DATA: "[NOT DATA]", Tier.SKIPPED: "[SKIPPED]",
}


def tier_from_outcome(outcome: str) -> Tier:
    """Map an existing confirm_render/run_command tier string to the Tier enum."""
    return _TIER_BY_OUTCOME.get(outcome, Tier.NOT_DATA)


def badge(verdict: Verdict) -> str:
    """A short, honest label for a verdict's strength (reuses the engine's own bracket words)."""
    return _BADGE.get(verdict.tier, "[NOT DATA]")
