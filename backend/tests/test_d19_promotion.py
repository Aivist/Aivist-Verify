# ==============================================================================
# D19 — conservative shadow->authoritative verdict promotion (OFFLINE invariant suite).
#
# This is the §5.1 acceptance table: it proves the promotion invariant with MOCKED verdicts
# and ZERO API calls. It exercises the REAL choke point (_code_authorized_channel), the REAL
# single writer (_promote_record_verified) against a real SQLite FuzzingRecord, and the REAL
# Phase-7 consumer (_run_shadow_deep_verification) with execute_deep_verification stubbed out.
#
# The one property every test defends: a promoted 'verified' can be produced ONLY when a
# deterministic code channel authorizes it. The model's raw opinion alone never promotes.
# Nothing here calls a model, boots a target, or touches the committed config defaults.
# ==============================================================================

import asyncio

import pytest
from sqlalchemy import select
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from backend.app.core.database import Base
from backend.app.core.config import settings
from backend.app.models.scan import VulnerabilityFinding, FuzzingRecord
from backend.app.services import fuzzer
from backend.app.services.fuzzer import (
    _FindingJob,
    _code_authorized_channel,
    _promote_record_verified,
    _run_shadow_deep_verification,
    _OWNER_VIEW_PROMOTION_CHANNEL,
)
from backend.app.services.deep_verifier import (
    DeepVerificationResult,
    WRITE_RECORD_EXEMPTION_REASON,
    STATE_READBACK_EXEMPTION_REASON,
    DELETE_READBACK_EXEMPTION_REASON,
    STATE_JUMP_EXEMPTION_REASON,
    CROSS_RESOURCE_OVERRIDE_REASON,
)

FOUR_CHANNELS = (
    WRITE_RECORD_EXEMPTION_REASON,
    STATE_READBACK_EXEMPTION_REASON,
    DELETE_READBACK_EXEMPTION_REASON,
    STATE_JUMP_EXEMPTION_REASON,
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def _mk(ai_verdict, *, guard_override=None, owner_view_corroborated=None,
        status="completed", ai_verdict_raw="__same__"):
    """A DeepVerificationResult carrying only the fields the choke point / writer read."""
    return DeepVerificationResult(
        status=status,
        ai_verdict=ai_verdict,
        ai_confidence=0.9,
        ai_reasoning="",
        ai_requested_follow_up=False,
        follow_up_request=None,
        follow_up_response=None,
        baseline={},
        attack={},
        model="test-model",
        approved_host="127.0.0.1:8001",
        ai_verdict_raw=(ai_verdict if ai_verdict_raw == "__same__" else ai_verdict_raw),
        guard_override=guard_override,
        owner_view_corroborated=owner_view_corroborated,
    )


def _job(finding_id=1, path="/api/orders/1"):
    return _FindingJob(
        finding_id=finding_id,
        parsed_request={"method": "GET", "path": path, "headers": {}, "body": None},
        base_url="http://127.0.0.1:8001",
        payloads=[{"target_param": "1", "payload_string": "2"}],
    )


# ---------------------------------------------------------------------------
# Isolated per-test SQLite bound into the fuzzer module (both the shadow read
# session and the promotion write session go through fuzzer.async_session_factory).
# ---------------------------------------------------------------------------
@pytest.fixture
def db(tmp_path, monkeypatch):
    url = "sqlite+aiosqlite:///" + str(tmp_path / "d19.db").replace("\\", "/")
    engine = create_async_engine(url, connect_args={"check_same_thread": False}, poolclass=NullPool)
    sm = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async def _create():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    asyncio.run(_create())

    # Route every session opened by the fuzzer at this test's throwaway DB.
    monkeypatch.setattr(fuzzer, "async_session_factory", sm, raising=True)

    yield sm
    asyncio.run(engine.dispose())


def _seed(sm, *, record_id="rec-1", finding_id=1, status="suspicious", diff=None):
    async def _go():
        async with sm() as s:
            s.add(VulnerabilityFinding(id=finding_id, template_id="d19-test",
                                       severity="high", matched_at="/x"))
            s.add(FuzzingRecord(id=record_id, finding_id=finding_id, payload_index=0,
                                verification_status=status,
                                diff_details=(diff if diff is not None
                                              else {"rule_oracle": "differential-diff"})))
            await s.commit()
    asyncio.run(_go())


def _read(sm, record_id="rec-1"):
    async def _go():
        async with sm() as s:
            rec = (await s.execute(
                select(FuzzingRecord).where(FuzzingRecord.id == record_id)
            )).scalar_one()
            return rec.verification_status, rec.diff_details
    return asyncio.run(_go())


def _run_shadow(job, result, monkeypatch, *, promote, shadow=True, enabled=True):
    """Drive the REAL Phase-7 consumer with execute_deep_verification stubbed to `result`."""
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", enabled, raising=False)
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_SHADOW", shadow, raising=False)
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_PROMOTE", promote, raising=False)
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_OWNER_AUTH", None, raising=False)

    async def _fake_execute(*args, **kwargs):
        if isinstance(result, Exception):
            raise result
        return result
    monkeypatch.setattr("backend.app.services.deep_verifier.execute_deep_verification",
                        _fake_execute, raising=True)
    asyncio.run(_run_shadow_deep_verification([job], None))


# ===========================================================================
# A. CHOKE POINT truth table (pure; no DB) — _code_authorized_channel
# ===========================================================================
@pytest.mark.parametrize("channel", FOUR_CHANNELS)
def test_choke_verified_plus_each_channel_authorizes(channel):
    assert _code_authorized_channel(_mk("verified", guard_override=channel)) == channel


def test_choke_verified_plus_owner_view_corroborated_true_authorizes():
    r = _mk("verified", guard_override=None, owner_view_corroborated=True)
    assert _code_authorized_channel(r) == _OWNER_VIEW_PROMOTION_CHANNEL


def test_choke_verified_with_no_authorizer_returns_none():
    # The load-bearing case: model raw-said 'verified' but no code channel and no owner-view.
    assert _code_authorized_channel(_mk("verified")) is None


def test_choke_verified_owner_view_false_or_none_not_authorized():
    assert _code_authorized_channel(_mk("verified", owner_view_corroborated=False)) is None
    assert _code_authorized_channel(_mk("verified", owner_view_corroborated=None)) is None


def test_choke_downgrade_override_is_not_an_authorizer():
    # A guard downgrade reason must never be mistaken for one of the four exemption channels.
    r = _mk("verified", guard_override=CROSS_RESOURCE_OVERRIDE_REASON)
    assert _code_authorized_channel(r) is None


@pytest.mark.parametrize("verdict", ["inconclusive", "failed", "suspicious", None])
def test_choke_non_verified_never_authorizes_even_with_channel(verdict):
    # ai_verdict != 'verified' short-circuits regardless of override/owner-view.
    r = _mk(verdict, guard_override=WRITE_RECORD_EXEMPTION_REASON, owner_view_corroborated=True)
    assert _code_authorized_channel(r) is None


# ===========================================================================
# B. SINGLE WRITER — _promote_record_verified against a real record
# ===========================================================================
def test_writer_promotes_suspicious_and_persists_evidence_chain(db):
    _seed(db)
    asyncio.run(_promote_record_verified(
        "rec-1", WRITE_RECORD_EXEMPTION_REASON, _mk("verified", guard_override=WRITE_RECORD_EXEMPTION_REASON),
    ))
    status, diff = _read(db)
    assert status == "verified"
    assert diff["rule_oracle"] == "differential-diff"          # rule diff preserved
    promo = diff["ai_promotion"]
    assert promo["authorizing_channel"] == WRITE_RECORD_EXEMPTION_REASON
    assert promo["promoted_from"] == "suspicious"
    assert promo["guard_override"] == WRITE_RECORD_EXEMPTION_REASON


@pytest.mark.parametrize("rule_status", ["verified", "failed", "untested"])
def test_writer_refuses_any_non_suspicious_row(db, rule_status):
    # D19 only ever touches the 'suspicious' band; the rule oracle's own verdicts are inviolate.
    _seed(db, status=rule_status, diff={"rule_oracle": "keep-me"})
    asyncio.run(_promote_record_verified(
        "rec-1", STATE_JUMP_EXEMPTION_REASON, _mk("verified", guard_override=STATE_JUMP_EXEMPTION_REASON),
    ))
    status, diff = _read(db)
    assert status == rule_status                 # untouched
    assert "ai_promotion" not in (diff or {})    # no promotion audit written


# ===========================================================================
# C. FULL CONSUMER — _run_shadow_deep_verification (real flag gating + choke + write)
# ===========================================================================
def test_promote_off_is_a_noop_even_with_an_authorized_result(db, monkeypatch):
    _seed(db)
    _run_shadow(_job(), _mk("verified", guard_override=DELETE_READBACK_EXEMPTION_REASON),
                monkeypatch, promote=False)
    status, diff = _read(db)
    assert status == "suspicious"                 # default OFF => byte-identical to shadow today
    assert "ai_promotion" not in (diff or {})


def test_promote_on_with_channel_promotes(db, monkeypatch):
    _seed(db)
    _run_shadow(_job(), _mk("verified", guard_override=STATE_JUMP_EXEMPTION_REASON),
                monkeypatch, promote=True)
    status, diff = _read(db)
    assert status == "verified"
    assert diff["ai_promotion"]["authorizing_channel"] == STATE_JUMP_EXEMPTION_REASON


def test_promote_on_read_semantic_owner_view_corroborated_promotes(db, monkeypatch):
    _seed(db)
    _run_shadow(_job(), _mk("verified", guard_override=None, owner_view_corroborated=True),
                monkeypatch, promote=True)
    status, diff = _read(db)
    assert status == "verified"
    assert diff["ai_promotion"]["authorizing_channel"] == _OWNER_VIEW_PROMOTION_CHANNEL
    assert diff["ai_promotion"]["owner_view_corroborated"] is True


def test_promote_on_model_verified_without_authorizer_stays_suspicious(db, monkeypatch):
    # THE load-bearing proof: promotion did not hand the model authority to create a verdict.
    _seed(db)
    _run_shadow(_job(), _mk("verified", guard_override=None, owner_view_corroborated=None),
                monkeypatch, promote=True)
    status, diff = _read(db)
    assert status == "suspicious"
    assert "ai_promotion" not in (diff or {})


def test_promote_on_owner_view_blocked_stays_suspicious(db, monkeypatch):
    _seed(db)
    _run_shadow(_job(), _mk("verified", guard_override=None, owner_view_corroborated=False),
                monkeypatch, promote=True)
    assert _read(db)[0] == "suspicious"


def test_promote_on_degraded_result_stays_suspicious_no_crash(db, monkeypatch):
    _seed(db)
    _run_shadow(_job(), _mk(None, status="degraded"), monkeypatch, promote=True)
    assert _read(db)[0] == "suspicious"


def test_promote_on_verifier_error_is_swallowed_rule_verdict_stands(db, monkeypatch):
    _seed(db)
    _run_shadow(_job(), RuntimeError("boom in the verifier"), monkeypatch, promote=True)
    assert _read(db)[0] == "suspicious"


def test_shadow_off_is_a_noop_even_with_promote_on(db, monkeypatch):
    _seed(db)
    _run_shadow(_job(), _mk("verified", guard_override=WRITE_RECORD_EXEMPTION_REASON),
                monkeypatch, promote=True, shadow=False)
    assert _read(db)[0] == "suspicious"


# ===========================================================================
# D. STRUCTURAL — the choke point is the SOLE gate; nothing bypasses it
# ===========================================================================
def test_structural_choke_point_is_the_only_gate(db, monkeypatch):
    # Force the choke point to authorize NOTHING; feed a result that legitimately HAS a channel.
    # If anything other than the choke point could promote, this record would flip. It must not.
    _seed(db)
    monkeypatch.setattr(fuzzer, "_code_authorized_channel", lambda result: None, raising=True)
    _run_shadow(_job(), _mk("verified", guard_override=WRITE_RECORD_EXEMPTION_REASON),
                monkeypatch, promote=True)
    assert _read(db)[0] == "suspicious"


def test_structural_no_authorizer_across_a_batch_promotes_zero(db, monkeypatch):
    # Mirrors the golden record's 79 raw-'verified' SAFE runs: with PROMOTE on, a model 'verified'
    # that no channel authorizes must promote ZERO of them.
    async def _seed_many():
        async with db() as s:
            s.add(VulnerabilityFinding(id=1, template_id="d19-test", severity="high", matched_at="/x"))
            for i in range(10):
                s.add(FuzzingRecord(id=f"rec-{i}", finding_id=1, payload_index=0,
                                    verification_status="suspicious", diff_details={"rule": i}))
            await s.commit()
    asyncio.run(_seed_many())

    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_SHADOW", True, raising=False)
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_PROMOTE", True, raising=False)
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_OWNER_AUTH", None, raising=False)

    async def _fake_execute(*a, **k):
        return _mk("verified", guard_override=None, owner_view_corroborated=None)
    monkeypatch.setattr("backend.app.services.deep_verifier.execute_deep_verification",
                        _fake_execute, raising=True)
    asyncio.run(_run_shadow_deep_verification([_job()], None))

    async def _count_verified():
        async with db() as s:
            rows = (await s.execute(select(FuzzingRecord))).scalars().all()
            return sum(1 for r in rows if r.verification_status == "verified")
    assert asyncio.run(_count_verified()) == 0
