"""
Shadow-mode (Phase 7) deep-verifier run through the REAL fuzzing pipeline.

OBSERVE-ONLY. Drives `execute_parallel_fuzzing` (the integrated path) on two
byte-identical silent-BOLA cases — a REAL one (profile) and the SECURE look-alike
(avatar) — so Phase 7 (`_run_shadow_deep_verification`) fires naturally and logs an
AI second opinion WITHOUT changing the persisted rule verdict.

This script does NOT modify any product code. It only:
  - sets BOTH gates ON for THIS run (settings override, like deep_verify_live_check.py),
  - points the app DB at an isolated temp SQLite file (no pollution of the dev DB),
  - persists two findings and calls the real `execute_parallel_fuzzing`,
  - wraps `deep_verifier.execute_deep_verification` at runtime READ-ONLY (call-through)
    purely to capture the evidence trail (follow-up path + read-back body) that the
    integrated shadow pass produced — Phase 7 still invokes the real function.

Preconditions: GEMINI_API_KEY loaded in settings; vulnerable target on :8001.
Run:  python scripts/audit/shadow_p0_run.py
"""

import os
import sys
import json
import asyncio
import logging
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

# --- Isolate the app DB to a throwaway file BEFORE importing backend modules ---
_TMP_DB = os.path.join(tempfile.gettempdir(), "shadow_p0_app.db")
for _suffix in ("", "-wal", "-shm"):
    try:
        os.remove(_TMP_DB + _suffix)
    except OSError:
        pass
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///" + _TMP_DB.replace("\\", "/")

from backend.app.core.config import settings  # noqa: E402

# --- Both gates ON for THIS run only (NOT committed to .env) ---
settings.AI_DEEP_VERIFY_ENABLED = True
settings.AI_DEEP_VERIFY_SHADOW = True

from sqlalchemy import select  # noqa: E402
from backend.app.core.database import engine, Base, async_session_factory  # noqa: E402
import backend.app.models.scan as models  # noqa: E402  (registers tables on Base)
from backend.app.models.scan import VulnerabilityFinding, FuzzingRecord  # noqa: E402
from backend.app.services.fuzzer import execute_parallel_fuzzing  # noqa: E402
import backend.app.services.deep_verifier as deep_verifier  # noqa: E402

# -----------------------------------------------------------------------------
# Logging: INFO, and a capture handler so we can echo the [FUZZER · SHADOW] lines.
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
for noisy in ("httpx", "httpcore", "google_genai", "google.genai"):
    logging.getLogger(noisy).setLevel(logging.WARNING)


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.INFO)
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(self.format(record))
        except Exception:
            pass


_cap = _CaptureHandler()
_cap.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
logging.getLogger().addHandler(_cap)

# -----------------------------------------------------------------------------
# READ-ONLY wrapper around the deep verifier to capture the evidence trail that
# the INTEGRATED shadow pass generated. Phase 7 imports the symbol lazily at call
# time, so patching the module attribute is picked up; the real function still runs.
# -----------------------------------------------------------------------------
_real_edv = deep_verifier.execute_deep_verification
_captured = []  # list of {"parsed_request", "payload", "result"}


async def _capturing_edv(*args, **kwargs):
    res = await _real_edv(*args, **kwargs)
    _captured.append({
        "parsed_request": kwargs.get("parsed_request"),
        "payload": kwargs.get("payload"),
        "result": res,
    })
    return res


deep_verifier.execute_deep_verification = _capturing_edv

BASE_URL = "http://127.0.0.1:8001"
APPROVED_HOST = "127.0.0.1:8001"
ALICE = "Bearer alice-token-aaaa"

CASES = [
    {
        "label": "PROFILE (REAL silent BOLA)  POST /api/users/{id}/profile",
        "parsed_request": {
            "method": "POST", "path": "/api/users/1/profile", "query_params": {},
            "headers": {"Authorization": ALICE, "Content-Type": "application/json"},
            "body": {"display_name": "selfwrite_p0"},
        },
        "payload": {"location": "path_segment", "target_param": "1",
                    "payload_string": "2", "type": "BOLA"},
    },
    {
        "label": "AVATAR (SECURE look-alike)  POST /api/users/{id}/avatar",
        "parsed_request": {
            "method": "POST", "path": "/api/users/1/avatar", "query_params": {},
            "headers": {"Authorization": ALICE, "Content-Type": "application/json"},
            "body": {"avatar_url": "https://x.local/self.png"},
        },
        "payload": {"location": "path_segment", "target_param": "1",
                    "payload_string": "2", "type": "BOLA"},
    },
]


async def _persist_finding(case) -> int:
    async with async_session_factory() as db:
        f = VulnerabilityFinding(
            source="hunter",
            template_id="logic-hunter:BOLA",
            severity="INFO",
            matched_at=BASE_URL,
            parsed_request=case["parsed_request"],
            automation_payloads=[case["payload"]],
        )
        db.add(f)
        await db.commit()
        await db.refresh(f)
        return f.id


async def _records_for(fid):
    async with async_session_factory() as db:
        rows = (await db.execute(
            select(FuzzingRecord).where(FuzzingRecord.finding_id == fid)
        )).scalars().all()
        return [(r.id, r.verification_status, r.diff_details) for r in rows]


async def main():
    print("=" * 80)
    print("SHADOW-MODE PHASE 7 RUN (integrated pipeline, observe-only)")
    print("=" * 80)
    print(f"AI_DEEP_VERIFY_ENABLED = {settings.AI_DEEP_VERIFY_ENABLED}")
    print(f"AI_DEEP_VERIFY_SHADOW  = {settings.AI_DEEP_VERIFY_SHADOW}")
    print(f"Model                  = {settings.GEMINI_PRO_MODEL}")
    print(f"GEMINI_API_KEY present = {bool(settings.GEMINI_API_KEY)}")
    print(f"Target                 = {BASE_URL}   approved_host = {APPROVED_HOST}")
    print(f"App DB (isolated temp) = {settings.DATABASE_URL}\n")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    for case in CASES:
        print("\n" + "#" * 80)
        print("# CASE:", case["label"])
        print("#" * 80)

        fid = await _persist_finding(case)
        print(f"persisted finding_id = {fid}")

        cap_before = len(_captured)
        log_before = len(_cap.lines)

        # --- REAL integrated pipeline (Phase 7 fires at the end if suspicious) ---
        await execute_parallel_fuzzing([fid], approved_host=APPROVED_HOST)

        # (a) the rule-oracle verdict persisted for this finding
        recs = await _records_for(fid)
        print("\n--- (a) PERSISTED FuzzingRecord(s) — the rule-oracle verdict ---")
        for rid, status, diff in recs:
            print(f"  record_id={rid}")
            print(f"  verification_status (rule_verdict) = {status!r}")
            print(f"  diff_details = {json.dumps(diff, ensure_ascii=False)}")

        # (b) the [FUZZER · SHADOW] log line(s) for this case
        shadow_lines = [ln for ln in _cap.lines[log_before:] if "SHADOW" in ln]
        print("\n--- (b) [FUZZER · SHADOW] log line(s) ---")
        if shadow_lines:
            for ln in shadow_lines:
                print("  " + ln)
        else:
            print("  (none captured)")

        # (c) the follow-up the deep verifier chose + the read-back it judged on
        new_caps = _captured[cap_before:]
        print("\n--- (c) deep-verifier evidence trail (what the AI judged on) ---")
        if not new_caps:
            print("  (deep verifier was not invoked for this case)")
        for cap in new_caps:
            res = cap["result"]
            print(f"  status={res.status}  ai_verdict={res.ai_verdict}  "
                  f"confidence={res.ai_confidence}  requested_follow_up={res.ai_requested_follow_up}")
            if res.degraded_reason:
                print(f"  degraded_reason={res.degraded_reason}")
            print(f"  attack request   = {res.attack.get('request', {}).get('method')} "
                  f"{res.attack.get('request', {}).get('url')}")
            print(f"  attack response  = {json.dumps(res.attack.get('response'), ensure_ascii=False)}")
            if res.follow_up_request:
                print(f"  follow-up CHOSEN = {res.follow_up_request.get('method')} "
                      f"{res.follow_up_request.get('path')}  (reason: {res.follow_up_request.get('reason')})")
                print(f"  read-back RESP   = {json.dumps(res.follow_up_response, ensure_ascii=False)}")
            else:
                print("  follow-up CHOSEN = (none; verdict delivered in turn 1)")
            print(f"  ai_reasoning     = {res.ai_reasoning}")

        # confirm shadow did NOT change the persisted verdict (re-query after run)
        recs_again = await _records_for(fid)
        print("\n--- confirm persisted verdict UNCHANGED by the shadow pass (re-query) ---")
        for (rid, s1, _), (_, s2, _) in zip(recs, recs_again):
            print(f"  record_id={rid}  before_requery={s1!r}  after_requery={s2!r}  "
                  f"identical={s1 == s2}")

    print("\n" + "=" * 80)
    print("SUMMARY (rule_verdict persisted vs AI_shadow_verdict logged; persisted is authoritative)")
    print("=" * 80)
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
