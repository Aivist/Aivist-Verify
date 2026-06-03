# ==============================================================================
# Live manual check for the isolated AI-in-the-loop deep verifier.
#
# This is a COMMITTED helper script (not a pytest test) — it requires the live
# vulnerable target on http://127.0.0.1:8001 AND Gemini network access, so it is
# deliberately NOT placed under backend/tests/ (it must not affect the 73-test
# suite or its count, and must not run in CI).
#
# It enables settings.AI_DEEP_VERIFY_ENABLED at runtime (the default stays False)
# and runs execute_deep_verification for three cases, printing the verbatim model
# JSON per turn plus the structured, auditable result.
#
# Run (with the target freshly re-seeded):
#   python backend/scripts/deep_verify_live_check.py
# ==============================================================================

import os
import sys
import json
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.core.config import settings

# Enable the (otherwise default-off) deep verifier for this manual run only.
settings.AI_DEEP_VERIFY_ENABLED = True

from backend.app.services.deep_verifier import execute_deep_verification  # noqa: E402

BASE_URL = "http://127.0.0.1:8001"
ALICE_AUTH = {"Authorization": "Bearer alice-token-aaaa"}

IDENTITY_NOTE = (
    "You are acting as Alice: user id = 1, role = 'user' (a NORMAL, non-admin user). "
    "Authorization model: a user may only read/write their OWN objects (Alice's own "
    "id = 1); admin-only endpoints require role = 'admin'."
)

# The discoverable API surface a real integration would supply (from the API spec /
# HAR / proxy capture). Lets the model request the CORRECT read-back endpoint.
AVAILABLE_ENDPOINTS = [
    "GET  /api/orders/{id}",
    "GET  /api/users/{id}/profile",
    "POST /api/users/{id}/profile",
    "GET  /api/users/{id}/settings",
    "POST /api/users/{id}/settings",
    "GET  /api/users/{id}/avatar",
    "POST /api/users/{id}/avatar",
    "GET  /api/admin/users",
]

CASES = [
    {
        "label": "Vuln D — POST /api/users/{id}/settings (expect: verified)",
        "parsed_request": {
            "method": "POST", "path": "/api/users/1/settings", "query_params": {},
            "headers": {"Content-Type": "application/json"},
            "body": {"notifications": "PWNED_CHANNEL"},
        },
        "payload": {"location": "path_segment", "target_param": "1",
                    "payload_string": "2", "type": "BOLA"},
        "context_note": IDENTITY_NOTE,
    },
    {
        "label": "SAFE — POST /api/users/{id}/avatar (expect: failed / not vulnerable)",
        "parsed_request": {
            "method": "POST", "path": "/api/users/1/avatar", "query_params": {},
            "headers": {"Content-Type": "application/json"},
            "body": {"avatar_url": "https://evil.example/pwn.png"},
        },
        "payload": {"location": "path_segment", "target_param": "1",
                    "payload_string": "2", "type": "BOLA"},
        "context_note": IDENTITY_NOTE,
    },
    {
        "label": "Vuln C — GET /api/admin/users (expect: verified)",
        "parsed_request": {
            "method": "GET", "path": "/api/admin/users", "query_params": {},
            "headers": {}, "body": None,
        },
        "payload": None,  # read-only: no mutation
        "context_note": (
            IDENTITY_NOTE
            + " NOTE: GET /api/admin/users is an ADMIN-ONLY endpoint that returns the "
            "full user roster including every user's role."
        ),
    },
]


async def main():
    print(f"AI_DEEP_VERIFY_ENABLED = {settings.AI_DEEP_VERIFY_ENABLED}")
    print(f"Model                  = {settings.GEMINI_PRO_MODEL}")
    print(f"Target                 = {BASE_URL}\n")

    summary = []
    for case in CASES:
        print("#" * 78)
        print("# CASE:", case["label"])
        print("#" * 78)

        result = await execute_deep_verification(
            parsed_request=case["parsed_request"],
            payload=case["payload"],
            base_url=BASE_URL,
            approved_host=None,            # derived from base_url -> 127.0.0.1:8001
            auth_context=ALICE_AUTH,
            context_note=case["context_note"],
            available_endpoints=AVAILABLE_ENDPOINTS,
        )

        print(f"\nstatus={result.status}  ai_verdict={result.ai_verdict}  "
              f"confidence={result.ai_confidence}  requested_follow_up={result.ai_requested_follow_up}")
        if result.degraded_reason:
            print("degraded_reason:", result.degraded_reason)

        if result.follow_up_request:
            print("\n-- follow-up the AI requested --")
            print(json.dumps(result.follow_up_request, indent=2))
            print("-- raw response fed back --")
            print(json.dumps(result.follow_up_response, indent=2))

        for i, raw in enumerate(result.turns_raw, 1):
            print(f"\n----- VERBATIM MODEL JSON · turn {i} -----")
            print(raw)

        print("\n----- FULL STRUCTURED RESULT (evidence trail) -----")
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        print()
        summary.append((case["label"], result.status, result.ai_verdict))

    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)
    for label, status, verdict in summary:
        print(f"  [{status:9s}] verdict={verdict!s:11s} {label}")


if __name__ == "__main__":
    asyncio.run(main())
