"""
Read-only VERBATIM byte capture for the D18 Phase-2 cross-path cases (GT-A..GT-E).

Same pattern as scripts/audit/capture_target_bytes_2.py: raw HTTP only — NO AI, NO
Gemini, NO deep_verifier, NO _differential_verdict / fuzzer verdict path. Bodies are
recorded EXACTLY as received: no normalization, prettifying, or summarizing.

The sequence is STATEFUL and ORDER-DEPENDENT (writes then cross-path read-backs), so
it must run top-to-bottom against a FRESH-seeded target.

Precondition: the vulnerable target must be running on http://127.0.0.1:8001 with the
new Identity/AuditEvent tables seeded (restart on a fresh DB).

Run:  python scripts/audit/capture_phase2_crosspath.py
"""

import httpx

BASE = "http://127.0.0.1:8001"
ALICE = "alice-token-aaaa"
BOB = "bob-token-bbbb"


def _auth(token):
    return {"Authorization": f"Bearer {token}"} if token is not None else {}


def capture(client, label, method, path, token, token_label, json_body=None):
    headers = _auth(token)
    url = BASE + path
    if method == "GET":
        resp = client.get(url, headers=headers)
    elif method == "POST":
        resp = client.post(url, headers=headers, json=json_body)
    else:
        raise ValueError(f"unsupported method {method}")

    print(f"=== {label}: {method} {path} ({token_label}) ===")
    print(f"method: {method}")
    print(f"url: {url}")
    print(f"request body: {json_body!r}")
    print(f"status_code: {resp.status_code}")
    print(f"Content-Length header: {resp.headers.get('content-length')}")
    print(f"len(content): {len(resp.content)}")
    print(f"body: {resp.text}")
    print()


def main():
    with httpx.Client(timeout=10.0) as client:
        # GT-A — REAL cross-path BOLA: Alice writes Bob's display_name, confirm via audit-log
        capture(client, "GT-A1", "POST", "/api/users/2/display-name", ALICE, "alice",
                {"display_name": "PWNED_DN"})
        capture(client, "GT-A2", "GET", "/api/audit-log", ALICE, "alice")

        # GT-B — there is NO same-path GET for display-name
        capture(client, "GT-B", "GET", "/api/users/2/display-name", ALICE, "alice")

        # GT-C — SAFE control: Alice's cross-user nickname write is dropped (no audit row)
        capture(client, "GT-C1", "POST", "/api/users/2/nickname", ALICE, "alice",
                {"nickname": "PWNED_NICK"})
        capture(client, "GT-C2", "GET", "/api/audit-log", ALICE, "alice")

        # GT-D — owner write lands + audits: Bob updates his own nickname
        capture(client, "GT-D1", "POST", "/api/users/2/nickname", BOB, "bob",
                {"nickname": "bob_new"})
        capture(client, "GT-D2", "GET", "/api/audit-log", ALICE, "alice")

        # GT-E — auth required on both the write and the cross-path read-back
        capture(client, "GT-E1", "POST", "/api/users/2/display-name", None, "no token",
                {"display_name": "x"})
        capture(client, "GT-E2", "GET", "/api/audit-log", None, "no token")


if __name__ == "__main__":
    main()
