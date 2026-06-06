"""
Read-only VERBATIM byte capture from the local vulnerable target (round 2).

Same pattern as scripts/audit/capture_target_bytes.py: raw HTTP only — NO AI, NO
Gemini, NO deep_verifier, NO _differential_verdict / fuzzer verdict path. Bodies
are recorded EXACTLY as received: no normalization, no prettifying, no summarizing.

Covers the remaining read-type BOLA/IDOR family (orders / invoices / notes /
documents), the vertical priv-esc endpoint (admin/users, user vs admin), and an
unauthenticated rejection sanity check.

Precondition: the vulnerable target must already be running on
http://127.0.0.1:8001  (python -m uvicorn vulnerable_target.main:app --port 8001)

Run:  python scripts/audit/capture_target_bytes_2.py
"""

import httpx

BASE = "http://127.0.0.1:8001"
ALICE = "alice-token-aaaa"
BOB = "bob-token-bbbb"
CAROL = "carol-token-cccc"


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def capture(client, label, method, path, token, token_label):
    headers = _auth(token) if token is not None else {}
    url = BASE + path
    if method == "GET":
        resp = client.get(url, headers=headers)
    else:
        raise ValueError(f"unsupported method {method}")

    print(f"=== {label}: {method} {path} ({token_label}) ===")
    print(f"method: {method}")
    print(f"url: {url}")
    print(f"status_code: {resp.status_code}")
    print(f"Content-Length header: {resp.headers.get('content-length')}")
    print(f"len(content): {len(resp.content)}")
    print(f"body: {resp.text}")
    print()


def main():
    with httpx.Client(timeout=10.0) as client:
        # --- Read-type BOLA/IDOR family: baseline=own object, attack=cross-user ---
        capture(client, "ORD1", "GET", "/api/orders/1", ALICE, "alice")
        capture(client, "ORD2", "GET", "/api/orders/2", ALICE, "alice")
        capture(client, "INV1", "GET", "/api/invoices/1", ALICE, "alice")
        capture(client, "INV2", "GET", "/api/invoices/2", ALICE, "alice")
        capture(client, "NOTE1", "GET", "/api/notes/1", ALICE, "alice")
        capture(client, "NOTE2", "GET", "/api/notes/2", ALICE, "alice")
        capture(client, "DOC1", "GET", "/api/documents/1", ALICE, "alice")
        capture(client, "DOC2", "GET", "/api/documents/2", ALICE, "alice")

        # --- Vertical privilege escalation ---
        capture(client, "ADM_user", "GET", "/api/admin/users", ALICE, "alice -- role=user, should NOT be allowed")
        capture(client, "ADM_admin", "GET", "/api/admin/users", CAROL, "carol -- role=admin, legitimate baseline")

        # --- Sanity: unauthenticated rejection still works ---
        capture(client, "NOAUTH", "GET", "/api/invoices/2", None, "no Authorization header")


if __name__ == "__main__":
    main()
