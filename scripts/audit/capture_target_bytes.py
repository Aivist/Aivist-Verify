"""
Read-only VERBATIM byte capture from the local vulnerable target.

Validates that our offline oracle test inputs match reality. This script ONLY
sends raw HTTP and records exactly what comes back — no AI, no Gemini, no
deep_verifier, no _differential_verdict / fuzzer verdict path. It does not
normalize, prettify, or summarize any response body.

Precondition: the vulnerable target must already be running on
http://127.0.0.1:8001  (python -m uvicorn vulnerable_target.main:app --port 8001)

Run:  python scripts/audit/capture_target_bytes.py
"""

import httpx

BASE = "http://127.0.0.1:8001"
ALICE = "alice-token-aaaa"
BOB = "bob-token-bbbb"


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def capture(client, label, method, path, token, json_body=None):
    headers = _auth(token)
    url = BASE + path
    if method == "GET":
        resp = client.get(url, headers=headers)
    elif method == "POST":
        resp = client.post(url, headers=headers, json=json_body)
    else:
        raise ValueError(f"unsupported method {method}")

    print(f"=== {label}: {method} {path} (alice) ===")
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
        # Case A — blatant BOLA (object read)
        capture(client, "A1 baseline", "GET", "/api/orders/1", ALICE)
        capture(client, "A2 attack", "GET", "/api/orders/2", ALICE)

        # Case B — silent BOLA (object write) + read-back
        capture(client, "B0 read-before", "GET", "/api/users/2/profile", ALICE)
        capture(client, "B1 baseline", "POST", "/api/users/1/profile", ALICE,
                {"display_name": "selfwrite"})
        capture(client, "B2 attack", "POST", "/api/users/2/profile", ALICE,
                {"display_name": "PROBE_A"})
        capture(client, "B3 read-after", "GET", "/api/users/2/profile", ALICE)

        # Case SAFE — secure look-alike (the trap), same shape as B
        capture(client, "S0 read-before", "GET", "/api/users/2/avatar", ALICE)
        capture(client, "S1 baseline", "POST", "/api/users/1/avatar", ALICE,
                {"avatar_url": "https://x.local/self.png"})
        capture(client, "S2 attack", "POST", "/api/users/2/avatar", ALICE,
                {"avatar_url": "https://evil.example/pwn.png"})
        capture(client, "S3 read-after", "GET", "/api/users/2/avatar", ALICE)


if __name__ == "__main__":
    main()
