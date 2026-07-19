# ==============================================================================
# Verification suite for the standalone Vulnerable Test Target.
#
# Proves every planted case is real (or, for the SAFE control, correctly secured),
# mirroring the main repo's test style (fastapi.testclient.TestClient against an
# ISOLATED, throwaway SQLite DB). The target reads its DB URL from the
# VULN_TARGET_DATABASE_URL env var, so we point it at a tmp file BEFORE importing
# the app — the real on-disk DB is never touched.
#
#   Vuln A — blatant BOLA (GET /api/orders/{id})              REAL
#   Vuln B — silent BOLA  (POST /api/users/{id}/profile)      REAL
#   Vuln C — vertical priv-esc (GET /api/admin/users)         REAL
#   Vuln D — silent BOLA  (POST /api/users/{id}/settings)     REAL
#   SAFE   — secured look-alike (POST /api/users/{id}/avatar) NOT vulnerable
#
# Run:  pytest vulnerable_target/test_vulns.py -v
# ==============================================================================

import os
import sys
import importlib

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

ALICE_TOKEN = "alice-token-aaaa"
BOB_TOKEN = "bob-token-bbbb"
CAROL_TOKEN = "carol-token-cccc"


@pytest.fixture
def client(tmp_path):
    """Isolated TestClient backed by a fresh per-test SQLite file."""
    db_file = tmp_path / "vuln_target_test.db"
    os.environ["VULN_TARGET_DATABASE_URL"] = "sqlite+aiosqlite:///" + str(db_file).replace("\\", "/")

    # Import (or reimport) the app AFTER the env var is set so the engine binds
    # to the throwaway DB. Reload guards against import order across tests.
    if "vulnerable_target.main" in sys.modules:
        target = importlib.reload(sys.modules["vulnerable_target.main"])
    else:
        target = importlib.import_module("vulnerable_target.main")

    from fastapi.testclient import TestClient

    # `with` runs the lifespan -> create_all + seed Alice & Bob.
    with TestClient(target.app) as c:
        yield c


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# -----------------------------------------------------------------------------
# Sanity: login + legitimate self-access work
# -----------------------------------------------------------------------------

def test_login_returns_token(client):
    resp = client.post("/login", json={"username": "alice"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"user_id": 1, "username": "alice", "role": "user", "token": ALICE_TOKEN}


def test_login_admin_carol_has_admin_role(client):
    resp = client.post("/login", json={"username": "carol"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"user_id": 3, "username": "carol", "role": "admin", "token": CAROL_TOKEN}


def test_alice_reads_own_order(client):
    resp = client.get("/api/orders/1", headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 200
    assert resp.json()["owner_id"] == 1
    assert resp.json()["item"] == "Vintage Typewriter"


# -----------------------------------------------------------------------------
# Vuln A — blatant BOLA: Alice's token reads Bob's order.
# -----------------------------------------------------------------------------

def test_vuln_a_alice_reads_bobs_order(client):
    alice_view = client.get("/api/orders/1", headers=_auth(ALICE_TOKEN))
    bob_order_via_alice = client.get("/api/orders/2", headers=_auth(ALICE_TOKEN))

    # The bug: Alice (authenticated) successfully reads Bob's order.
    assert bob_order_via_alice.status_code == 200
    body = bob_order_via_alice.json()
    assert body["owner_id"] == 2  # NOT Alice's id -> cross-user leak
    assert body["item"] == "Mechanical Keyboard Set + Artisan Keycaps Bundle"
    assert body["currency"] == "EUR"

    # And the responses differ in content + length, so a size/diff oracle catches it.
    assert alice_view.content != bob_order_via_alice.content
    assert len(alice_view.content) != len(bob_order_via_alice.content)


# -----------------------------------------------------------------------------
# Vuln B — silent BOLA: Alice overwrites Bob's profile; the write is only
# visible via a follow-up GET. The POST response is byte-identical regardless.
# -----------------------------------------------------------------------------

def test_vuln_b_alice_overwrites_bobs_profile(client):
    # Baseline: Bob's name is "Bob".
    before = client.get("/api/users/2/profile", headers=_auth(ALICE_TOKEN))
    assert before.status_code == 200
    assert before.json()["display_name"] == "Bob"

    # Alice (her token) writes to Bob's profile (user_id=2).
    write = client.post(
        "/api/users/2/profile",
        headers=_auth(ALICE_TOKEN),
        json={"display_name": "PWNED_BY_ALICE"},
    )
    # Opaque, constant success response — no signal that a cross-user write occurred.
    assert write.status_code == 200
    assert write.json() == {"status": "ok"}

    # The ONLY way to observe the write: read it back.
    after = client.get("/api/users/2/profile", headers=_auth(ALICE_TOKEN))
    assert after.status_code == 200
    assert after.json()["display_name"] == "PWNED_BY_ALICE"  # Bob's name changed


def test_vuln_b_response_is_indistinguishable_self_vs_cross(client):
    """A single-shot diff oracle can't tell a self-write from a cross-write:
    the status, length, and body are identical in both cases."""
    self_write = client.post(
        "/api/users/1/profile",
        headers=_auth(ALICE_TOKEN),
        json={"display_name": "Alice2"},
    )
    cross_write = client.post(
        "/api/users/2/profile",  # Bob, via Alice's token
        headers=_auth(ALICE_TOKEN),
        json={"display_name": "Alice2"},
    )

    assert self_write.status_code == cross_write.status_code == 200
    assert self_write.content == cross_write.content
    assert len(self_write.content) == len(cross_write.content)

    # Yet the cross write really happened (only a read-back reveals it).
    after = client.get("/api/users/2/profile", headers=_auth(BOB_TOKEN))
    assert after.json()["display_name"] == "Alice2"


# -----------------------------------------------------------------------------
# Vuln C — vertical privilege escalation: a normal user reaches the admin-only
# roster endpoint and receives the full user list (including roles).
# -----------------------------------------------------------------------------

def test_vuln_c_normal_user_gets_admin_roster(client):
    resp = client.get("/api/admin/users", headers=_auth(ALICE_TOKEN))

    # The bug: Alice (role=user) is authenticated but the endpoint never checks
    # for admin, so she gets the privileged roster.
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 3
    by_id = {u["id"]: u for u in body["users"]}
    # The response is richer than any normal-user endpoint: all users + their roles.
    assert by_id[1]["username"] == "alice" and by_id[1]["role"] == "user"
    assert by_id[2]["username"] == "bob" and by_id[2]["role"] == "user"
    # Crucially, a normal user learns that Carol is an admin — a real boundary cross.
    assert by_id[3]["username"] == "carol" and by_id[3]["role"] == "admin"


def test_vuln_c_admin_gets_same_roster(client):
    """Sanity: the admin (Carol) is *supposed* to see this — same payload."""
    alice_view = client.get("/api/admin/users", headers=_auth(ALICE_TOKEN))
    carol_view = client.get("/api/admin/users", headers=_auth(CAROL_TOKEN))
    assert carol_view.status_code == 200
    # The escalation is that the normal user gets the SAME data the admin gets.
    assert alice_view.json() == carol_view.json()


# -----------------------------------------------------------------------------
# Vuln D — silent BOLA regression: Alice overwrites Bob's setting; only a
# follow-up GET reveals it. Same shape/oracle as Vuln B, on a fresh endpoint.
# -----------------------------------------------------------------------------

def test_vuln_d_alice_overwrites_bobs_settings(client):
    before = client.get("/api/users/2/settings", headers=_auth(ALICE_TOKEN))
    assert before.status_code == 200
    assert before.json()["notifications"] == "sms"  # Bob's seeded value

    write = client.post(
        "/api/users/2/settings",
        headers=_auth(ALICE_TOKEN),
        json={"notifications": "PWNED_CHANNEL"},
    )
    assert write.status_code == 200
    assert write.json() == {"status": "ok"}  # opaque, gives nothing away

    after = client.get("/api/users/2/settings", headers=_auth(ALICE_TOKEN))
    assert after.status_code == 200
    assert after.json()["notifications"] == "PWNED_CHANNEL"  # cross-user write LANDED


def test_vuln_d_response_indistinguishable_self_vs_cross(client):
    self_write = client.post(
        "/api/users/1/settings", headers=_auth(ALICE_TOKEN), json={"notifications": "weekly"}
    )
    cross_write = client.post(
        "/api/users/2/settings", headers=_auth(ALICE_TOKEN), json={"notifications": "weekly"}
    )
    assert self_write.status_code == cross_write.status_code == 200
    assert self_write.content == cross_write.content  # byte-identical


# -----------------------------------------------------------------------------
# SAFE control — looks identical to Vuln B/D (same opaque 200 ok) but ownership
# IS enforced: a cross-user write is silently dropped, so the read-back shows the
# value UNCHANGED. The correct verdict is NOT vulnerable.
# -----------------------------------------------------------------------------

def test_safe_cross_user_write_does_not_land(client):
    before = client.get("/api/users/2/avatar", headers=_auth(ALICE_TOKEN))
    assert before.status_code == 200
    original = before.json()["avatar_url"]
    assert original == "https://avatars.local/bob.png"

    # Alice attempts to overwrite Bob's avatar — SAME opaque 200 ok as Vuln D.
    write = client.post(
        "/api/users/2/avatar",
        headers=_auth(ALICE_TOKEN),
        json={"avatar_url": "https://evil.example/pwn.png"},
    )
    assert write.status_code == 200
    assert write.json() == {"status": "ok"}  # NOT a 403 — that is the trap

    # Read-back: UNCHANGED. The cross-user write was silently ignored.
    after = client.get("/api/users/2/avatar", headers=_auth(ALICE_TOKEN))
    assert after.status_code == 200
    assert after.json()["avatar_url"] == original  # secure → write did NOT land


def test_safe_response_matches_vulnerable_shape_but_secure(client):
    """The POST response is byte-identical to the (vulnerable) settings endpoint,
    proving a single-shot oracle cannot distinguish them — only the read-back can."""
    safe_cross = client.post(
        "/api/users/2/avatar", headers=_auth(ALICE_TOKEN),
        json={"avatar_url": "https://evil.example/pwn.png"},
    )
    vuln_cross = client.post(
        "/api/users/2/settings", headers=_auth(ALICE_TOKEN),
        json={"notifications": "x"},
    )
    assert safe_cross.status_code == vuln_cross.status_code == 200
    assert safe_cross.content == vuln_cross.content  # identical {"status":"ok"}


def test_safe_owner_write_does_land(client):
    """Sanity: the SAFE endpoint is functional — the legitimate owner CAN update."""
    write = client.post(
        "/api/users/2/avatar",
        headers=_auth(BOB_TOKEN),  # Bob updating his OWN avatar
        json={"avatar_url": "https://avatars.local/bob-new.png"},
    )
    assert write.status_code == 200
    after = client.get("/api/users/2/avatar", headers=_auth(BOB_TOKEN))
    assert after.json()["avatar_url"] == "https://avatars.local/bob-new.png"


# -----------------------------------------------------------------------------
# X-SILENT-VULN (M1.2(A)) — silent cross-path WRITE confirmed by the object's OWN STATE
# read on a DIFFERENT path. Alice overwrites Bob's gizmo `code`; the POST is an opaque
# 200 {"status":"ok"} (no same-path GET at all); the ONLY observation is the cross-path
# state read GET /api/gizmos/2. Ground truth: REAL — a landed cross-user write.
# -----------------------------------------------------------------------------

_UNIQUE = "gz-unique-7c3f9a12e4b"  # a fuzzer-style unique value (not a common enum)


def test_x_silent_vuln_cross_user_write_lands_in_state(client):
    # Baseline: Bob's gizmo state (via the cross-path state read) is the seeded value.
    before = client.get("/api/gizmos/2", headers=_auth(ALICE_TOKEN))
    assert before.status_code == 200
    assert before.json() == {"id": 2, "owner_id": 2, "code": "gizmo_bob_v0"}

    # Alice (her token) writes a UNIQUE value to Bob's gizmo (user_id=2). Opaque success.
    write = client.post(
        "/api/users/2/gizmo", headers=_auth(ALICE_TOKEN), json={"code": _UNIQUE}
    )
    assert write.status_code == 200
    assert write.json() == {"status": "ok"}  # gives nothing away about whose code changed

    # The ONLY way to observe it: the cross-path STATE read. The write LANDED on Bob's object.
    after = client.get("/api/gizmos/2", headers=_auth(ALICE_TOKEN))
    assert after.status_code == 200
    assert after.json() == {"id": 2, "owner_id": 2, "code": _UNIQUE}  # victim's state carries our value


def test_x_silent_vuln_has_no_same_path_get(client):
    # There is deliberately NO GET on the write path -> a same-path read-back is impossible;
    # confirmation MUST be cross-path. FastAPI answers 405 (path exists, method not allowed).
    resp = client.get("/api/users/2/gizmo", headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 405


# -----------------------------------------------------------------------------
# X-SILENT-SAFE (M1.2(A)) — SECURE mirror of X-SILENT-VULN. SAME opaque 200 on the write,
# but ownership IS enforced: a cross-user write is silently dropped, so the cross-path
# state read shows the value UNCHANGED. Ground truth: SECURE — a `verified` is a FALSE POSITIVE.
# -----------------------------------------------------------------------------

def test_x_silent_safe_cross_user_write_does_not_land(client):
    before = client.get("/api/sprockets/2", headers=_auth(ALICE_TOKEN))
    assert before.status_code == 200
    assert before.json() == {"id": 2, "owner_id": 2, "code": "sprocket_bob_v0"}

    # Alice attempts to overwrite Bob's sprocket — SAME opaque 200 ok as the vulnerable gizmo.
    write = client.post(
        "/api/users/2/sprocket", headers=_auth(ALICE_TOKEN), json={"code": _UNIQUE}
    )
    assert write.status_code == 200
    assert write.json() == {"status": "ok"}  # NOT a 403 — that is the trap

    # Cross-path STATE read: UNCHANGED. The unique value is ABSENT -> the write was dropped.
    after = client.get("/api/sprockets/2", headers=_auth(ALICE_TOKEN))
    assert after.status_code == 200
    assert after.json() == {"id": 2, "owner_id": 2, "code": "sprocket_bob_v0"}
    assert _UNIQUE not in after.text  # the causality signal the exemption gates on is absent


def test_x_silent_safe_owner_write_does_land(client):
    # Sanity: the SAFE endpoint is functional — the legitimate owner CAN update his own.
    write = client.post(
        "/api/users/2/sprocket", headers=_auth(BOB_TOKEN), json={"code": _UNIQUE}
    )
    assert write.status_code == 200
    after = client.get("/api/sprockets/2", headers=_auth(BOB_TOKEN))
    assert after.json() == {"id": 2, "owner_id": 2, "code": _UNIQUE}


def test_x_silent_vuln_and_safe_write_responses_are_byte_identical(client):
    # A single-shot oracle cannot tell the REAL silent write from the SECURE one: same
    # status, same bytes on the write response. Only the cross-path STATE read separates them.
    vuln = client.post(
        "/api/users/2/gizmo", headers=_auth(ALICE_TOKEN), json={"code": _UNIQUE}
    )
    safe = client.post(
        "/api/users/2/sprocket", headers=_auth(ALICE_TOKEN), json={"code": _UNIQUE}
    )
    assert vuln.status_code == safe.status_code == 200
    assert vuln.content == safe.content  # identical {"status":"ok"}


# -----------------------------------------------------------------------------
# Auth is still required (the bugs are authorization bugs, not "no auth at all").
# -----------------------------------------------------------------------------

def test_missing_token_is_rejected(client):
    assert client.get("/api/orders/2").status_code == 401
    assert client.get("/api/orders/2", headers=_auth("not-a-real-token")).status_code == 401
    # New endpoints enforce authentication too (they only skip *authorization*).
    assert client.get("/api/admin/users").status_code == 401
    assert client.get("/api/users/2/settings").status_code == 401
    assert client.get("/api/users/2/avatar").status_code == 401
    assert client.get("/api/gizmos/2").status_code == 401
    assert client.get("/api/sprockets/2").status_code == 401
