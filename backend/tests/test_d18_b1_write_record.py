# ==============================================================================
# Offline unit tests for B-1 (deterministic write-record gathering + guard exemption).
#
# These assert the DETERMINISTIC, target-agnostic machinery directly — NO live model,
# NO network. The point of this file is to prove, without Gemini, the two properties
# the live measurement cannot guarantee by itself:
#
#   1. GENERICITY (anti-hardcoding): the write-record classifier/selector identifies a
#      record/log/history endpoint on a COMPLETELY DIFFERENT, made-up spec that contains
#      NO "/api/audit-log", NO "audit" tag, NO target field. If this passes on a foreign
#      spec, the logic is structural, not hardcoded to the practice target.
#   2. SAFETY (the X-SAFE gate): the structural content match REQUIRES the attacked object
#      id AND a value THIS attack wrote to appear TOGETHER in a single record (equality,
#      not substring). A secure cross-path control — whose only audit row is the BASELINE
#      self-write on a DIFFERENT id — must FAIL the match, so the exemption never fires and
#      it stays inconclusive. A false match here would reopen the integrity hole.
# ==============================================================================

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from vulnerable_target.main import app
from backend.app.services.endpoint_catalog import (
    catalog_from_openapi,
    is_write_record_entry,
    select_write_record_endpoint,
    has_same_path_readback,
)
from backend.app.services.deep_verifier import (
    _apply_cross_resource_guard,
    _attacked_object_id,
    _written_values,
    _write_record_content_match,
    _path_is_write_record,
    _is_owner_key,
    _field_tokens,
    CROSS_RESOURCE_OVERRIDE_REASON,
    WRITE_RECORD_EXEMPTION_REASON,
)


# A COMPLETELY DIFFERENT, made-up API surface — no "/api/audit-log", no "audit" tag, no
# target field/path. Used to prove the classifier is generic, not hardcoded.
FOREIGN_CATALOG = [
    "POST /v1/widgets/{widget_id}/rename  [tags: widgets; operationId: rename_widget]",
    "GET /v1/widgets/{widget_id}  [tags: widgets; operationId: get_widget]",
    "GET /v1/activity-history  [tags: telemetry; operationId: list_activity_history]",
    "GET /api/blogs/{blog_id}  [tags: blog; operationId: get_blog]",   # 'blog' contains 'log' but must NOT match
    "GET /api/catalog/{sku}  [tags: catalog; operationId: get_catalog_item]",  # 'catalog' contains 'log' but must NOT match
    "POST /v1/login  [tags: auth; operationId: login]",               # 'login' contains 'log' but is POST + not a token match
]


# -----------------------------------------------------------------------------
# 1. GENERICITY — classifier/selector work on a foreign spec, reject substrings
# -----------------------------------------------------------------------------

def test_classifier_matches_generic_record_endpoint_on_foreign_spec():
    assert is_write_record_entry(
        "GET /v1/activity-history  [tags: telemetry; operationId: list_activity_history]"
    ) is True


def test_classifier_is_whole_token_not_substring():
    # 'blog', 'catalog', 'login' all CONTAIN 'log' as a substring but are NOT records.
    assert is_write_record_entry("GET /api/blogs/{blog_id}  [tags: blog; operationId: get_blog]") is False
    assert is_write_record_entry("GET /api/catalog/{sku}  [tags: catalog; operationId: get_catalog_item]") is False
    assert is_write_record_entry("GET /v1/login  [tags: auth; operationId: login]") is False


def test_classifier_requires_get():
    # A POST to an audit/log endpoint is not a READ-back of a record.
    assert is_write_record_entry("POST /v1/audit-log  [tags: audit; operationId: write_audit]") is False


def test_selector_picks_record_on_foreign_spec_without_hardcoding():
    chosen = select_write_record_endpoint(FOREIGN_CATALOG)
    assert chosen == "/v1/activity-history"


def test_selector_returns_none_when_no_record_endpoint():
    no_record = [
        "GET /v1/widgets/{widget_id}  [tags: widgets; operationId: get_widget]",
        "POST /v1/widgets/{widget_id}/rename  [tags: widgets; operationId: rename_widget]",
    ]
    assert select_write_record_endpoint(no_record) is None


def test_selector_fills_template_param_with_attacked_id():
    templated = ["GET /v1/users/{user_id}/history  [tags: x; operationId: user_history]"]
    assert select_write_record_endpoint(templated, attacked_object_id="2") == "/v1/users/2/history"


# -----------------------------------------------------------------------------
# 1b. On the REAL target spec the generic selector lands on the audit-log (by
#     structure, via the same rule that worked on the foreign spec above).
# -----------------------------------------------------------------------------

def test_selector_on_real_target_resolves_to_audit_log():
    catalog = catalog_from_openapi(app.openapi())
    assert select_write_record_endpoint(catalog) == "/api/audit-log"


def test_same_path_readback_detection_crosspath_vs_samepath():
    catalog = catalog_from_openapi(app.openapi())
    # display-name / nickname have NO real GET read-back -> cross-path (False).
    assert has_same_path_readback(catalog, "/api/users/2/display-name") is False
    assert has_same_path_readback(catalog, "/api/users/2/nickname") is False
    # profile / avatar DO have a templated GET read-back -> same-path (True).
    assert has_same_path_readback(catalog, "/api/users/2/profile") is True
    assert has_same_path_readback(catalog, "/api/users/2/avatar") is True


def test_same_path_readback_ignores_concrete_placeholder_on_other_id():
    # A concrete placeholder GET on the BASELINE id (1) must NOT count as a same-path
    # read-back for the ATTACK id (2).
    catalog = ["GET /api/users/1/display-name", "POST /api/users/1/display-name"]
    assert has_same_path_readback(catalog, "/api/users/2/display-name") is False


# -----------------------------------------------------------------------------
# 2. SAFETY — structural content match (the X-SAFE gate)
# -----------------------------------------------------------------------------

# X-CROSS (REAL): baseline self-write (user 1) AND attack cross-write (user 2) both
# landed and were audited. A record links the ATTACKED id (2) to the written value.
XCROSS_AUDIT = (
    '{"events":['
    '{"id":1,"event":"display_name.update","user_id":1,"new_value":"xcross_attack_r2"},'
    '{"id":2,"event":"display_name.update","user_id":2,"new_value":"xcross_attack_r2"}'
    ']}'
)

# X-SAFE (SECURE): only the baseline self-write (user 1) was audited; the cross-user
# attack was silently dropped -> NO record for the attacked id (2). The written value IS
# present (on the user-1 row) — the match must STILL fail because it is not on id 2.
XSAFE_AUDIT = (
    '{"events":['
    '{"id":1,"event":"nickname.update","user_id":1,"new_value":"xsafe_attack_r2"}'
    ']}'
)

# A same-named-field read-back on a DIFFERENT resource showing the OLD value.
PROFILE_READBACK = '{"user_id":2,"display_name":"Bob"}'


def test_content_match_true_for_xcross_landed_write():
    assert _write_record_content_match(XCROSS_AUDIT, "2", ["xcross_attack_r2"]) is True


def test_content_match_false_for_xsafe_only_baseline_row():
    # CRITICAL SAFETY: written value present (on the user-1 row) but attacked id 2 is NOT
    # in that record -> must be False (no exemption -> stays inconclusive).
    assert _write_record_content_match(XSAFE_AUDIT, "2", ["xsafe_attack_r2"]) is False


def test_content_match_not_substring_on_id():
    # The attacked id "2" appears as a SUBSTRING of "xsafe_attack_r2" but is not a scalar
    # value of any record -> must NOT match.
    body = '{"events":[{"id":1,"user_id":1,"new_value":"xsafe_attack_r2"}]}'
    assert _write_record_content_match(body, "2", ["xsafe_attack_r2"]) is False


def test_content_match_false_for_old_value_same_named_field():
    assert _write_record_content_match(PROFILE_READBACK, "2", ["xcross_attack_r2"]) is False


def test_content_match_false_for_empty_log():
    assert _write_record_content_match('{"events":[]}', "2", ["xcross_attack_r2"]) is False


def test_content_match_false_for_non_json():
    assert _write_record_content_match("not json at all", "2", ["xcross_attack_r2"]) is False


def test_content_match_false_when_inputs_missing():
    assert _write_record_content_match(XCROSS_AUDIT, None, ["xcross_attack_r2"]) is False
    assert _write_record_content_match(XCROSS_AUDIT, "2", []) is False
    assert _write_record_content_match("", "2", ["xcross_attack_r2"]) is False


# -----------------------------------------------------------------------------
# 2b. Runtime-param extraction (target-agnostic)
# -----------------------------------------------------------------------------

def test_attacked_object_id_from_path_diff():
    assert _attacked_object_id(
        "/api/users/1/display-name", "/api/users/2/display-name",
        {"location": "path_segment", "payload_string": "2"},
    ) == "2"


def test_attacked_object_id_falls_back_to_payload_string():
    # Identical paths (no diff) -> fall back to the BOLA payload_string.
    assert _attacked_object_id("/x", "/x", {"payload_string": "9"}) == "9"


def test_written_values_from_dict_body():
    assert _written_values({"body": {"display_name": "xcross_attack_r2"}}) == ["xcross_attack_r2"]


def test_path_is_write_record_generic():
    assert _path_is_write_record("/api/audit-log") is True
    assert _path_is_write_record("/v1/activity-history") is True
    assert _path_is_write_record("/api/users/2/profile") is False
    assert _path_is_write_record("/login") is False


# -----------------------------------------------------------------------------
# 3. GUARD EXEMPTION — verified+cross-path only exempt WITH content match
# -----------------------------------------------------------------------------

ATTACK = "/api/users/2/display-name"
RECORD = "/api/audit-log"


def test_exemption_fires_for_verified_with_content_match():
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK, RECORD, follow_up_performed=True, write_record_decisive=True
    )
    assert final == "verified"
    assert reason == WRITE_RECORD_EXEMPTION_REASON


def test_no_exemption_for_verified_without_content_match():
    # Write-record flagged but content match FAILED -> stays inconclusive (X-SAFE path).
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK, RECORD, follow_up_performed=True, write_record_decisive=False
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_exemption_does_not_apply_to_failed():
    # A record's PRESENCE can only prove a write happened (verified); 'failed' is never
    # exempted by it.
    final, reason = _apply_cross_resource_guard(
        "failed", ATTACK, RECORD, follow_up_performed=True, write_record_decisive=True
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_exemption_unneeded_for_same_path():
    # Same-path read-back is already decisive; exemption flag is irrelevant.
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK, ATTACK, follow_up_performed=True, write_record_decisive=True
    )
    assert final == "verified"
    assert reason is None


def test_backward_compatible_default_no_exemption():
    # Existing 4-arg callers (no write_record_decisive) keep the original downgrade.
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK, RECORD, follow_up_performed=True
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


# -----------------------------------------------------------------------------
# 3b. End-to-end OFFLINE safety composition: X-SAFE can never be exempted.
# -----------------------------------------------------------------------------

def test_xsafe_end_to_end_stays_inconclusive_offline():
    # Even if the model returned 'verified' on X-SAFE, the content match fails (no record
    # for the attacked id) -> guard downgrades -> inconclusive. The integrity hole stays shut.
    content_match = _write_record_content_match(XSAFE_AUDIT, "2", ["xsafe_attack_r2"])
    assert content_match is False
    final, reason = _apply_cross_resource_guard(
        "verified", "/api/users/2/nickname", RECORD,
        follow_up_performed=True, write_record_decisive=content_match,
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_xcross_end_to_end_can_reach_verified_offline():
    # X-CROSS: a record links attacked id 2 to the written value -> exemption -> verified.
    content_match = _write_record_content_match(XCROSS_AUDIT, "2", ["xcross_attack_r2"])
    assert content_match is True
    final, reason = _apply_cross_resource_guard(
        "verified", "/api/users/2/display-name", RECORD,
        follow_up_performed=True, write_record_decisive=content_match,
    )
    assert final == "verified"
    assert reason == WRITE_RECORD_EXEMPTION_REASON


# -----------------------------------------------------------------------------
# 4. D23 — the attacked-id check binds to an OWNER/SUBJECT key, never to a record's
#    own primary key. A record's `id` says nothing about WHOSE object it is; matching
#    on it let a dirty/accumulated log false-match and fire the exemption on a SECURE
#    control (the only anti-false-positive gate). These pin the tightened behavior.
# -----------------------------------------------------------------------------

# THE D23 CASE (this is what regressed before the fix): an accumulated X-SAFE log where
# the SECOND row's own primary key `id` == the attacked id (2), while its subject is a
# DIFFERENT user (1). The attack's written value IS present (on that user-1 row). Before
# the fix `aid in <all scalars>` matched via the row's own id -> exemption -> X-SAFE
# FALSE POSITIVE. It must NOT match.
XSAFE_AUDIT_ID_COLLISION = (
    '{"events":['
    '{"id":1,"event":"nickname.update","user_id":1,"new_value":"xsafe_attack_r2"},'
    '{"id":2,"event":"nickname.update","user_id":1,"new_value":"xsafe_attack_r2"}'
    ']}'
)


def test_D23_record_own_id_colliding_with_attacked_id_does_not_match():
    # CRITICAL SAFETY: id==2 collides with the attacked id but the subject is user 1.
    assert _write_record_content_match(
        XSAFE_AUDIT_ID_COLLISION, "2", ["xsafe_attack_r2"]
    ) is False


def test_D23_collision_stays_inconclusive_end_to_end():
    # The composed gate: no content match -> no exemption -> guard downgrades -> the
    # secure control stays inconclusive even though the model said 'verified'.
    content_match = _write_record_content_match(
        XSAFE_AUDIT_ID_COLLISION, "2", ["xsafe_attack_r2"]
    )
    assert content_match is False
    final, reason = _apply_cross_resource_guard(
        "verified", "/api/users/2/nickname", RECORD,
        follow_up_performed=True, write_record_decisive=content_match,
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_D23_record_with_no_subject_field_does_not_match():
    # No owner/subject key at all -> cannot prove whose object it is -> err inconclusive.
    body = '{"events":[{"id":2,"event":"rename","new_value":"V"}]}'
    assert _write_record_content_match(body, "2", ["V"]) is False


# --- genericity: the subject key is found by generic vocabulary, not this target's
#     literal "user_id". A foreign log naming its subject differently still works. ---

def test_D23_generic_owner_key_naming_still_matches_on_foreign_log():
    # 'ownerId' (camelCase), no "user_id", no "/api/audit-log", no target field names.
    foreign = '{"entries":[{"seq":7,"action":"rename","ownerId":2,"value":"V"}]}'
    assert _write_record_content_match(foreign, "2", ["V"]) is True


def test_D23_generic_subject_key_variants_match():
    for body in (
        '{"log":[{"pk":9,"account_id":2,"val":"V"}]}',
        '{"log":[{"pk":9,"subjectId":2,"val":"V"}]}',
        '{"log":[{"pk":9,"actor":2,"val":"V"}]}',
        '{"log":[{"pk":9,"resource_id":2,"val":"V"}]}',
    ):
        assert _write_record_content_match(body, "2", ["V"]) is True, body


def test_D23_foreign_log_owner_mismatch_does_not_match():
    # Same foreign shape, but the subject is a different owner -> no match.
    foreign = '{"entries":[{"seq":2,"action":"rename","ownerId":1,"value":"V"}]}'
    assert _write_record_content_match(foreign, "2", ["V"]) is False


# --- the owner-key classifier itself (structural, whole-token, camelCase-aware) ---

def test_D23_is_owner_key_excludes_primary_keys():
    assert _is_owner_key("id") is False
    assert _is_owner_key("pk") is False
    assert _is_owner_key("event") is False
    assert _is_owner_key("new_value") is False
    assert _is_owner_key("seq") is False


def test_D23_is_owner_key_accepts_generic_subject_names():
    for name in ("user_id", "userId", "UserID", "owner", "ownerId", "account_id",
                 "subjectId", "actor", "member_id", "uid", "resource_id"):
        assert _is_owner_key(name) is True, name


def test_D23_field_tokens_splits_camel_and_separators():
    assert _field_tokens("user_id") == {"user", "id"}
    assert _field_tokens("userId") == {"user", "id"}
    assert _field_tokens("UserID") == {"user", "id"}
    assert _field_tokens("id") == {"id"}
