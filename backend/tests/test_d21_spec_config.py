# ==============================================================================
# D21 — AI_DEEP_VERIFY_OPENAPI_SPEC promoted to a first-class config field.
#
# What D21 changed: the shadow verifier's endpoint-catalog spec source is now a
# DECLARED Settings field (a path to an OpenAPI JSON file), loadable from .env like the
# other AI_DEEP_VERIFY_* flags, instead of an undeclared `getattr` seam. The path is
# resolved to a parsed spec dict at the fuzzer consumption point
# (`_resolve_openapi_catalog_source`), which FAILS SAFE back to the placeholder catalog
# on any bad value. The verdict path and the verdict gate are untouched.
#
# These tests pin the OBJECTIVE, verdict-free properties only (per the D21 brief — no
# invented "expected verdicts"):
#   * zero regression: unset (None) -> byte-identical placeholder catalog;
#   * positive: a real OpenAPI file -> discovered surface, MERGED with the placeholder;
#   * fail-safe: missing file / malformed JSON / non-object JSON / wrong type -> None
#     -> placeholder (never a crash, never a weakened catalog);
#   * back-compat: an already-parsed spec dict (in-process driver injection) still works.
#
# The allowed-to-fail safety anchor is the zero-regression assertion: it fails against a
# consumer that does not fall back to the placeholder for an absent/bad spec source.
# ==============================================================================

import json

from vulnerable_target.main import app
from backend.app.services.fuzzer import (
    _resolve_openapi_catalog_source,
    _shadow_endpoint_catalog,
)

# A cross-path write whose decisive read-back (GET /api/audit-log) lives ONLY in the real
# OpenAPI surface, never in the placeholder — so its presence/absence cleanly separates
# "real catalog wired" from "placeholder" (same fixture the D18 phase-2 tests use).
FINDING = {"method": "POST", "path": "/api/users/{user_id}/display-name"}
AUDIT_LOG_PREFIX = "GET /api/audit-log"


def _offers_audit_log(catalog) -> bool:
    """Entries LEAD with 'METHOD /path' and may carry a '  [tags: ...]' annotation."""
    return any(e == AUDIT_LOG_PREFIX or e.startswith(AUDIT_LOG_PREFIX + "  [") for e in catalog)


# -----------------------------------------------------------------------------
# Zero regression — unset spec resolves to None and yields the exact placeholder.
# -----------------------------------------------------------------------------

def test_D21_unset_spec_resolves_to_none():
    assert _resolve_openapi_catalog_source(None) is None
    assert _resolve_openapi_catalog_source("") is None


def test_D21_unset_spec_yields_byte_identical_placeholder():
    # The safety anchor: with no spec source the shadow catalog must be EXACTLY today's
    # placeholder (the finding's own path + a same-resource GET), unchanged by D21.
    placeholder = _shadow_endpoint_catalog(FINDING, None)
    via_resolver = _shadow_endpoint_catalog(FINDING, _resolve_openapi_catalog_source(None))
    assert via_resolver == placeholder
    assert placeholder == [
        "POST /api/users/{user_id}/display-name",
        "GET /api/users/{user_id}/display-name",
    ]
    assert not _offers_audit_log(placeholder)


# -----------------------------------------------------------------------------
# Positive — a path to a real OpenAPI file feeds the discovered surface, merged.
# -----------------------------------------------------------------------------

def test_D21_path_to_openapi_file_feeds_real_catalog(tmp_path):
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(app.openapi()), encoding="utf-8")

    source = _resolve_openapi_catalog_source(str(spec_file))
    assert source is not None
    assert source["kind"] == "openapi"
    assert isinstance(source["spec"], dict)

    catalog = _shadow_endpoint_catalog(FINDING, source)
    # discovered cross-path surface the placeholder can never reach ...
    assert _offers_audit_log(catalog)
    # ... AND the placeholder is still merged in (the finding's own path is never dropped).
    assert "POST /api/users/{user_id}/display-name" in catalog


# -----------------------------------------------------------------------------
# Fail-safe — every bad value degrades to None -> placeholder, never a crash.
# -----------------------------------------------------------------------------

def test_D21_missing_file_fails_safe(tmp_path):
    missing = tmp_path / "does_not_exist.json"
    assert _resolve_openapi_catalog_source(str(missing)) is None
    # end to end: a missing path is indistinguishable from "unset" at the catalog seam
    assert _shadow_endpoint_catalog(FINDING, _resolve_openapi_catalog_source(str(missing))) == \
        _shadow_endpoint_catalog(FINDING, None)


def test_D21_malformed_json_fails_safe(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not valid json", encoding="utf-8")
    assert _resolve_openapi_catalog_source(str(bad)) is None


def test_D21_non_object_json_fails_safe(tmp_path):
    # Valid JSON, but not a JSON object -> not a usable spec -> fail safe.
    arr = tmp_path / "arr.json"
    arr.write_text("[1, 2, 3]", encoding="utf-8")
    assert _resolve_openapi_catalog_source(str(arr)) is None


def test_D21_unexpected_type_fails_safe():
    assert _resolve_openapi_catalog_source(12345) is None


# -----------------------------------------------------------------------------
# Back-compat — an already-parsed spec dict (in-process driver) is accepted verbatim.
# -----------------------------------------------------------------------------

def test_D21_already_parsed_dict_is_accepted_verbatim():
    spec = app.openapi()
    source = _resolve_openapi_catalog_source(spec)
    assert source == {"kind": "openapi", "spec": spec}
    # and it reaches the real surface just like the file path does
    assert _offers_audit_log(_shadow_endpoint_catalog(FINDING, source))
