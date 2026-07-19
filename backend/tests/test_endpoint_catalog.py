# ==============================================================================
# Human-owned test for backend/app/services/endpoint_catalog.py  (D18 — Step 2;
# refreshed for B-1 Step 1: the catalog now carries genuine OpenAPI semantics).
#
# THE EXPECTED VALUES ARE HUMAN-OWNED GROUND TRUTH. The maintainer fixed them and
# they must NOT be authored, added, relaxed, or "corrected" here to make a test
# pass. The test INPUT is also not graded by this file: KEY A/B load the REAL
# OpenAPI surface from vulnerable_target.main.app.openapi(); we only wire that
# input through the function under test and assert the GIVEN values. If an
# assertion fails, that is a SIGNAL to report — not something to fix here.
#
# FORMAT CHANGE (B-1 Step 1): catalog entries used to be the bare string
# "METHOD /path". They now LEAD with "METHOD /path" and may carry a trailing
# "  [tags: ...; operationId: ...]" annotation of the operation's GENUINE,
# pre-existing OpenAPI metadata. The HUMAN-OWNED GROUND TRUTH is unchanged: it is
# the SET of "METHOD /path" prefixes (extracted here via `_prefix`). EXPECTED_CATALOG
# below is byte-identical to before — only the extraction adapts to the new format.
#
# KEY A — catalog_from_openapi(app.openapi()) correctness (exact 26-endpoint surface
#         by prefix; genuine metadata faithfully surfaced, nothing invented).
# KEY B — cross-resource reach (teeth): the placeholder _shadow_endpoint_catalog
#         offers only the finding's own path; the real catalog reaches other paths.
# ==============================================================================

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import re

from vulnerable_target.main import app
from backend.app.services.endpoint_catalog import catalog_from_openapi
from backend.app.services.fuzzer import _shadow_endpoint_catalog


# -----------------------------------------------------------------------------
# Human-owned expected surface (KEY A). Verbatim from the maintainer; do not edit.
# -----------------------------------------------------------------------------
EXPECTED_CATALOG = {
    "GET /",
    "GET /api/admin/users",
    "GET /api/audit-log",
    "GET /api/documents/{document_id}",
    "GET /api/gizmos/{gizmo_id}",
    "GET /api/invoices/{invoice_id}",
    "GET /api/ledgers/{ledger_id}",
    "GET /api/notes/{note_id}",
    "GET /api/orders/{order_id}",
    "GET /api/sprockets/{sprocket_id}",
    "GET /api/statements/{statement_id}",
    "GET /api/users/{user_id}/avatar",
    "POST /api/users/{user_id}/avatar",
    "POST /api/users/{user_id}/display-name",
    "POST /api/users/{user_id}/gizmo",
    "GET /api/users/{user_id}/ledger",
    "POST /api/users/{user_id}/nickname",
    "GET /api/users/{user_id}/profile",
    "POST /api/users/{user_id}/profile",
    "GET /api/users/{user_id}/settings",
    "POST /api/users/{user_id}/settings",
    "POST /api/users/{user_id}/sprocket",
    "GET /api/users/{user_id}/statement",
    "GET /api/users/{user_id}/theme",
    "POST /api/users/{user_id}/theme",
    "POST /login",
}

# Human-owned fixture finding (KEY B).
FINDING = {"method": "POST", "path": "/api/users/{user_id}/profile"}
FINDING_PATH = "/api/users/{user_id}/profile"

_ENTRY_RE = re.compile(r"^[A-Z]+ /")


def _prefix(entry: str) -> str:
    """Extract the leading 'METHOD /path' from a (possibly annotated) catalog entry.

    Entries now LEAD with 'METHOD /path' and may carry a trailing '  [..]' annotation;
    the human-owned ground truth is this prefix only.
    """
    return entry.split("  [", 1)[0]


def _path_of(entry: str) -> str:
    """Extract the path portion of a (possibly annotated) catalog entry."""
    _, _, path = _prefix(entry).partition(" ")
    return path


# -----------------------------------------------------------------------------
# KEY A — catalog_from_openapi on the real spec
# -----------------------------------------------------------------------------

def test_A1_exact_set_equality_and_count():
    catalog = catalog_from_openapi(app.openapi())
    # Human-owned ground truth is the SET of "METHOD /path" prefixes.
    assert {_prefix(e) for e in catalog} == EXPECTED_CATALOG
    assert len(catalog) == 26


def test_A2_well_formed_no_dupes_no_metadata():
    catalog = catalog_from_openapi(app.openapi())
    # Every entry LEADS with "METHOD /path" with an uppercase method.
    for entry in catalog:
        assert _ENTRY_RE.match(entry), f"malformed entry: {entry!r}"
    # No duplicates (full entries, and the "METHOD /path" prefixes).
    assert len(catalog) == len(set(catalog))
    assert len(catalog) == len({_prefix(e) for e in catalog})
    # No OpenAPI metadata key was ever emitted AS an endpoint (i.e. as the method
    # token / leading "METHOD /path"). Surfacing metadata in the trailing annotation
    # is expected; a metadata key masquerading as an operation is not.
    for leak in ("parameters", "summary", "description", "$ref"):
        for entry in catalog:
            assert leak not in _prefix(entry).lower(), f"metadata leaked as endpoint: {entry!r}"


def test_A3_degenerate_specs_return_empty_and_do_not_raise():
    assert catalog_from_openapi({}) == []
    assert catalog_from_openapi({"paths": {}}) == []
    # Malformed spec: paths present but its members are not Operation Objects.
    malformed = {"paths": {"/x": "not-a-path-item", "/y": {"get": "not-an-operation",
                                                            "summary": "meta-only"}}}
    assert catalog_from_openapi(malformed) == []


def test_A4_surfaces_genuine_openapi_metadata_verbatim():
    """The catalog no longer DISCARDS the operation's semantics. For every operation in
    the real spec, the entry's annotation must reflect EXACTLY the tags + operationId the
    spec declares (computed from the spec here — nothing invented), and must NOT contain
    any summary/description text (deliberately not surfaced in Step 1)."""
    spec = app.openapi()
    catalog = catalog_from_openapi(spec)
    by_prefix = {_prefix(e): e for e in catalog}

    http_methods = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
    surfaced_any_metadata = False
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method.lower() not in http_methods or not isinstance(op, dict):
                continue
            entry = by_prefix[f"{method.upper()} {path}"]
            tags = op.get("tags") or []
            if tags:
                surfaced_any_metadata = True
                assert ("tags: " + ", ".join(str(t) for t in tags)) in entry, entry
            op_id = op.get("operationId")
            if op_id:
                surfaced_any_metadata = True
                assert ("operationId: " + op_id) in entry, entry
            # Step-1 scope: the auto-generated `summary` (e.g. "Get Audit Log") exists in
            # the spec but is intentionally NOT surfaced; assert it never leaks in.
            summary = op.get("summary")
            if summary:
                assert summary not in entry, f"summary leaked into entry: {entry!r}"

    # Teeth: prove metadata is actually being carried (guards against a silent regression
    # back to the bare "METHOD /path" format).
    assert surfaced_any_metadata
    assert "[tags: audit; operationId: get_audit_log_api_audit_log_get]" in by_prefix["GET /api/audit-log"]


# -----------------------------------------------------------------------------
# KEY B — cross-resource reach (teeth): placeholder vs. real catalog
# -----------------------------------------------------------------------------

def test_B1_placeholder_has_no_cross_path_endpoint():
    placeholder = _shadow_endpoint_catalog(FINDING)
    cross_path = [e for e in placeholder if _path_of(e) != FINDING_PATH]
    assert len(cross_path) == 0


def test_B2_real_catalog_reaches_other_paths_incl_invoices():
    catalog = catalog_from_openapi(app.openapi())
    cross_path = [e for e in catalog if _path_of(e) != FINDING_PATH]
    assert len(cross_path) >= 1
    assert any(_prefix(e) == "GET /api/invoices/{invoice_id}" for e in catalog)


def test_B3_real_catalog_is_superset_of_placeholder_no_regression():
    catalog = catalog_from_openapi(app.openapi())
    assert any(_prefix(e) == "GET /api/users/{user_id}/profile" for e in catalog)
