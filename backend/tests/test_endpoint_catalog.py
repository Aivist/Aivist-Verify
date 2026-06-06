# ==============================================================================
# Human-owned test for backend/app/services/endpoint_catalog.py  (D18 — Step 2).
#
# THE EXPECTED VALUES ARE HUMAN-OWNED GROUND TRUTH. The maintainer fixed them and
# they must NOT be authored, added, relaxed, or "corrected" here to make a test
# pass. The test INPUT is also not graded by this file: KEY A/B load the REAL
# OpenAPI surface from vulnerable_target.main.app.openapi(); we only wire that
# input through the function under test and assert the GIVEN values. If an
# assertion fails, that is a SIGNAL to report — not something to fix here.
#
# KEY A — catalog_from_openapi(app.openapi()) correctness (exact 15-entry surface).
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
    "GET /api/documents/{document_id}",
    "GET /api/invoices/{invoice_id}",
    "GET /api/notes/{note_id}",
    "GET /api/orders/{order_id}",
    "GET /api/users/{user_id}/avatar",
    "POST /api/users/{user_id}/avatar",
    "GET /api/users/{user_id}/profile",
    "POST /api/users/{user_id}/profile",
    "GET /api/users/{user_id}/settings",
    "POST /api/users/{user_id}/settings",
    "GET /api/users/{user_id}/theme",
    "POST /api/users/{user_id}/theme",
    "POST /login",
}

# Human-owned fixture finding (KEY B).
FINDING = {"method": "POST", "path": "/api/users/{user_id}/profile"}
FINDING_PATH = "/api/users/{user_id}/profile"

_ENTRY_RE = re.compile(r"^[A-Z]+ /")


def _path_of(entry: str) -> str:
    """Extract the path portion of a 'METHOD /path' catalog entry."""
    _, _, path = entry.partition(" ")
    return path


# -----------------------------------------------------------------------------
# KEY A — catalog_from_openapi on the real spec
# -----------------------------------------------------------------------------

def test_A1_exact_set_equality_and_count():
    catalog = catalog_from_openapi(app.openapi())
    assert set(catalog) == EXPECTED_CATALOG
    assert len(catalog) == 15


def test_A2_well_formed_no_dupes_no_metadata():
    catalog = catalog_from_openapi(app.openapi())
    # Every entry is "METHOD /path" with an uppercase method.
    for entry in catalog:
        assert _ENTRY_RE.match(entry), f"malformed entry: {entry!r}"
    # No duplicates.
    assert len(catalog) == len(set(catalog))
    # No OpenAPI metadata keys leaked in as operations.
    for leak in ("parameters", "summary", "description", "$ref"):
        for entry in catalog:
            assert leak not in entry.split(" ", 1)[0].lower(), f"metadata leaked: {entry!r}"


def test_A3_degenerate_specs_return_empty_and_do_not_raise():
    assert catalog_from_openapi({}) == []
    assert catalog_from_openapi({"paths": {}}) == []
    # Malformed spec: paths present but its members are not Operation Objects.
    malformed = {"paths": {"/x": "not-a-path-item", "/y": {"get": "not-an-operation",
                                                            "summary": "meta-only"}}}
    assert catalog_from_openapi(malformed) == []


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
    assert "GET /api/invoices/{invoice_id}" in catalog


def test_B3_real_catalog_is_superset_of_placeholder_no_regression():
    catalog = catalog_from_openapi(app.openapi())
    assert "GET /api/users/{user_id}/profile" in catalog
