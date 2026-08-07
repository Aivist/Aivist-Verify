# ==============================================================================
# scan "1" — the no-spec path: catalog from an endpoints LIST instead of an OpenAPI spec. Only the
# catalog SOURCE changes; the endpoints list normalizes to the SAME List[str] format
# catalog_from_openapi produces, so ALL downstream discovery is byte-identical.
# ==============================================================================
import os
import sys
import json

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO)

from backend.app.services.endpoint_catalog import (
    catalog_from_endpoints, spec_from_endpoints, catalog_from_openapi,
)
from backend.app.cli.external_verify import _load_endpoints_file


# ------------------------------------------------------------------ normalizer
def test_catalog_from_endpoints_matches_openapi_format_and_drops_junk():
    eps = ["get /api/orders/{order_id}", "POST /api/orders", "GET /api/orders/{order_id}",  # dup
           "garbage line", "", "# a comment", "CONNECT /x", "no-slash-path"]
    cat = catalog_from_endpoints(eps)
    # method upper-cased, deduped, junk/comment/non-HTTP/non-'/' lines DROPPED
    assert set(cat) == {"GET /api/orders/{order_id}", "POST /api/orders"}
    # THE INVARIANT that keeps discovery identical: same format catalog_from_openapi produces
    assert catalog_from_endpoints(eps) == catalog_from_openapi(spec_from_endpoints(eps))
    # degenerate inputs -> empty catalog, never a crash
    assert catalog_from_endpoints([]) == [] and catalog_from_endpoints("not-a-list") == []


def test_spec_from_endpoints_invents_no_metadata():
    spec = spec_from_endpoints(["GET /api/orders/{id}", "POST /api/orders"])
    assert spec["paths"]["/api/orders/{id}"] == {"get": {}}          # empty operation objects
    assert spec["paths"]["/api/orders"] == {"post": {}}              # nothing invented (no tags/summary)


# ------------------------------------------------------------------ loader (fail-safe, mirrors _load_spec_file)
def test_load_endpoints_json_array(tmp_path):
    p = tmp_path / "eps.json"
    p.write_text(json.dumps(["GET /api/orders/{id}", "POST /api/orders"]), encoding="utf-8")
    assert _load_endpoints_file(str(p)) == ["GET /api/orders/{id}", "POST /api/orders"]


def test_load_endpoints_newline_delimited_with_comments(tmp_path):
    p = tmp_path / "eps.txt"
    p.write_text("GET /api/orders/{id}\n# a comment\n\nPOST /api/orders\n", encoding="utf-8")
    assert _load_endpoints_file(str(p)) == ["GET /api/orders/{id}", "POST /api/orders"]


def test_load_endpoints_malformed_raises_not_crash(tmp_path):
    prose = tmp_path / "prose.txt"
    prose.write_text("this is not endpoints\njust some prose\n", encoding="utf-8")
    with pytest.raises(Exception):
        _load_endpoints_file(str(prose))          # no usable "METHOD /path" -> raises (caller -> NOT DATA)
    obj = tmp_path / "obj.json"
    obj.write_text('{"not":"an array"}', encoding="utf-8")
    with pytest.raises(Exception):
        _load_endpoints_file(str(obj))            # JSON object, not a usable list -> raises
