# ==============================================================================
# Unit Tests — Step D: Hunter -> Verify link via explicit structured columns.
#
# Proves the fuzzer's payload/parsed-request/auth-refresh resolvers now read the
# dedicated JSON columns first (the bridge that closes the broken link), while
# the legacy JSON-in-text fallback and the Nuclei "no payloads" path are
# preserved unchanged. No network or DB — plain ORM instances (never added to a
# session) are sufficient because the resolvers only read attributes.
# ==============================================================================

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.models.scan import VulnerabilityFinding
from backend.app.services.fuzzer import (
    _extract_payloads,
    _extract_parsed_request,
    _extract_auth_refresh_request,
)


_PAYLOAD = {
    "phase": 1, "type": "BOLA", "location": "query_param",
    "target_param": "id", "payload_string": "2", "expected_match": "HTTP 200",
}
_PARSED = {"method": "GET", "path": "/api/x", "query_params": {}, "headers": {"Host": "good.com"}, "body": None}
_ANCHOR = {"method": "POST", "url": "https://good.com/login", "headers": {}, "body": {"u": "x"}}


# =============================================================================
# 1. Column path — the Step D bridge (Hunter findings)
# =============================================================================

def test_payloads_read_from_explicit_column():
    f = VulnerabilityFinding(source="hunter", template_id="logic-hunter", severity="BOLA",
                             matched_at="https://good.com", automation_payloads=[_PAYLOAD])
    assert _extract_payloads(f) == [_PAYLOAD]


def test_parsed_request_read_from_explicit_column():
    f = VulnerabilityFinding(source="hunter", template_id="logic-hunter", severity="BOLA",
                             matched_at="https://good.com", parsed_request=_PARSED)
    assert _extract_parsed_request(f) == _PARSED


def test_auth_refresh_read_from_explicit_column():
    f = VulnerabilityFinding(source="hunter", template_id="logic-hunter", severity="BOLA",
                             matched_at="https://good.com", auth_refresh_request=_ANCHOR)
    assert _extract_auth_refresh_request(f) == _ANCHOR


# =============================================================================
# 2. Legacy fallback — JSON embedded in ai_patch/poc_request still works
# =============================================================================

def test_legacy_json_in_text_still_extracts_payloads():
    legacy = json.dumps({"automation_payloads": [_PAYLOAD]})
    f = VulnerabilityFinding(source="nuclei", template_id="t", severity="HIGH",
                             matched_at="https://good.com", ai_patch=legacy)
    # explicit column is None → must fall back to the embedded JSON
    assert _extract_payloads(f) == [_PAYLOAD]


def test_legacy_json_in_text_still_extracts_parsed_request():
    legacy = json.dumps({"parsed_data": _PARSED})
    f = VulnerabilityFinding(source="nuclei", template_id="t", severity="HIGH",
                             matched_at="https://good.com", poc_request=legacy)
    assert _extract_parsed_request(f) == _PARSED


# =============================================================================
# 3. Nuclei path unchanged — markdown ai_patch + raw poc_request => no payloads
# =============================================================================

def test_nuclei_finding_yields_no_payloads():
    f = VulnerabilityFinding(
        source="nuclei", template_id="CVE-2024-1234", severity="CRITICAL",
        matched_at="https://good.com/x",
        ai_patch="## 漏洞根因剖析\nThis is markdown, not JSON.",
        poc_request="GET /x HTTP/1.1\nHost: good.com",
    )
    assert _extract_payloads(f) == []


def test_explicit_column_takes_precedence_over_legacy():
    other = {**_PAYLOAD, "payload_string": "999"}
    f = VulnerabilityFinding(source="hunter", template_id="logic-hunter", severity="BOLA",
                             matched_at="https://good.com",
                             automation_payloads=[_PAYLOAD],
                             ai_patch=json.dumps({"automation_payloads": [other]}))
    # the typed column wins over the legacy embedded JSON
    assert _extract_payloads(f) == [_PAYLOAD]
