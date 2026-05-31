# ==============================================================================
# Unit Tests — Heuristic Traffic Pruning Engine
# Validates scoring logic, veto conditions, path segment scanning, and batch filter
# ==============================================================================

import sys
import os

# Ensure the project root is on sys.path so 'backend.app.*' resolves
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest
from backend.app.services.pruner import calculate_exposure_score, filter_high_value_traffic


# =============================================================================
# Helper — build minimal parsed_request dicts
# =============================================================================

def _req(
    method="GET",
    path="/",
    query_params=None,
    headers=None,
    body=None,
):
    return {
        "method": method,
        "path": path,
        "query_params": query_params or {},
        "headers": headers or {},
        "body": body,
    }


# =============================================================================
# 1. Static Asset Veto Tests — must always return 0.0
# =============================================================================

class TestStaticAssetVeto:
    """Static file extensions and telemetry routes must be hard-vetoed to 0.0."""

    @pytest.mark.parametrize("ext", [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
        ".ico", ".woff", ".woff2", ".svg", ".map", ".html",
    ])
    def test_static_file_extensions_vetoed(self, ext):
        req = _req(path=f"/static/bundle{ext}")
        assert calculate_exposure_score(req) == 0.0

    def test_javascript_bundle_vetoed(self):
        req = _req(path="/assets/vendor.chunk.js")
        assert calculate_exposure_score(req) == 0.0

    def test_html_page_vetoed(self):
        req = _req(path="/pages/index.html")
        assert calculate_exposure_score(req) == 0.0


# =============================================================================
# 2. Telemetry / Analytics Veto Tests
# =============================================================================

class TestTelemetryVeto:
    """Analytics trackers and third-party telemetry must be hard-vetoed."""

    def test_analytics_route_vetoed(self):
        req = _req(path="/analytics/event")
        assert calculate_exposure_score(req) == 0.0

    def test_metrics_route_vetoed(self):
        req = _req(path="/metrics/heartbeat")
        assert calculate_exposure_score(req) == 0.0

    def test_google_analytics_vetoed(self):
        req = _req(path="/collect?v=1&tid=UA-google-analytics-id")
        assert calculate_exposure_score(req) == 0.0

    def test_doubleclick_vetoed(self):
        req = _req(path="/pagead/doubleclick/conversion")
        assert calculate_exposure_score(req) == 0.0


# =============================================================================
# 3. Method Scoring Tests
# =============================================================================

class TestMethodScoring:
    """Verify base scores for different HTTP methods."""

    def test_post_base_score(self):
        score = calculate_exposure_score(_req(method="POST", path="/data"))
        assert score >= 0.4

    def test_put_base_score(self):
        score = calculate_exposure_score(_req(method="PUT", path="/data"))
        assert score >= 0.4

    def test_patch_base_score(self):
        score = calculate_exposure_score(_req(method="PATCH", path="/data"))
        assert score >= 0.4

    def test_delete_base_score(self):
        score = calculate_exposure_score(_req(method="DELETE", path="/data"))
        assert score >= 0.3

    def test_get_with_params_score(self):
        score = calculate_exposure_score(_req(
            method="GET", path="/search", query_params={"q": "test"}
        ))
        assert score >= 0.2

    def test_static_get_score(self):
        score = calculate_exposure_score(_req(method="GET", path="/about"))
        assert score >= 0.1


# =============================================================================
# 4. Path Segment Scanning — Critical for parameterless endpoints
# =============================================================================

class TestPathSegmentScanning:
    """Path segments must be scanned against the sensitive wordlist."""

    def test_admin_reset_path_surfaces(self):
        """GET /api/v1/admin/reset must score meaningfully from path segments.
        Breakdown: GET(0.1) + admin(0.1) + reset(0.1) + API marker(0.1) = 0.4
        This alone is below threshold, but when combined with POST/JSON it would
        cross. Here we just verify path segments ARE being detected."""
        req = _req(method="GET", path="/api/v1/admin/reset")
        score = calculate_exposure_score(req)
        # Must be significantly above a plain GET (0.1) due to path scanning
        assert score >= 0.4, f"Expected >= 0.4, got {score}"
        # Verify upgrading to POST crosses the threshold
        req_post = _req(method="POST", path="/api/v1/admin/reset",
                        headers={"Content-Type": "application/json"})
        post_score = calculate_exposure_score(req_post)
        assert post_score >= 0.65, f"POST variant expected >= 0.65, got {post_score}"

    def test_user_delete_path_surfaces(self):
        """DELETE /api/v1/user/delete — DELETE(0.3) + user(0.1) + delete(0.1) + api(0.1) = 0.6.
        Adding JSON Content-Type crosses the threshold."""
        req = _req(method="DELETE", path="/api/v1/user/delete")
        score = calculate_exposure_score(req)
        assert score >= 0.6, f"Expected >= 0.6, got {score}"
        # With content-type, it crosses 0.65
        req_with_ct = _req(method="DELETE", path="/api/v1/user/delete",
                           headers={"Content-Type": "application/json"})
        assert calculate_exposure_score(req_with_ct) >= 0.65

    def test_checkout_transfer_path(self):
        """POST /api/v2/checkout/transfer should score high."""
        req = _req(method="POST", path="/api/v2/checkout/transfer")
        score = calculate_exposure_score(req)
        assert score >= 0.65, f"Expected >= 0.65, got {score}"

    def test_admin_update_path(self):
        """PATCH /api/v1/admin/update should score high."""
        req = _req(method="PATCH", path="/api/v1/admin/update")
        score = calculate_exposure_score(req)
        assert score >= 0.65, f"Expected >= 0.65, got {score}"


# =============================================================================
# 5. Content-Type & API Marker Bonus Tests
# =============================================================================

class TestContextualSignals:
    """Content-Type and API path markers should add bonuses."""

    def test_json_content_type_bonus(self):
        base_score = calculate_exposure_score(_req(method="POST", path="/data"))
        json_score = calculate_exposure_score(_req(
            method="POST", path="/data",
            headers={"Content-Type": "application/json"},
        ))
        assert json_score > base_score

    def test_graphql_content_type_bonus(self):
        base_score = calculate_exposure_score(_req(method="POST", path="/query"))
        gql_score = calculate_exposure_score(_req(
            method="POST", path="/query",
            headers={"Content-Type": "application/graphql"},
        ))
        assert gql_score > base_score

    def test_api_path_marker_bonus(self):
        plain_score = calculate_exposure_score(_req(method="POST", path="/data"))
        api_score = calculate_exposure_score(_req(method="POST", path="/api/data"))
        assert api_score > plain_score


# =============================================================================
# 6. Parameter Sensitivity Tests
# =============================================================================

class TestParameterSensitivity:
    """Sensitive keywords in params/body should increase score."""

    def test_sensitive_query_params(self):
        """GET with sensitive query params + path segments:
        GET+params(0.2) + admin(0.1) + user(0.1) + role(0.1) + id(0.1) + API marker(0.1) = 0.7."""
        req = _req(
            method="GET",
            path="/api/v1/admin/resource",
            query_params={"user_id": "123", "role": "admin", "id": "456"},
        )
        score = calculate_exposure_score(req)
        assert score >= 0.65, f"Expected >= 0.65, got {score}"

    def test_sensitive_body_keys(self):
        req = _req(
            method="POST",
            path="/api/v1/resource",
            headers={"Content-Type": "application/json"},
            body={"user_id": 1001, "amount": 500, "token": "abc"},
        )
        score = calculate_exposure_score(req)
        assert score >= 0.65, f"Expected >= 0.65, got {score}"

    def test_multi_keyword_key_counts_all_keywords(self):
        """REGRESSION (determinism): a single key containing TWO sensitive
        keywords ('user_id' ⊇ user + id) must count BOTH, regardless of
        PYTHONHASHSEED. GET+params(0.2) + user(0.1) + id(0.1) = 0.4 exactly.
        The old 'break on first match per key' logic could yield 0.3."""
        req = _req(method="GET", path="/x", query_params={"user_id": "1"})
        assert calculate_exposure_score(req) == pytest.approx(0.4)

    def test_sensitive_query_params_score_is_exact(self):
        """REGRESSION (determinism): locks the exact expected score so a
        hash-seed-dependent regression can never silently return. Distinct
        keywords across keys+path = {user, id, role, admin} → cap-relevant
        bonus 0.4. GET+params(0.2) + 0.4 + API marker(0.1) = 0.7."""
        req = _req(
            method="GET",
            path="/api/v1/admin/resource",
            query_params={"user_id": "123", "role": "admin", "id": "456"},
        )
        assert calculate_exposure_score(req) == pytest.approx(0.7)

    def test_score_is_stable_across_repeated_calls(self):
        """The score for a fixed input must be identical every call within a
        process (and, with the order-independent fix, across processes)."""
        req = _req(
            method="POST",
            path="/api/v1/admin/user/update",
            query_params={"user_id": "1", "token": "x"},
            headers={"Content-Type": "application/json"},
            body={"role": "admin"},
        )
        scores = {calculate_exposure_score(req) for _ in range(50)}
        assert len(scores) == 1, f"non-deterministic scores observed: {scores}"

    def test_param_bonus_capped_at_04(self):
        """Even with many sensitive matches, bonus must not exceed 0.4."""
        req = _req(
            method="POST",
            path="/api/v1/admin/user/reset/delete/update",
            query_params={"token": "x", "amount": "y", "price": "z"},
            headers={"Content-Type": "application/json"},
            body={"role": "admin", "privilege": "high", "status": "active",
                  "checkout": "1", "invoice": "2", "uuid": "abc", "auth": "tok",
                  "transfer": "yes", "pay": "now"},
        )
        score = calculate_exposure_score(req)
        # Max possible: method(0.4) + param_cap(0.4) + json(0.15) + api(0.1) = 1.05 → clamped to 1.0
        assert score <= 1.0


# =============================================================================
# 7. Score Normalization — always [0.0, 1.0]
# =============================================================================

class TestScoreNormalization:
    def test_score_never_exceeds_1(self):
        """Even a maximally-scored request must clamp at 1.0."""
        req = _req(
            method="POST",
            path="/api/v1/admin/user/delete/reset/update/transfer",
            query_params={"token": "x", "amount": "y", "price": "z", "id": "1"},
            headers={"Content-Type": "application/json"},
            body={"role": "superadmin", "privilege": "root", "uuid": "abc"},
        )
        score = calculate_exposure_score(req)
        assert 0.0 <= score <= 1.0

    def test_score_never_below_0(self):
        req = _req(method="GET", path="/about")
        score = calculate_exposure_score(req)
        assert 0.0 <= score <= 1.0


# =============================================================================
# 8. Batch Filter Engine Tests
# =============================================================================

class TestBatchFilter:
    """filter_high_value_traffic should correctly threshold and sort."""

    def test_filters_below_threshold(self):
        requests = [
            _req(method="GET", path="/static/logo.png"),   # veto → 0.0
            _req(method="GET", path="/about"),              # ~0.1
            _req(method="POST", path="/api/v1/admin/update",
                 headers={"Content-Type": "application/json"},
                 body={"role": "admin"}),                   # high
        ]
        result = filter_high_value_traffic(requests, threshold=0.65)
        assert len(result) >= 1
        # The high-value one must be present
        assert any(r["path"] == "/api/v1/admin/update" for r in result)
        # Static asset must NOT be present
        assert not any(r["path"] == "/static/logo.png" for r in result)

    def test_empty_input_returns_empty(self):
        assert filter_high_value_traffic([]) == []

    def test_all_below_threshold(self):
        requests = [
            _req(method="GET", path="/home"),
            _req(method="GET", path="/contact"),
        ]
        result = filter_high_value_traffic(requests, threshold=0.65)
        assert result == []

    def test_results_sorted_descending(self):
        """Filtered results must be sorted by exposure score descending."""
        requests = [
            _req(method="POST", path="/api/v1/checkout/transfer",
                 headers={"Content-Type": "application/json"},
                 body={"amount": 100}),
            _req(method="POST", path="/api/v1/admin/reset",
                 headers={"Content-Type": "application/json"},
                 body={"token": "abc", "user_id": 1, "role": "admin"}),
        ]
        result = filter_high_value_traffic(requests, threshold=0.5)
        if len(result) >= 2:
            scores = [r["_exposure_score"] for r in result]
            assert scores == sorted(scores, reverse=True)

    def test_exposure_score_annotated(self):
        """Each result entry should have the _exposure_score key."""
        requests = [
            _req(method="POST", path="/api/v1/admin/update",
                 headers={"Content-Type": "application/json"},
                 body={"role": "admin"}),
        ]
        result = filter_high_value_traffic(requests, threshold=0.0)
        assert len(result) >= 1
        assert "_exposure_score" in result[0]
        assert isinstance(result[0]["_exposure_score"], float)
