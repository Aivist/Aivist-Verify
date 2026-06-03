# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: High-Performance Heuristic Traffic Pruning Engine
#
# Purpose: Grade, score, and eliminate noisy HTTP request streams (e.g. HAR
#          imports) to protect Gemini from token exhaustion and focus scanning
#          resources on high-value business endpoints only.
# ==============================================================================

import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger("app.services.pruner")

# =============================================================================
# Constants — Scoring Weights & Wordlists
# =============================================================================

# HTTP method base scores (higher = more interesting for security testing)
_METHOD_SCORES: Dict[str, float] = {
    "POST": 0.4,
    "PUT": 0.4,
    "PATCH": 0.4,
    "DELETE": 0.3,
}
_GET_WITH_PARAMS_SCORE: float = 0.2
_GET_STATIC_SCORE: float = 0.1

# Sensitive parameter keywords — triggers +0.1 per unique match
_SENSITIVE_KEYWORDS: frozenset = frozenset({
    "id", "uuid", "role", "user", "amount", "price", "pay",
    "admin", "privilege", "status", "token", "auth", "checkout", "invoice",
    "delete", "reset", "update", "transfer",
})

# Maximum cumulative bonus from parameter sensitivity matches
_MAX_PARAM_BONUS: float = 0.4

# Content-Type signals that indicate structured API payloads
_API_CONTENT_TYPES: frozenset = frozenset({
    "application/json",
    "application/graphql",
})

# URL path markers indicating API routing infrastructure
_API_PATH_MARKERS: tuple = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql")

# Static asset extensions — hard veto (score → 0.0)
_STATIC_EXTENSIONS: frozenset = frozenset({
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".svg", ".map", ".html", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".pdf",
})

# Telemetry / analytics route fragments — hard veto (score → 0.0)
_TELEMETRY_ROUTES: tuple = (
    "/analytics/", "/metrics/", "/telemetry/", "/beacon/", "/_track/",
    "google-analytics", "doubleclick",
)


# =============================================================================
# Shared deterministic helpers (single source of truth)
#
# Reused by: HAR ingestion (api/v1/hunter.py) and the Step 9 proxy radar —
# both the mitmdump Tier-1 hook (addon) and the FastAPI Tier-2 pipeline — so the
# scope lock, static veto, and login-endpoint detection never drift between
# subsystems.
# =============================================================================

# Public alias of the static-asset veto set for Tier-1 reuse by the proxy addon.
STATIC_EXTENSIONS: frozenset = _STATIC_EXTENSIONS

# Login / identity endpoint signatures (deterministic, no AI).
LOGIN_PATH_MARKERS: tuple = ("login", "signin", "sign-in", "auth", "token", "session", "oauth")
LOGIN_BODY_MARKERS: tuple = ("password", "passwd", "username", "login", "token", "session", "grant_type")


def is_static_path(path: str) -> bool:
    """True if the path points at a static asset (Tier-1 negative-weight veto)."""
    p = (path or "").lower().split("?", 1)[0]
    return any(p.endswith(ext) for ext in _STATIC_EXTENSIONS)


def host_in_scope(host: str, scope) -> bool:
    """
    Scope-lock check. Empty/falsy scope == no host filter (everything in scope).
    A host matches if it equals an approved entry or is a subdomain of it.
    """
    if not scope:
        return True
    h = (host or "").lower()
    for s in scope:
        s = (s or "").lower().strip()
        if not s:
            continue
        if h == s or h.endswith("." + s):
            return True
    return False


def detect_login_candidate(method: str, path: str, body) -> bool:
    """
    Flags a request as a likely login/identity endpoint: a POST/PUT-family
    method AND a login/auth/token/session/password marker in the path or body.
    Powers the Identity Provider Anchor pre-fill in both HAR and proxy flows.
    """
    if (method or "").upper() not in ("POST", "PUT"):
        return False
    low_path = (path or "").lower()
    if any(m in low_path for m in LOGIN_PATH_MARKERS):
        return True
    body_text = ""
    if isinstance(body, dict):
        body_text = " ".join(str(k) for k in body.keys()).lower()
    elif body:
        body_text = str(body).lower()
    return any(m in body_text for m in LOGIN_BODY_MARKERS)


# =============================================================================
# Core Scoring Engine
# =============================================================================

def calculate_exposure_score(parsed_request: dict) -> float:
    """
    Calculates a deterministic heuristic exposure score for a single parsed
    HTTP request, representing its likelihood of being a security-relevant
    business endpoint worth scanning or analyzing with Gemini.

    Scoring Dimensions:
        1. HTTP Method weight (POST/PUT/PATCH > DELETE > GET+params > GET)
        2. Parameter sensitivity (keys matching sensitive wordlist)
        3. Contextual signals (Content-Type, API path markers)
        4. Negative veto (static assets, telemetry routes → instant 0.0)

    :param parsed_request: A dict with keys: method, path, query_params,
                           headers, body (as produced by traffic_parser or
                           HAR entry conversion).
    :return: A float strictly clamped to [0.0, 1.0].
    """
    method = parsed_request.get("method", "GET").upper()
    path = parsed_request.get("path", "/")
    query_params = parsed_request.get("query_params", {}) or {}
    headers = parsed_request.get("headers", {}) or {}
    body = parsed_request.get("body")

    # --------------------------------------------------------------------- #
    # Veto Check — Static assets and telemetry routes get instant 0.0
    # --------------------------------------------------------------------- #
    path_lower = path.lower()

    # Check static file extensions
    for ext in _STATIC_EXTENSIONS:
        if path_lower.endswith(ext):
            return 0.0

    # Check telemetry route fragments
    for route in _TELEMETRY_ROUTES:
        if route in path_lower:
            return 0.0

    # --------------------------------------------------------------------- #
    # 1. Method Scoring
    # --------------------------------------------------------------------- #
    if method in _METHOD_SCORES:
        score = _METHOD_SCORES[method]
    elif method == "GET" and query_params:
        score = _GET_WITH_PARAMS_SCORE
    else:
        score = _GET_STATIC_SCORE

    # --------------------------------------------------------------------- #
    # 2. Parameter & Path Semantic Sensitivity Scanner
    # --------------------------------------------------------------------- #
    # Collect all parameter keys from query string, body, AND path segments
    all_param_keys: set = set()

    # Query string keys
    for key in query_params.keys():
        all_param_keys.add(key.lower())

    # Body keys (if dict/JSON)
    if isinstance(body, dict):
        _collect_keys_recursive(body, all_param_keys)

    # Path segment scanning — split path into segments and treat each as a key
    for segment in path_lower.split("/"):
        segment = segment.strip()
        if segment:
            all_param_keys.add(segment)

    # Score sensitive keyword matches (count of DISTINCT keywords present across
    # all keys). This is deterministic and independent of set iteration order:
    # we collect every sensitive keyword that is a substring of any key, rather
    # than stopping at the first hit per key. The previous "break on first match
    # per key" logic produced PYTHONHASHSEED-dependent counts because which
    # keyword a multi-keyword key (e.g. "user_id" ⊇ {"user","id"}) consumed
    # depended on frozenset iteration order.
    matched_keywords: set = set()
    for key in all_param_keys:
        for keyword in _SENSITIVE_KEYWORDS:
            if keyword in key:
                matched_keywords.add(keyword)

    param_bonus = min(len(matched_keywords) * 0.1, _MAX_PARAM_BONUS)
    score += param_bonus

    # --------------------------------------------------------------------- #
    # 3. Contextual Signals
    # --------------------------------------------------------------------- #
    # Content-Type signal
    content_type = ""
    for header_key, header_val in headers.items():
        if header_key.lower() == "content-type":
            content_type = header_val.lower()
            break

    for api_ct in _API_CONTENT_TYPES:
        if api_ct in content_type:
            score += 0.15
            break

    # API routing path markers
    for marker in _API_PATH_MARKERS:
        if marker in path_lower:
            score += 0.1
            break

    # --------------------------------------------------------------------- #
    # Final Normalization — clamp to [0.0, 1.0]
    # --------------------------------------------------------------------- #
    return max(0.0, min(1.0, score))


def _collect_keys_recursive(obj: Any, keys_set: set, max_depth: int = 5) -> None:
    """
    Recursively collects all keys from a nested dict/list structure
    into the provided set. Depth-limited to prevent stack overflow on
    pathological inputs.
    """
    if max_depth <= 0:
        return

    if isinstance(obj, dict):
        for key, value in obj.items():
            keys_set.add(str(key).lower())
            _collect_keys_recursive(value, keys_set, max_depth - 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_keys_recursive(item, keys_set, max_depth - 1)


# =============================================================================
# Batch Filter Engine
# =============================================================================

def filter_high_value_traffic(
    parsed_requests: list[dict],
    threshold: float = 0.65,
) -> list[dict]:
    """
    Filters a batch of parsed HTTP requests, retaining only those whose
    exposure score meets or exceeds the given threshold. Designed for
    high-throughput processing of massive HAR imports (20MB+, thousands
    of entries) in under 150ms.

    Each surviving entry is annotated with an ``_exposure_score`` key
    containing its computed score for downstream consumption.

    :param parsed_requests: List of parsed request dicts (from traffic_parser
                            or HAR conversion).
    :param threshold: Minimum exposure score to retain (default 0.65).
    :return: Filtered list sorted descending by exposure score.
    """
    if not parsed_requests:
        return []

    scored: list[tuple[float, dict]] = []

    for req in parsed_requests:
        score = calculate_exposure_score(req)
        if score >= threshold:
            # Attach score for transparency/debugging
            req_copy = dict(req)
            req_copy["_exposure_score"] = round(score, 4)
            scored.append((score, req_copy))

    # Sort descending by score — highest-value endpoints first
    scored.sort(key=lambda item: item[0], reverse=True)

    result = [entry for _, entry in scored]

    logger.info(
        f"[PRUNER] Filtered {len(parsed_requests)} requests → "
        f"{len(result)} high-value endpoints (threshold={threshold})"
    )

    return result
