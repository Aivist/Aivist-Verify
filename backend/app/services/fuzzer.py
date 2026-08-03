# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Fuzzing Execution Engine — Differential Request Replay & Verification
#
# Core Pipeline:
#   1. Load finding + automation_payloads from DB
#   2. Reconstruct target URL from parsed request / matched_at
#   3. Send baseline request(s) → compute average Content-Length, status, timing
#   4. For each payload: mutate → send → differential compare → write FuzzingRecord
# ==============================================================================

import copy
import json
import time
import logging
import uuid
import re
import asyncio
import random
import difflib
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode, urlparse, urlunparse, urljoin, parse_qsl

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import async_session_factory
from backend.app.core.config import settings, reveal_secret
from backend.app.models.scan import VulnerabilityFinding, FuzzingRecord, utcnow
from backend.app.services.proxy_pipeline import is_writer_running, get_writer_service
# Scope-lock (node 3): the single audited host-scope decision. Pure/stdlib-only, so
# importing it here adds no import-time weight and cannot cycle (scope.py imports
# neither fuzzer nor config).
from backend.app.services.scope import ScopePolicy

logger = logging.getLogger("app.services.fuzzer")

# Max chars of the response body stored in the FuzzingRecord display log (N4).
# Note: the differential oracle runs on the full captured body
# (settings.FUZZER_RESPONSE_BODY_MAX_LENGTH); this smaller cap only trims what
# we persist for human review, so it intentionally differs from the capture cap.
_RECORD_RESPONSE_LOG_MAX_LENGTH = 3000

# Keywords that indicate a WAF / security filter blocked the request
_BLOCK_KEYWORDS = frozenset({
    "access denied", "forbidden", "blocked", "waf", "captcha",
    "rate limit", "not authorized", "invalid token", "csrf",
})

# Headers to strip before differential comparison (volatile / non-deterministic)
_VOLATILE_HEADERS = frozenset({
    "date", "keep-alive", "x-powered-by", "transfer-encoding",
    "content-length", "set-cookie", "server", "x-runtime",
})

# JSON keys whose values are dynamic noise (timestamps, tokens, etc.)
_DYNAMIC_JSON_KEYS = frozenset({
    "timestamp", "time", "id", "uuid", "token",
    "nonce", "csrf", "request_id",
})

# Regex patterns for normalizing dynamic text noise
_DYNAMIC_TEXT_PATTERNS = [
    # ISO 8601 timestamps: 2024-01-15T12:30:45.123Z
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*Z?(?:[+-]\d{2}:?\d{2})?"),
    # RFC 2822 / common datetime: Mon, 15 Jan 2024 12:30:45 GMT
    re.compile(r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*\w*"),
    # UUIDs: 550e8400-e29b-41d4-a716-446655440000 (MUST precede Unix timestamp pattern)
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    # High-entropy hex tokens (32+ chars)
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    # Unix timestamps (10 or 13 digits) — after UUID to avoid partial UUID clobbering
    re.compile(r"\b\d{10,13}\b"),
]

# SequenceMatcher CPU protection cap (characters)
_SEQUENCE_MATCHER_MAX_LEN = 50_000

# Veto keywords — force verdict to 'failed' if present in 200 OK response
_VETO_KEYWORDS = frozenset({
    "error", "forbidden", "unauthorized", "permission denied",
    "操作无权限", "login", "access denied",
})

# Escalation keys — if these appear ONLY in test response, escalate to 'verified'
_ESCALATION_KEYS = frozenset({
    "email", "token", "password", "ssn", "admin",
    "secret", "credit_card", "phone",
})

# SQLite retry config
_DB_COMMIT_MAX_RETRIES = 3
_DB_COMMIT_BASE_DELAY = 0.1  # seconds, exponential backoff base

# Adaptive backoff for 429 / 503 responses
_RATE_LIMIT_DEFAULT_PAUSE = 5.0  # seconds


# ==============================================================================
# Step 7: Dynamic Session Custody & Auto-Resume State Machine
# ==============================================================================
# Terminology note: this engine runs inside a single asyncio event loop, so the
# synchronization primitives below are *coroutine/task-safe* (asyncio.Event /
# asyncio.Lock) — not OS-thread-safe. That is the correct safety model here;
# there are no OS threads to guard against.

# 200-OK "soft logout" body signatures (lower-cased substring match)
_AUTH_DEATH_BODY_SIGNATURES = (
    "session expired",
    "please login",
    "token invalid",
    "unauthenticated",
    "authorization required",
)

# Hard auth-death status codes
_AUTH_DEATH_STATUS = frozenset({401, 403})

# Re-authentication circuit-breaker config
_AUTH_REFRESH_MAX_RETRIES = 3
_AUTH_REFRESH_BASE_DELAY = 0.5  # seconds, exponential backoff base

# Module-level registry so the API layer (GET /verify/{id}/results) can surface
# live re-auth diagnostics for a running fuzzing job. Keyed by finding_id.
# In a parallel batch, multiple finding_ids point at the SAME controller object.
_ACTIVE_CUSTODY: Dict[int, "AuthCustodyController"] = {}


# ==============================================================================
# Step 8: Parallel Fuzzing Engine configuration
# ==============================================================================
# Global cap on concurrent outbound fuzz requests across ALL endpoints in a batch.
_PARALLEL_MAX_CONCURRENCY = 5
# Single-Writer Consumer batching: the lone DB-writer commits every N records OR
# every T seconds, so polling UIs see steady progress without per-record thrash.
_DB_WRITER_BATCH_SIZE = 10
_DB_WRITER_FLUSH_INTERVAL = 1.5  # seconds
# Sentinel placed on the result queue to tell the writer to drain and stop.
_QUEUE_SENTINEL = object()
# Anti-thrash guard: max distinct re-auth cycles per run before failing fast
# (prevents an endless refresh loop when a fresh token is still rejected).
_MAX_REAUTH_CYCLES = 3


class ScopeViolationError(Exception):
    """Raised when a dispatch would target a host outside the approved scope."""


class AuthCustodyController:
    """
    Per-finding authentication custody controller (Section 7.1).

    Holds the master barrier gate, the single in-memory active auth value, and
    the cached re-auth request. Every outbound fuzzing dispatch gates on
    ``session_valid_event`` and inline-injects ``current_active_auth_value``.
    """

    def __init__(
        self,
        finding_id: int,
        auth_refresh_request: Optional[dict] = None,
        initial_auth_value: str = "",
        auth_kind: str = "cookie",
        approved_host: str = "",
        max_reauth_cycles: int = _MAX_REAUTH_CYCLES,
        scope_policy: Optional["ScopePolicy"] = None,
    ) -> None:
        self.finding_id = finding_id  # label only (first finding in a batch)
        # Barrier: set == valid/open; cleared == re-authenticating/blocked.
        self.session_valid_event = asyncio.Event()
        self.session_valid_event.set()  # start in the valid (open) state
        # Dynamic identity storage
        self.current_active_auth_value: str = initial_auth_value or ""
        self.auth_kind: str = auth_kind  # "cookie" | "token"
        # Single-flight refresh guard
        self.is_refreshing: bool = False
        self._refresh_lock = asyncio.Lock()
        # Cached re-auth request config (method/url/headers/body) or None
        self.auth_refresh_request: Optional[dict] = auth_refresh_request
        # Step 8: domain scope lock — re-auth/probe may only target this host.
        self.approved_host: str = (approved_host or "").lower()
        # Scope-lock (node 3): the ONE audited policy for the re-auth probe + outbound
        # sends. An explicit policy wins; else derive from approved_host (byte-compat).
        # None => unlocked.
        self.scope_policy: Optional["ScopePolicy"] = scope_policy or (
            ScopePolicy.from_declaration([self.approved_host]) if self.approved_host else None
        )
        # Step 8: anti-thrash re-auth cycle cap
        self.max_reauth_cycles: int = max_reauth_cycles
        self.reauth_count: int = 0
        # Diagnostics
        self.refresh_failed: bool = False
        self.last_diagnostic: str = ""

    def is_reauthenticating(self) -> bool:
        """True while the barrier is cleared (a refresh is in flight)."""
        return not self.session_valid_event.is_set()

    async def _refresh_session_and_resume(self) -> None:
        """
        Deadlock-free re-auth (Section 7.3).

        Single-flight guarded by ``is_refreshing``; the ``finally`` block ALWAYS
        clears the flag and re-opens the barrier so pending tasks either resume
        with a fresh credential or fail fast — never gridlock.
        """
        # --- Section 7.3.1: single-flight race prevention ---
        async with self._refresh_lock:
            if self.is_refreshing:
                return  # another task already owns the refresh; bow out
            self.is_refreshing = True

        try:
            # --- No cached refresh request → cannot recover; fail fast ---
            if not self.auth_refresh_request:
                self.refresh_failed = True
                self.last_diagnostic = (
                    "[RE-AUTH ABORTED] No cached auth_refresh_request configured; "
                    "cannot recover session. Releasing barrier so tasks fail fast."
                )
                logger.critical(f"[CUSTODY · {self.finding_id}] {self.last_diagnostic}")
                return

            # Step 8: anti-thrash cap — bail if we've already cycled too many times
            if self.reauth_count >= self.max_reauth_cycles:
                self.refresh_failed = True
                self.last_diagnostic = (
                    f"[RE-AUTH CAPPED] Reached max {self.max_reauth_cycles} re-auth "
                    f"cycles; refusing to thrash. Releasing barrier (fail fast)."
                )
                logger.critical(f"[CUSTODY · {self.finding_id}] {self.last_diagnostic}")
                return
            self.reauth_count += 1

            req = self.auth_refresh_request
            method = str(req.get("method", "POST")).upper()
            url = req.get("url", "")
            headers = req.get("headers", {}) or {}
            body = req.get("body")

            # Step 8 Constraint 2(a): domain scope lock — never probe a 3rd-party host.
            # Converged onto the ONE audited ScopePolicy (host-level; the resolved-IP guard
            # lives at the _send_request chokepoint).
            if self.scope_policy is not None and not self.scope_policy.netloc_allowed(_host_of(url)):
                self.refresh_failed = True
                self.last_diagnostic = (
                    f"[RE-AUTH BLOCKED] Refresh host '{_host_of(url)}' is outside approved "
                    f"scope '{self.approved_host}'. Refusing out-of-scope probe."
                )
                logger.critical(f"[CUSTODY · {self.finding_id}] {self.last_diagnostic}")
                return

            last_error: Any = None
            # --- Section 7.3.2: circuit breaker, max 3 retries ---
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
                    read=settings.FUZZER_HTTP_TIMEOUT_READ,
                    write=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
                    pool=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
                ),
                verify=False,
            ) as client:
                for attempt in range(_AUTH_REFRESH_MAX_RETRIES):
                    try:
                        kwargs: Dict[str, Any] = {
                            "method": method,
                            "url": url,
                            "headers": headers,
                            "follow_redirects": True,
                        }
                        if body is not None and method in ("POST", "PUT", "PATCH", "DELETE"):
                            if isinstance(body, dict):
                                kwargs["json"] = body
                            else:
                                kwargs["content"] = str(body)

                        resp = await client.request(**kwargs)

                        new_value, kind = _extract_new_auth_value(resp)
                        if new_value:
                            self.current_active_auth_value = new_value
                            self.auth_kind = kind
                            self.refresh_failed = False
                            self.last_diagnostic = (
                                f"[RE-AUTH OK] New {kind} acquired on attempt {attempt + 1}."
                            )
                            logger.info(f"[CUSTODY · {self.finding_id}] {self.last_diagnostic}")
                            return
                        last_error = f"status={resp.status_code}, no token/cookie extracted"
                    except Exception as e:  # must never escape — circuit breaker owns it
                        last_error = e

                    # Exponential backoff before the next attempt
                    await asyncio.sleep(_AUTH_REFRESH_BASE_DELAY * (2 ** attempt))

            self.refresh_failed = True
            self.last_diagnostic = (
                f"[RE-AUTH FAILED] Exhausted {_AUTH_REFRESH_MAX_RETRIES} attempts: {last_error}"
            )
            logger.critical(f"[CUSTODY · {self.finding_id}] {self.last_diagnostic}")

        finally:
            # --- The Anti-Deadlock Contract (Section 7.3.2) ---
            # ALWAYS clear the flag and re-open the gate, success or failure.
            self.is_refreshing = False
            self.session_valid_event.set()


def _extract_new_auth_value(response: "httpx.Response") -> tuple:
    """
    Extracts a fresh credential from a refresh response (Section 7.3.2).

    Priority:
        1. Set-Cookie header  → ("name=value", "cookie")
        2. First-level JSON access_token / token → (value, "token")

    Returns ("", "") if nothing usable was found.
    """
    set_cookie = response.headers.get("set-cookie", "")
    if set_cookie:
        # Take the first cookie pair (name=value), drop attributes
        return set_cookie.split(";")[0].strip(), "cookie"

    try:
        data = response.json()
        if isinstance(data, dict):
            for key in ("access_token", "token"):
                val = data.get(key)
                if val:
                    return str(val), "token"
    except Exception:
        pass

    return "", ""


def _inject_active_auth(headers: dict, custody: Optional["AuthCustodyController"]) -> dict:
    """
    O(1) inline auth header overwrite (Section 7.3.3).

    Called right before the socket opens. Overwrites the Authorization header
    (token kind) or Cookie header (cookie kind). No-ops when no active value is
    set, guaranteeing byte-identical requests pre-refresh (zero regression).
    """
    if custody is None or not custody.current_active_auth_value:
        return headers

    new_headers = dict(headers)
    value = custody.current_active_auth_value

    if custody.auth_kind == "token":
        auth_key = next((k for k in new_headers if k.lower() == "authorization"), "Authorization")
        new_headers[auth_key] = value if value.lower().startswith("bearer ") else f"Bearer {value}"
    else:  # cookie
        cookie_key = next((k for k in new_headers if k.lower() == "cookie"), "Cookie")
        new_headers[cookie_key] = value

    return new_headers


def _is_auth_death(status_code: int, response_body: str) -> bool:
    """Heuristic auth-death detector (Section 7.2.1)."""
    if status_code in _AUTH_DEATH_STATUS:
        return True
    if status_code == 200:
        low = (response_body or "").lower()
        return any(sig in low for sig in _AUTH_DEATH_BODY_SIGNATURES)
    return False


def _host_of(url: str) -> str:
    """Returns the lower-cased netloc (host[:port]) of a URL, or '' on failure."""
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


def get_active_custody(finding_id: int) -> Optional["AuthCustodyController"]:
    """API-layer accessor for live re-auth diagnostics (Section 7.4)."""
    return _ACTIVE_CUSTODY.get(finding_id)


def _extract_auth_refresh_request(finding: VulnerabilityFinding) -> Optional[dict]:
    """
    Optional hook: resolves a cached re-auth request for the finding.

    Step D resolution order:
        1. The explicit ``auth_refresh_request`` JSON column (Hunter findings).
        2. LEGACY fallback: a {"auth_refresh_request": {...}} object embedded in
           the ai_patch / poc_request text columns.
    Returns None if not supplied (re-auth then fails fast & releases the gate).
    """
    # --- Step D: explicit typed column takes precedence ---
    column_refresh = getattr(finding, "auth_refresh_request", None)
    if isinstance(column_refresh, dict) and column_refresh:
        # Accept both a wrapped {"auth_refresh_request": {...}} and a bare dict.
        if isinstance(column_refresh.get("auth_refresh_request"), dict):
            return column_refresh["auth_refresh_request"]
        if column_refresh.get("url"):
            return column_refresh

    # --- LEGACY fallback: JSON embedded in text columns ---
    for field_value in [finding.ai_patch, finding.poc_request]:
        if not field_value:
            continue
        try:
            data = json.loads(field_value)
            if isinstance(data, dict) and isinstance(data.get("auth_refresh_request"), dict):
                return data["auth_refresh_request"]
        except (json.JSONDecodeError, TypeError):
            continue
    return None


# ==============================================================================
# 1. Request Mutation Engine
# ==============================================================================

async def mutate_request(parsed_request: dict, payload_instruction: dict) -> dict:
    """
    Deep-copies the parsed HTTP request and applies a single mutation
    based on the payload instruction's location and target_param.

    Supported locations:
        - query_param:  Mutate or inject into query_params dict
        - json_key:     Mutate or inject into body dict (when body is JSON)
        - header:       Mutate or inject into headers dict
        - cookie:       Mutate a value within the Cookie header string
        - path_segment: Replace a path segment matching target_param

    Returns the mutated request dict. Never raises — logs warnings on failures.
    """
    mutated = copy.deepcopy(parsed_request)
    location = payload_instruction.get("location", "").lower()
    target_param = payload_instruction.get("target_param", "")
    payload_value = payload_instruction.get("payload_string", "")

    try:
        if location == "query_param":
            if not isinstance(mutated.get("query_params"), dict):
                mutated["query_params"] = {}
            mutated["query_params"][target_param] = payload_value

        elif location == "json_key":
            if isinstance(mutated.get("body"), dict):
                mutated["body"][target_param] = payload_value
            else:
                logger.warning(
                    f"[MUTATOR] Cannot apply json_key mutation: body is not a dict. "
                    f"Target: {target_param}"
                )

        elif location == "header":
            if not isinstance(mutated.get("headers"), dict):
                mutated["headers"] = {}
            mutated["headers"][target_param] = payload_value

        elif location == "cookie":
            headers = mutated.get("headers", {})
            cookie_str = headers.get("Cookie", headers.get("cookie", ""))
            # Parse existing cookies, apply mutation
            cookie_parts = {}
            for segment in cookie_str.split(";"):
                segment = segment.strip()
                if "=" in segment:
                    k, _, v = segment.partition("=")
                    cookie_parts[k.strip()] = v.strip()
            cookie_parts[target_param] = payload_value
            new_cookie = "; ".join(f"{k}={v}" for k, v in cookie_parts.items())
            mutated["headers"]["Cookie"] = new_cookie

        elif location == "path_segment":
            original_path = mutated.get("path", "/")
            segments = original_path.split("/")
            replaced = False
            for i, seg in enumerate(segments):
                if seg == target_param or seg.lower() == target_param.lower():
                    segments[i] = payload_value
                    replaced = True
                    break
            if not replaced:
                # Append as last segment if target not found
                segments.append(payload_value)
            mutated["path"] = "/".join(segments)

        else:
            logger.warning(f"[MUTATOR] Unknown location '{location}'. Skipping mutation.")

    except Exception as e:
        logger.error(f"[MUTATOR] Exception during mutation: {e}")

    return mutated


# ==============================================================================
# 2. HTTP Request Sender
# ==============================================================================

def _reconstruct_url(parsed_request: dict, base_url: str) -> str:
    """
    Reconstructs a full URL from the parsed request's path + query_params,
    anchored to the base_url derived from matched_at or Host header.
    """
    parsed_base = urlparse(base_url)
    path = parsed_request.get("path", "/")
    query_params = parsed_request.get("query_params", {})
    # If the path itself already carries a query (e.g. an op wrote "/x?a=1"), split it off and
    # MERGE with query_params — explicit query_params win on a key clash — so a query-string id
    # composes correctly and we never emit a malformed double-'?' URL (D29). A path with no '?'
    # is untouched, so path-based cases stay byte-identical.
    if "?" in path:
        path, _, _embedded = path.partition("?")
        merged = dict(parse_qsl(_embedded, keep_blank_values=True))
        if query_params:
            merged.update(query_params)
        query_string = urlencode(merged, doseq=True) if merged else ""
    else:
        query_string = urlencode(query_params, doseq=True) if query_params else ""

    reconstructed = urlunparse((
        parsed_base.scheme or "https",
        parsed_base.netloc,
        path,
        "",  # params
        query_string,
        "",  # fragment
    ))
    return reconstructed


def _extract_base_url(finding: VulnerabilityFinding) -> str:
    """
    Derives the target base URL from the finding's matched_at field.
    Falls back to https:// prefix if no scheme is present.
    """
    matched_at = finding.matched_at or ""
    if matched_at.startswith("http://") or matched_at.startswith("https://"):
        parsed = urlparse(matched_at)
        return f"{parsed.scheme}://{parsed.netloc}"
    # If matched_at is just a hostname or path, attempt to construct
    if "/" in matched_at:
        host_part = matched_at.split("/")[0]
    else:
        host_part = matched_at
    return f"https://{host_part}"


# Bounded manual-redirect chain length (scope-lock node 3). Only reached when a scope
# is LOCKED; unlocked/lab mode keeps httpx's own auto-follow, byte-identically.
_MAX_REDIRECTS = 5


def _effective_scope_policy(
    scope: Optional["ScopePolicy"], custody: Optional["AuthCustodyController"]
) -> Optional["ScopePolicy"]:
    """The scope policy this dispatch enforces. An explicit `scope` wins; else it is
    derived from `custody.approved_host` (so the existing fuzzer call sites, which pass
    only custody, converge onto the ONE audited gate without any call-site change). No
    approved host on either => None (UNLOCKED / lab mode; byte-identical to today)."""
    if scope is not None:
        return scope
    if custody is not None:
        pol = getattr(custody, "scope_policy", None)
        if pol is not None:
            return pol
        if getattr(custody, "approved_host", ""):
            return ScopePolicy.from_declaration([custody.approved_host])
    return None


def _build_request_kwargs(
    method: str, url: str, headers: dict, body: Any, follow_redirects: bool
) -> Dict[str, Any]:
    """Assemble httpx request kwargs — the SAME json/content/Content-Type logic the
    initial request and every manual-redirect re-issue share (kept identical to the
    pre-scope-lock inline build; only `follow_redirects` is now a parameter)."""
    kwargs: Dict[str, Any] = {
        "method": method, "url": url, "headers": headers,
        "follow_redirects": follow_redirects,
    }
    if body is not None and method in ("POST", "PUT", "PATCH", "DELETE"):
        if isinstance(body, dict):
            kwargs["json"] = body
        else:
            kwargs["content"] = str(body)
            if "Content-Type" not in headers and "content-type" not in headers:
                kwargs["headers"] = {**headers, "Content-Type": "text/plain"}
    return kwargs


async def _follow_redirects_scoped(
    client: httpx.AsyncClient, response: "httpx.Response",
    method: str, headers: dict, body: Any, policy: "ScopePolicy",
) -> "httpx.Response":
    """Per-hop redirect enforcement (LOCKED scope only). httpx auto-follow is disabled
    for a locked scope; instead each redirect Location is re-validated against the SAME
    policy (host + resolved-IP) BEFORE it is followed, and the FIRST out-of-scope hop is
    refused. Redirect method/body semantics mirror httpx: 307/308 preserve; 301/302/303
    become GET with no body. Bounded by `_MAX_REDIRECTS`."""
    hops = 0
    while response.status_code in (301, 302, 303, 307, 308) and hops < _MAX_REDIRECTS:
        location = response.headers.get("location")
        if not location:
            break
        next_url = urljoin(str(response.request.url), location)
        decision = policy.check(next_url)
        if not decision.allowed:
            raise ScopeViolationError(
                f"redirect to out-of-scope target refused ({decision.reason}): {next_url}"
            )
        if response.status_code in (307, 308):
            next_method, next_body = method, body
        else:
            next_method, next_body = "GET", None
        response = await client.request(
            **_build_request_kwargs(next_method, next_url, headers, next_body,
                                    follow_redirects=False)
        )
        method, body, hops = next_method, next_body, hops + 1
    return response


async def _send_request(
    client: httpx.AsyncClient,
    parsed_request: dict,
    base_url: str,
    custody: Optional["AuthCustodyController"] = None,
    scope: Optional["ScopePolicy"] = None,
) -> Dict[str, Any]:
    """
    Sends an HTTP request based on the parsed request structure.
    Includes adaptive back-off for 429/503 rate-limit responses with single retry.
    Returns a dict with status_code, content_length, response_body (truncated), elapsed_ms.

    Section 7.1/7.3.3: when a custody controller is supplied, this dispatch
    gates on the barrier event and inline-injects the current active auth value
    immediately before the socket opens.

    SCOPE LOCK (node 3): this is the ONE audited outbound gate. It enforces the scope
    policy UNCONDITIONALLY (no longer only when a custody controller is present),
    fail-closed, before the socket opens; and when the scope is LOCKED it disables
    httpx auto-follow and validates every redirect hop against the same policy. An
    UNLOCKED policy (no scope declared — the labs / 430/430 harness default) is a
    pass-through that keeps httpx auto-follow, so behavior is byte-identical to before.
    """
    url = _reconstruct_url(parsed_request, base_url)
    method = parsed_request.get("method", "GET").upper()
    headers = parsed_request.get("headers", {})
    body = parsed_request.get("body")

    # --- Scope lock: fail-closed gate on the initial URL, before anything else ------
    policy = _effective_scope_policy(scope, custody)
    locked = policy is not None and policy.locked
    if locked:
        decision = policy.check(url)
        if not decision.allowed:
            raise ScopeViolationError(
                f"out-of-scope target refused ({decision.reason}): {url}"
            )

    # --- Section 7.1: barrier gate + Section 7.3.3: O(1) inline auth injection ---
    if custody is not None:
        await custody.session_valid_event.wait()
        headers = _inject_active_auth(headers, custody)

    # Build httpx-compatible kwargs. follow_redirects stays True (httpx auto-follow,
    # byte-identical) when UNLOCKED; a LOCKED scope disables it so redirects are
    # validated per-hop below.
    kwargs = _build_request_kwargs(method, url, headers, body, follow_redirects=not locked)

    start_time = time.monotonic()
    response = await client.request(**kwargs)

    # Adaptive back-off for rate limiting (429 / 503)
    if response.status_code in (429, 503):
        retry_after = _RATE_LIMIT_DEFAULT_PAUSE
        if "Retry-After" in response.headers:
            try:
                retry_after = float(response.headers["Retry-After"])
            except (ValueError, TypeError):
                pass
        logger.warning(
            f"[FUZZER · RATE LIMIT] Received {response.status_code}, "
            f"backing off {retry_after}s before retry..."
        )
        await asyncio.sleep(retry_after)
        # Single retry after back-off
        start_time = time.monotonic()
        response = await client.request(**kwargs)

    # Per-hop redirect enforcement (LOCKED scope only; unlocked already auto-followed).
    if locked:
        response = await _follow_redirects_scoped(client, response, method, headers, body, policy)

    elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)

    response_text = response.text[:settings.FUZZER_RESPONSE_BODY_MAX_LENGTH]

    return {
        "status_code": response.status_code,
        "content_length": len(response.content),
        "response_body": response_text,
        "elapsed_ms": elapsed_ms,
        "url": url,
    }


def _serialize_request_for_log(parsed_request: dict, base_url: str) -> str:
    """Serializes a parsed request into a human-readable text block for DB storage."""
    url = _reconstruct_url(parsed_request, base_url)
    method = parsed_request.get("method", "GET")
    headers = parsed_request.get("headers", {})
    body = parsed_request.get("body")

    lines = [f"{method} {url}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        if isinstance(body, dict):
            lines.append(json.dumps(body, ensure_ascii=False, indent=2))
        else:
            lines.append(str(body))
    return "\n".join(lines)


# ==============================================================================
# 3. Response Sanitization Engine (Anti-Noise)
# ==============================================================================

def _sanitize_json_recursive(obj: Any) -> Any:
    """
    Recursively traverses a JSON-compatible structure (dict/list).
    Replaces values under dynamic noise keys with '{{DYNAMIC_NOISE}}'.
    Ensures deterministic comparison by removing server-injected randomness.
    """
    if isinstance(obj, dict):
        return {
            k: "{{DYNAMIC_NOISE}}" if k.lower() in _DYNAMIC_JSON_KEYS
            else _sanitize_json_recursive(v)
            for k, v in obj.items()
        }
    elif isinstance(obj, list):
        return [_sanitize_json_recursive(item) for item in obj]
    return obj


def _sanitize_response_text(raw_text: str) -> str:
    """
    Sanitizes response body text to remove dynamic noise before comparison.

    Pipeline:
        1. If valid JSON: apply recursive key sanitizer, re-serialize with sorted keys.
        2. Apply regex patterns to neutralize timestamps, UUIDs, hex tokens.
    """
    text = raw_text

    # Attempt JSON deep cleaning
    try:
        parsed = json.loads(text)
        sanitized_obj = _sanitize_json_recursive(parsed)
        text = json.dumps(sanitized_obj, sort_keys=True, ensure_ascii=False)
    except (json.JSONDecodeError, TypeError):
        pass  # Not JSON — proceed with regex

    # Apply regex text sanitization regardless (catches embedded dynamic strings)
    for pattern in _DYNAMIC_TEXT_PATTERNS:
        text = pattern.sub("{{DYNAMIC_NOISE}}", text)

    return text


def _normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Returns a copy of headers with volatile/non-deterministic keys removed."""
    return {
        k: v for k, v in headers.items()
        if k.lower() not in _VOLATILE_HEADERS
    }


def _compute_similarity(text_a: str, text_b: str) -> float:
    """
    Computes textual similarity ratio using SequenceMatcher.

    CPU Protection: Truncates inputs exceeding _SEQUENCE_MATCHER_MAX_LEN characters
    to prevent O(N²) worst-case stalling the event loop on large HTML/JSON bodies.
    """
    a = text_a[:_SEQUENCE_MATCHER_MAX_LEN]
    b = text_b[:_SEQUENCE_MATCHER_MAX_LEN]
    return difflib.SequenceMatcher(None, a, b).ratio()


# ==============================================================================
# 4. Differential Analysis Oracle
# ==============================================================================

def _differential_verdict(
    baseline: Dict[str, Any],
    test_result: Dict[str, Any],
    payload_instruction: dict,
) -> Dict[str, Any]:
    """
    Advanced Differential Oracle with noise reduction, veto, and escalation rules.

    Pipeline:
        1. Sanitize both response bodies (recursive JSON + regex text normalization).
        2. Compute textual similarity ratio (with CPU protection cap).
        3. Apply length/status heuristics (preserves original Rule 1-5 logic).
        4. Apply Veto Rule (prevent false positives on denial strings in 200 OK).
        5. Apply Escalation Rule (prevent false negatives on leaked sensitive data).

    Returns a dict with verdict, metrics, and analysis notes.
    """
    base_len = baseline.get("content_length", 0)
    test_len = test_result.get("content_length", 0)
    base_status = baseline.get("status_code", 0)
    test_status = test_result.get("status_code", 0)

    length_deviation = abs(test_len - base_len) / max(base_len, 1)

    # --- Sanitize response bodies for noise-free comparison ---
    base_body_sanitized = _sanitize_response_text(baseline.get("response_body", ""))
    test_body_sanitized = _sanitize_response_text(test_result.get("response_body", ""))

    # --- Compute textual similarity (CPU-protected) ---
    similarity = _compute_similarity(base_body_sanitized, test_body_sanitized)
    body_capped = (
        len(base_body_sanitized) > _SEQUENCE_MATCHER_MAX_LEN
        or len(test_body_sanitized) > _SEQUENCE_MATCHER_MAX_LEN
    )

    response_body_lower = test_result.get("response_body", "").lower()
    is_blocked = any(kw in response_body_lower for kw in _BLOCK_KEYWORDS)

    vuln_type = payload_instruction.get("type", "").upper()
    notes = []
    verdict = "failed"

    # Rule 1: Server error triggered (potential crash / injection)
    if base_status < 500 and test_status >= 500:
        verdict = "verified"
        notes.append(f"Server error triggered: {base_status} -> {test_status}")

    # Rule 2: BOLA / IDOR — access granted with different credentials
    elif vuln_type in ("BOLA", "IDOR"):
        if test_status == 200 and not is_blocked:
            if length_deviation > 0.05:
                verdict = "verified"
                notes.append(
                    f"IDOR/BOLA confirmed: status 200, length deviation {length_deviation:.2%}, "
                    f"similarity {similarity:.2%}, no blocking detected"
                )
            else:
                verdict = "suspicious"
                notes.append(
                    f"IDOR/BOLA possible: status 200, length deviation {length_deviation:.2%}, "
                    f"similarity {similarity:.2%}"
                )
        elif test_status == 200 and is_blocked:
            verdict = "failed"
            notes.append("Request returned 200 but response contains blocking keywords")

    # Rule 3: Privilege escalation / mass assignment — unexpected success
    elif vuln_type in ("MASS_ASSIGNMENT", "PARAMETER_POLLUTION"):
        if test_status in (200, 201) and not is_blocked and length_deviation > 0.1:
            verdict = "verified"
            notes.append(
                f"Parameter manipulation succeeded: status {test_status}, "
                f"length deviation {length_deviation:.2%}"
            )
        elif test_status in (200, 201):
            verdict = "suspicious"
            notes.append(f"Status {test_status} but minimal response change")

    # Rule 4: Generic — significant divergence
    elif length_deviation > 0.15 and not is_blocked:
        verdict = "suspicious"
        notes.append(f"Significant response divergence: {length_deviation:.2%}")

    # Rule 5: Status code change (non-error) could be interesting
    elif base_status != test_status:
        verdict = "suspicious"
        notes.append(f"Status code changed: {base_status} -> {test_status}")

    # ------------------------------------------------------------------ #
    # Veto Rule: Override false positives on 200 OK with denial strings
    # Even if heuristics flagged verified/suspicious, explicit denial in the
    # response body means the server rejected the attack — not exploitable.
    # ------------------------------------------------------------------ #
    if verdict in ("verified", "suspicious") and test_status == 200:
        test_lower = test_result.get("response_body", "").lower()
        if any(kw in test_lower for kw in _VETO_KEYWORDS):
            verdict = "failed"
            notes.append("VETO: Response body contains explicit denial/error strings despite 200 OK")

    # ------------------------------------------------------------------ #
    # Escalation Rule: Promote suspicious to verified on sensitive data leak
    # If the fuzzing response contains high-risk keys (email, password, etc.)
    # that were completely absent in the baseline, this confirms data exposure.
    # ------------------------------------------------------------------ #
    if verdict == "suspicious" and test_status == 200 and length_deviation <= 0.05:
        base_lower = baseline.get("response_body", "").lower()
        test_lower = test_result.get("response_body", "").lower()
        leaked = [k for k in _ESCALATION_KEYS if k in test_lower and k not in base_lower]
        if leaked:
            verdict = "verified"
            notes.append(f"ESCALATION: Sensitive keys found only in test response: {leaked}")

    if not notes:
        notes.append("No significant deviation detected")

    return {
        "verdict": verdict,
        "length_deviation_ratio": round(length_deviation, 4),
        "status_code_baseline": base_status,
        "status_code_test": test_status,
        "content_length_baseline": base_len,
        "content_length_test": test_len,
        "elapsed_ms_baseline": baseline.get("elapsed_ms", 0),
        "elapsed_ms_test": test_result.get("elapsed_ms", 0),
        "is_blocked": is_blocked,
        "similarity_ratio": round(similarity, 4),
        "sanitized_body_capped": body_capped,
        "analysis_notes": "; ".join(notes),
    }


# ==============================================================================
# 5. SQLite Write Resiliency
# ==============================================================================

async def _commit_with_retry(db: AsyncSession) -> None:
    """
    Wraps db.commit() with exponential backoff retry to handle
    SQLite 'database is locked' transient errors from concurrent writes.

    Retries up to _DB_COMMIT_MAX_RETRIES times with exponential delay.
    On non-retryable errors or final attempt exhaustion, re-raises.
    """
    for attempt in range(_DB_COMMIT_MAX_RETRIES):
        try:
            await db.commit()
            return
        except Exception as e:
            if "database is locked" in str(e).lower() and attempt < _DB_COMMIT_MAX_RETRIES - 1:
                delay = _DB_COMMIT_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    f"[FUZZER · DB RETRY] SQLite locked, attempt {attempt + 1}/{_DB_COMMIT_MAX_RETRIES}, "
                    f"retrying in {delay:.2f}s..."
                )
                await asyncio.sleep(delay)
            else:
                raise


# ==============================================================================
# 6. Parallel Fuzzing Engine (Step 8) — Single-Writer Consumer
# ==============================================================================

class _FindingJob:
    """A resolved per-endpoint fuzzing job (one VulnerabilityFinding)."""
    __slots__ = ("finding_id", "parsed_request", "base_url", "payloads", "baseline")

    def __init__(self, finding_id: int, parsed_request: dict, base_url: str, payloads: List[dict]):
        self.finding_id = finding_id
        self.parsed_request = parsed_request
        self.base_url = base_url
        self.payloads = payloads
        self.baseline: Optional[Dict[str, Any]] = None


def _make_persist_job(item: dict):
    """Wrap a result item as a model-agnostic WriteJob for the WriterService."""
    def _job(db: AsyncSession) -> None:
        _persist_record(
            db,
            item["record_id"],
            item["finding_id"],
            item["payload_index"],
            item["sent_request"],
            item["received_response"],
            item["verification_status"],
            item["diff_details"],
        )
    return _job


async def _forward_results_to_writer(result_queue: "asyncio.Queue", writer) -> None:
    """
    Step 9 unified-writer adapter: drain this batch's result_queue and submit
    each record as a WriteJob to the shared app-wide WriterService (which owns
    the only write session and commits on its own cadence). Stops on sentinel.
    Does NOT commit — serialization & commit are the WriterService's job.
    """
    while True:
        item = await result_queue.get()
        try:
            if item is _QUEUE_SENTINEL:
                return
            await writer.submit(_make_persist_job(item))
        except Exception:
            logger.exception("[FUZZER · WRITER-FWD] Failed to forward a result record")
        finally:
            result_queue.task_done()


async def _db_writer_consumer(result_queue: "asyncio.Queue") -> None:
    """
    The SOLE database writer (Step 8 Constraint 1).

    Owns the only write AsyncSession and drains `result_queue`, committing in
    small batches (size- or time-bounded) so the polling UI sees steady progress.
    Because exactly one coroutine ever touches this session, there is neither
    AsyncSession concurrency misuse nor a competing SQLite writer — the network
    layer parallelizes while writes stay safely serialized.
    """
    async with async_session_factory() as db:
        pending = 0
        while True:
            try:
                item = await asyncio.wait_for(
                    result_queue.get(), timeout=_DB_WRITER_FLUSH_INTERVAL
                )
            except asyncio.TimeoutError:
                # Idle tick — flush buffered rows so pollers keep seeing progress.
                if pending:
                    await _commit_with_retry(db)
                    pending = 0
                continue

            try:
                if item is _QUEUE_SENTINEL:
                    if pending:
                        await _commit_with_retry(db)
                    return
                _persist_record(
                    db,
                    item["record_id"],
                    item["finding_id"],
                    item["payload_index"],
                    item["sent_request"],
                    item["received_response"],
                    item["verification_status"],
                    item["diff_details"],
                )
                pending += 1
                if pending >= _DB_WRITER_BATCH_SIZE:
                    await _commit_with_retry(db)
                    pending = 0
            except Exception:
                logger.exception("[FUZZER · WRITER] Failed to persist a result record")
            finally:
                result_queue.task_done()


async def execute_parallel_fuzzing(
    finding_ids: List[int],
    auth_refresh_request: Optional[dict] = None,
    approved_host: Optional[str] = None,
    max_concurrency: int = _PARALLEL_MAX_CONCURRENCY,
    scope: Optional[List[str]] = None,
    model: Optional[str] = None,
) -> None:
    """
    Step 8 master engine: true-concurrent multi-endpoint fuzzing that shares ONE
    self-healing AuthCustodyController, backed by a single DB-writer consumer.

    Design:
        - Network I/O runs concurrently (asyncio.gather + a global Semaphore).
        - All workers share one custody barrier; an auth-death anywhere pauses the
          whole batch, fires exactly ONE re-auth, injects globally, and resumes.
        - Every DB write funnels through `_db_writer_consumer` (no concurrent writers).
        - Single-host batch lock (Constraint 2): all endpoints must share one host.

    `auth_refresh_request` is transient (never persisted). When omitted, a cached
    refresh request is harvested from the finding JSON as a fallback.
    """
    if not finding_ids:
        return
    logger.info(f"[FUZZER · PARALLEL] Starting batch for finding_ids={finding_ids}")

    # --- Phase 1: load findings & build jobs (read-only session) ---
    jobs: List[_FindingJob] = []
    fallback_refresh: Optional[dict] = None
    async with async_session_factory() as db:
        result = await db.execute(
            select(VulnerabilityFinding).where(VulnerabilityFinding.id.in_(finding_ids))
        )
        findings = {f.id: f for f in result.scalars().all()}
        for fid in finding_ids:
            finding = findings.get(fid)
            if finding is None:
                logger.error(f"[FUZZER · PARALLEL] Finding ID {fid} not found; skipping.")
                continue
            payloads = _extract_payloads(finding)
            if not payloads:
                logger.warning(f"[FUZZER · PARALLEL] No payloads for finding_id={fid}; skipping.")
                continue
            jobs.append(_FindingJob(
                finding_id=fid,
                parsed_request=_extract_parsed_request(finding),
                base_url=_extract_base_url(finding),
                payloads=payloads,
            ))
            if fallback_refresh is None:
                fallback_refresh = _extract_auth_refresh_request(finding)

    if not jobs:
        logger.warning("[FUZZER · PARALLEL] No runnable jobs in batch. Aborting.")
        return

    # --- Phase 2: single-host batch lock (Constraint 2) + unified scope policy ---
    hosts = {_host_of(job.base_url) for job in jobs if _host_of(job.base_url)}
    # Build the ONE audited scope policy from the unified `scope` declaration, or the
    # legacy `approved_host` alias. None => UNLOCKED (single-finding legacy path),
    # byte-identical to before. `approved` stays the single-host label (v1 batch
    # constraint + custody + response), derived when not explicitly declared.
    if scope:
        scope_policy = ScopePolicy.from_declaration(scope)
        approved = (approved_host or (next(iter(hosts)) if hosts else "")).lower()
        enforce_scope = True
    elif approved_host:
        approved = approved_host.lower()
        scope_policy = ScopePolicy.from_declaration([approved])
        enforce_scope = True
    else:
        approved = next(iter(hosts)) if hosts else ""
        # Implicit single-finding call == legacy path → keep scope unlocked to
        # preserve exact Step 6/7 behavior (zero regression). Implicit multi-
        # finding batches still get locked to their shared derived host.
        enforce_scope = len(jobs) > 1
        scope_policy = ScopePolicy.from_declaration([approved]) if enforce_scope else None
    # v1 single-host batch constraint: every finding must share the one approved host.
    out_of_scope = {h for h in hosts if h != approved}
    if out_of_scope:
        logger.error(
            f"[FUZZER · PARALLEL] Mixed-host batch rejected. Approved='{approved}', "
            f"out-of-scope={out_of_scope}. v1 enforces single-host batches."
        )
        return
    # Scope authorization, converged onto the one ScopePolicy: every finding host must be
    # within the declared scope. Host-level here; the _send_request chokepoint owns the
    # resolved-IP rebinding guard.
    if scope_policy is not None:
        unauthorized = {h for h in hosts if not scope_policy.netloc_allowed(h)}
        if unauthorized:
            logger.error(
                f"[FUZZER · PARALLEL] Out-of-scope batch rejected: hosts {unauthorized} are "
                f"outside the declared scope. Refusing to probe unauthorized hosts."
            )
            return

    # --- Phase 3: build ONE shared custody controller ---
    custody = AuthCustodyController(
        finding_id=jobs[0].finding_id,
        auth_refresh_request=auth_refresh_request or fallback_refresh,
        approved_host=(approved if enforce_scope else ""),
        scope_policy=(scope_policy if enforce_scope else None),
    )
    for job in jobs:
        _ACTIVE_CUSTODY[job.finding_id] = custody  # many ids → same controller

    result_queue: "asyncio.Queue" = asyncio.Queue()
    semaphore = asyncio.Semaphore(max(1, max_concurrency))
    # Unified-writer decision (Step 9): when the app-wide WriterService is up
    # (production / lifespan), forward results into it so flows + fuzz records
    # share ONE SQLite writer. When it isn't (standalone unit tests), fall back
    # to the original ephemeral per-batch consumer — preserving Step 8 behavior.
    if is_writer_running():
        writer_task = asyncio.create_task(
            _forward_results_to_writer(result_queue, get_writer_service())
        )
    else:
        writer_task = asyncio.create_task(_db_writer_consumer(result_queue))

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
                read=settings.FUZZER_HTTP_TIMEOUT_READ,
                write=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
                pool=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
            ),
            limits=httpx.Limits(
                max_connections=max(1, max_concurrency) * 2,
                max_keepalive_connections=max(1, max_concurrency),
            ),
            verify=False,  # Many pentest targets use self-signed certs
        ) as client:
            # --- Phase 4: baselines (concurrent, gated by the shared semaphore) ---
            async def _baseline_for(job: _FindingJob) -> None:
                async with semaphore:
                    job.baseline = await _compute_baseline(
                        client, job.parsed_request, job.base_url, custody=custody
                    )

            await asyncio.gather(*[_baseline_for(j) for j in jobs], return_exceptions=True)

            # --- Phase 5: fan out payload workers across ALL endpoints ---
            workers = []
            for job in jobs:
                if job.baseline is None:
                    logger.error(
                        f"[FUZZER · PARALLEL] Baseline failed for finding_id={job.finding_id}; "
                        f"skipping its {len(job.payloads)} payloads."
                    )
                    continue
                logger.info(
                    f"[FUZZER · PARALLEL] finding_id={job.finding_id} baseline ok "
                    f"(status={job.baseline['status_code']}); queueing {len(job.payloads)} payloads."
                )
                for idx, payload in enumerate(job.payloads):
                    workers.append(_execute_single_fuzz(
                        result_queue=result_queue,
                        client=client,
                        finding_id=job.finding_id,
                        payload_index=idx,
                        payload_instruction=payload,
                        parsed_request=job.parsed_request,
                        base_url=job.base_url,
                        baseline=job.baseline,
                        semaphore=semaphore,
                        custody=custody,
                    ))

            await asyncio.gather(*workers, return_exceptions=True)

    except Exception:
        logger.exception("[FUZZER · PARALLEL] Unexpected error during batch execution")
    finally:
        # --- Phase 6: stop the writer, drain remaining results, deregister ---
        await result_queue.put(_QUEUE_SENTINEL)
        try:
            await asyncio.wait_for(writer_task, timeout=30)
        except asyncio.TimeoutError:
            logger.error("[FUZZER · PARALLEL] DB writer did not drain in time; cancelling.")
            writer_task.cancel()
        for job in jobs:
            _ACTIVE_CUSTODY.pop(job.finding_id, None)
    logger.info(f"[FUZZER · PARALLEL] Batch complete for finding_ids={finding_ids}")

    # --- Phase 7 (SHADOW MODE, purely additive) ---------------------------------
    # Runs ONLY after the batch above is fully complete and its FuzzingRecords are
    # persisted. Gated behind settings.AI_DEEP_VERIFY_SHADOW (default False), so when
    # off this is an immediate no-op and the engine behaves byte-for-byte as before.
    # It is READ-ONLY: it observes "suspicious" records and logs an AI second
    # opinion without touching verification_status / diff_details / the writer path.
    # Any failure is logged and swallowed — it can never affect the batch result.
    await _run_shadow_deep_verification(jobs, custody, model=model)


# ==============================================================================
# 6b. Backward-compatible single-target entry point (Step 6/7)
# ==============================================================================

async def execute_differential_fuzzing(finding_id: int) -> None:
    """
    Thin wrapper over the Step 8 parallel engine with a batch of one.

    The approved host is derived implicitly (scope lock stays OFF for the legacy
    single-target path), and any cached re-auth request is harvested from the
    finding JSON — preserving the exact prior Step 6/7 behavior with zero regression.
    """
    await execute_parallel_fuzzing([finding_id])


# ==============================================================================
# 6c. Phase 7 — SHADOW-MODE AI-in-the-loop deep verification (read-only, additive)
# ==============================================================================
# This block is the FIRST integration cut (architecture option B), but it is
# strictly OBSERVATIONAL. It does not modify Phases 1–6, _execute_single_fuzz, or
# _differential_verdict — those stay byte-for-byte unchanged — and it never alters
# a persisted verdict. It runs after a completed batch, gated behind
# settings.AI_DEEP_VERIFY_SHADOW (default False), querying back this run's
# "suspicious" FuzzingRecords and asking the isolated deep verifier for a second
# opinion that is LOGGED ONLY. Everything here fails closed (logged + swallowed).


def _shadow_auth_context(
    custody: Optional["AuthCustodyController"], parsed_request: dict
) -> Dict[str, str]:
    """
    Auth seam for shadow mode. Prefer the live custody controller's currently-active
    credential (token/cookie); fall back to the auth header carried on the finding's
    own parsed_request. Returns headers to merge into the deep verifier's request.
    """
    if custody is not None and getattr(custody, "current_active_auth_value", ""):
        value = custody.current_active_auth_value
        if custody.auth_kind == "token":
            return {"Authorization": value if value.lower().startswith("bearer ") else f"Bearer {value}"}
        return {"Cookie": value}

    headers = (parsed_request or {}).get("headers", {}) or {}
    for k, v in headers.items():
        if k.lower() in ("authorization", "cookie", "x-token"):
            return {k: v}
    return {}


def _shadow_endpoint_catalog(
    parsed_request: dict, catalog_source: Optional[Dict[str, Any]] = None
) -> List[str]:
    """
    Endpoint-catalog seam for shadow mode.

    DEFAULT (catalog_source is None): BYTE-IDENTICAL to the original placeholder —
    the finding's own path plus an obvious GET read-back of the same resource path.
    This preserves zero-regression behavior whenever no real API surface is wired:
    when no source is provided, the discovery code path below is never touched.

    WHEN catalog_source IS EXPLICITLY PROVIDED (a descriptor consumed by
    endpoint_catalog.build_catalog, e.g. {"kind": "openapi", "spec": <openapi dict>}),
    the real discovered surface (D18) is used instead, MERGED with the placeholder so
    the finding's own path / same-resource read-back is ALWAYS still offered even if
    the spec happens to omit it. Any catalog-source error fails safe back to the
    placeholder — the shadow pass must never be weakened or broken by a bad source.
    """
    # --- Original placeholder (unchanged logic) ---
    path = (parsed_request or {}).get("path", "") or ""
    method = str((parsed_request or {}).get("method", "GET") or "GET").upper()
    placeholder: List[str] = []
    if path:
        placeholder.append(f"{method} {path}")
        if method != "GET":
            placeholder.append(f"GET {path}")  # obvious read-back of the same resource

    # --- Zero-regression gate: no source -> exactly today's behavior ---
    if not catalog_source:
        return placeholder

    # --- Real endpoint surface (explicitly provided; lazy import keeps the default
    #     path free of any new import-time dependency) ---
    try:
        from backend.app.services.endpoint_catalog import build_catalog
        real = build_catalog(catalog_source)
    except Exception as e:
        logger.warning(
            "[FUZZER · SHADOW] endpoint catalog source unusable (%s); "
            "falling back to placeholder.", e
        )
        return placeholder

    # Merge real surface with the placeholder, dedupe, and order deterministically
    # (by path, then method) so the verifier prompt stays reproducible.
    merged = set(real) | set(placeholder)
    return sorted(merged, key=lambda e: (e.partition(" ")[2], e.partition(" ")[0]))


def _resolve_openapi_catalog_source(spec_value: Any) -> Optional[Dict[str, Any]]:
    """Turn the AI_DEEP_VERIFY_OPENAPI_SPEC setting into a build_catalog descriptor (D21).

    The setting is normally a FILESYSTEM PATH (str) to an OpenAPI/Swagger JSON document,
    so it can be set from .env / the environment like the other AI_DEEP_VERIFY_* flags.
    For backward compatibility with in-process measurement drivers that inject an
    ALREADY-PARSED spec dict straight onto `settings`, a dict is also accepted verbatim.

    Returns a `{"kind": "openapi", "spec": <parsed dict>}` descriptor, or None when the
    setting is unset OR unusable. FAIL-SAFE: a missing file, a parse error, or a value of
    the wrong type logs a warning and returns None, so `_shadow_endpoint_catalog` falls
    back to its byte-identical placeholder — the shadow pass is never weakened or broken by
    a bad spec source (the same fail-safe posture `_shadow_endpoint_catalog` itself takes).

    JSON only: the repo declares no YAML dependency, so a YAML spec is intentionally not
    parsed here (adding it would rely on an undeclared, environment-incidental import).
    """
    if not spec_value:
        return None
    # Back-compat: an already-parsed spec dict (in-process measurement drivers).
    if isinstance(spec_value, dict):
        return {"kind": "openapi", "spec": spec_value}
    # Normal config: a filesystem path to an OpenAPI JSON document.
    if isinstance(spec_value, str):
        try:
            with open(spec_value, "r", encoding="utf-8") as fh:
                spec = json.load(fh)
        except Exception as e:
            logger.warning(
                "[FUZZER · SHADOW] AI_DEEP_VERIFY_OPENAPI_SPEC=%r is unusable (%s); "
                "falling back to the placeholder catalog.", spec_value, e,
            )
            return None
        if not isinstance(spec, dict):
            logger.warning(
                "[FUZZER · SHADOW] AI_DEEP_VERIFY_OPENAPI_SPEC=%r did not parse to a JSON "
                "object; falling back to the placeholder catalog.", spec_value,
            )
            return None
        return {"kind": "openapi", "spec": spec}
    # Any other type is a misconfiguration -> fail safe.
    logger.warning(
        "[FUZZER · SHADOW] AI_DEEP_VERIFY_OPENAPI_SPEC has unexpected type %s; "
        "falling back to the placeholder catalog.", type(spec_value).__name__,
    )
    return None


# ==============================================================================
# D19 — CONSERVATIVE VERDICT PROMOTION (shadow -> authoritative). Default OFF.
# The SINGLE choke point + the SINGLE writer. Structural invariant: a promoted
# 'verified' can ONLY be produced when _code_authorized_channel returns non-None;
# there is no other code path in Phase 7 that writes 'verified'.
# ==============================================================================
_OWNER_VIEW_PROMOTION_CHANNEL = "owner_view_corroborated"


def _code_authorized_channel(result) -> Optional[str]:
    """The D19 CHOKE POINT — pure, side-effect-free. Returns the deterministic channel that
    authorizes promoting a rule-oracle 'suspicious' to 'verified', or None if none does.

    A channel authorizes ONLY when the deep verifier's own verdict is 'verified' AND one of:
      * guard_override is one of the FOUR exemption channels (write-record readback, state
        readback, delete negative-assertion, mass-assignment state-jump), OR
      * owner_view_corroborated is True (the D24 read-semantic owner-view gate corroborated).
    The model's raw opinion ALONE never authorizes: a 'verified' with guard_override=None and
    owner_view_corroborated is not True (a same-path model-verified, or a read case where the owner
    gate was not configured) returns None here and is therefore NEVER promoted. This is the
    structural expression of D19's conservative-only invariant — no other path promotes.

    Attributes are read defensively via getattr so a partial/foreign result can never raise.
    """
    if getattr(result, "ai_verdict", None) != "verified":
        return None
    # Single source of truth for the four channel names: the constants exported by deep_verifier.
    # Imported lazily so this module keeps zero import-time dependency on the verifier when
    # shadow/promotion are off (the default); by the time this runs the verifier module is already
    # imported (the shadow runner imported it), so it is a cached lookup, not a reload.
    from backend.app.services.deep_verifier import (
        WRITE_RECORD_EXEMPTION_REASON,
        STATE_READBACK_EXEMPTION_REASON,
        DELETE_READBACK_EXEMPTION_REASON,
        STATE_JUMP_EXEMPTION_REASON,
    )
    override = getattr(result, "guard_override", None)
    if override in (
        WRITE_RECORD_EXEMPTION_REASON,
        STATE_READBACK_EXEMPTION_REASON,
        DELETE_READBACK_EXEMPTION_REASON,
        STATE_JUMP_EXEMPTION_REASON,
    ):
        return override
    if getattr(result, "owner_view_corroborated", None) is True:
        return _OWNER_VIEW_PROMOTION_CHANNEL
    return None


async def _promote_record_verified(record_id: str, channel: str, result) -> None:
    """The D19 SINGLE WRITER — promote ONE 'suspicious' FuzzingRecord to 'verified', persisting the
    authorizing evidence chain into diff_details (nullable JSON column, no schema change). Called
    ONLY for records _code_authorized_channel already authorized (channel is non-None). Opens its
    own write session — safe because Phase 7 runs after the batch WriterService has drained (sole
    writer here). NEVER raises: any failure is logged and swallowed so the rule verdict stands.

    Additive by construction: the ONLY mutation it can make is suspicious -> verified, and only
    under an authorizer. It re-reads the row and re-checks 'suspicious' first, so it can never
    override the rule oracle's own 'verified'/'failed', and it never downgrades anything.
    """
    try:
        async with async_session_factory() as db:
            rec = (await db.execute(
                select(FuzzingRecord).where(FuzzingRecord.id == record_id)
            )).scalar_one_or_none()
            if rec is None:
                return
            if rec.verification_status != "suspicious":
                logger.info(
                    "[FUZZER · PROMOTE] record=%s finding_id=%s is %r (not 'suspicious') — leaving "
                    "the rule verdict; D19 only ever promotes within the suspicious band.",
                    record_id, getattr(rec, "finding_id", "?"), rec.verification_status,
                )
                return
            prior = rec.diff_details
            base = dict(prior) if isinstance(prior, dict) else (
                {} if prior is None else {"_rule_oracle_diff": prior}
            )
            # Preserve the rule-oracle diff already present; nest the promotion audit under its
            # own key so the full chain is reconstructable from the record alone.
            base["ai_promotion"] = {
                "promoted_from": "suspicious",
                "promoted_to": "verified",
                "authorizing_channel": channel,
                "ai_verdict": getattr(result, "ai_verdict", None),
                "ai_verdict_raw": getattr(result, "ai_verdict_raw", None),
                "guard_override": getattr(result, "guard_override", None),
                "owner_view_corroborated": getattr(result, "owner_view_corroborated", None),
                "anchoring_result": getattr(result, "anchoring_result", None),
                "caller_identity_anchor": getattr(result, "caller_identity_anchor", None),
                "payload_causality_anchor": getattr(result, "payload_causality_anchor", None),
                "negative_assertion_anchor": getattr(result, "negative_assertion_anchor", None),
                "state_jump_anchor": getattr(result, "state_jump_anchor", None),
                "ai_confidence": getattr(result, "ai_confidence", None),
                "model": getattr(result, "model", None),
                "promoted_at": utcnow().isoformat(),
            }
            rec.verification_status = "verified"
            rec.diff_details = base   # full reassignment marks the JSON column dirty
            await db.commit()
            logger.info(
                "[FUZZER · PROMOTE] record=%s finding_id=%s promoted suspicious->verified via "
                "channel=%r (ai_verdict_raw=%r owner_view_corroborated=%r).",
                record_id, rec.finding_id, channel,
                getattr(result, "ai_verdict_raw", None),
                getattr(result, "owner_view_corroborated", None),
            )
    except Exception as e:
        logger.warning(
            "[FUZZER · PROMOTE] promotion write failed for record=%s (swallowed; rule verdict "
            "stands): %s", record_id, e,
        )


async def _run_shadow_deep_verification(
    jobs: List["_FindingJob"], custody: Optional["AuthCustodyController"],
    model: Optional[str] = None,
) -> None:
    """
    Phase 7 shadow runner (read-only). For each "suspicious" FuzzingRecord produced
    by this batch, re-run the isolated execute_deep_verification against the same
    target and LOG the AI's verdict alongside the rule verdict. Never overwrites the
    record, never changes what the user sees, and NEVER raises.
    """
    # Hard gate: when off, this is an immediate no-op (byte-identical behavior).
    if not settings.AI_DEEP_VERIFY_SHADOW:
        return

    try:
        # Imported lazily so the module has zero new import-time dependencies when
        # shadow mode is off (the default).
        from backend.app.services.deep_verifier import (
            execute_deep_verification,
            OwnerCredential,
        )

        job_by_id = {job.finding_id: job for job in (jobs or [])}
        finding_ids = list(job_by_id.keys())
        if not finding_ids:
            return

        # Query back THIS run's suspicious records (read-only session).
        async with async_session_factory() as db:
            rows = (await db.execute(
                select(FuzzingRecord).where(
                    FuzzingRecord.finding_id.in_(finding_ids),
                    FuzzingRecord.verification_status == "suspicious",
                )
            )).scalars().all()

        if not rows:
            logger.info("[FUZZER · SHADOW] No 'suspicious' records to shadow-verify.")
            return

        logger.info(f"[FUZZER · SHADOW] Shadow-verifying {len(rows)} suspicious record(s) (read-only).")

        # Optional settings-pointed spec source (D18/D21). Absent by default ->
        # catalog_source stays None -> _shadow_endpoint_catalog returns the byte-identical
        # placeholder (zero regression). When set (a path to an OpenAPI JSON file, or an
        # in-process spec dict), the resolver hands the real endpoint surface to the
        # verifier; any bad value fails safe back to the placeholder. Live fetch is
        # intentionally not performed here.
        catalog_source = _resolve_openapi_catalog_source(settings.AI_DEEP_VERIFY_OPENAPI_SPEC)

        # Two-account ownership baseline: the OWNER/VICTIM credential, resolved here so the
        # second identity reaches the REAL Phase-7 pipeline and not just a measurement
        # harness. Absent by default -> None -> byte-identical behavior. It is passed
        # through only; nothing consumes it yet (the D24 read-semantic gate is a separate
        # milestone), and it is NEVER used for an attack request.
        owner_credential = OwnerCredential.from_config(reveal_secret(settings.AI_DEEP_VERIFY_OWNER_AUTH))
        # D30: the THIRD/BYSTANDER credential for public-resource discrimination. Resolved the same
        # way, absent by default -> None -> byte-identical (no bystander probe). Passed through only;
        # consumed solely by the D24 read-semantic branch's suppress-only public-check. It is
        # DOWNGRADE-ONLY (can only turn a would-be 'verified' into 'inconclusive') and NEVER used
        # for an attack request. The D19 promotion logic below is unchanged.
        bystander_credential = OwnerCredential.from_config(reveal_secret(settings.AI_DEEP_VERIFY_BYSTANDER_AUTH))

        for rec in rows:
            # Each record is independent; one failure must not stop the others.
            try:
                job = job_by_id.get(rec.finding_id)
                if job is None:
                    continue
                payloads = job.payloads or []
                payload = (
                    payloads[rec.payload_index]
                    if 0 <= rec.payload_index < len(payloads) else None
                )

                result = await execute_deep_verification(
                    parsed_request=job.parsed_request,
                    payload=payload,
                    base_url=job.base_url,
                    approved_host=(custody.approved_host or None) if custody is not None else None,
                    auth_context=_shadow_auth_context(custody, job.parsed_request),
                    available_endpoints=_shadow_endpoint_catalog(job.parsed_request, catalog_source),
                    owner_credential=owner_credential,
                    bystander_credential=bystander_credential,
                    model_name=model,
                )

                logger.info(
                    "[FUZZER · SHADOW] finding_id=%s payload#%s | rule_verdict=suspicious | "
                    "AI_shadow_verdict=%s (status=%s, confidence=%s, follow_up=%s) | "
                    "NOT applied (shadow, observe-only).",
                    rec.finding_id, rec.payload_index, result.ai_verdict, result.status,
                    result.ai_confidence, result.ai_requested_follow_up,
                )

                # ---- D19: conservative promotion (default OFF; the shadow log above always
                #      runs). Promotion is a SEPARATE, opt-in write that fires ONLY when the flag
                #      is on AND the code choke point authorizes it. A model 'verified' with no
                #      deterministic authorizer returns None here and is NEVER promoted — the
                #      record keeps its 'suspicious' rule verdict untouched. ----
                if settings.AI_DEEP_VERIFY_PROMOTE:
                    _channel = _code_authorized_channel(result)
                    if _channel is not None:
                        await _promote_record_verified(rec.id, _channel, result)
                    else:
                        logger.info(
                            "[FUZZER · PROMOTE] finding_id=%s payload#%s | AI_verdict=%s but NO "
                            "deterministic authorizer -> NOT promoted ('suspicious' stands).",
                            rec.finding_id, rec.payload_index, result.ai_verdict,
                        )
            except Exception as e:
                logger.warning(
                    "[FUZZER · SHADOW] Shadow deep-verify failed for finding_id=%s payload#%s: %s",
                    getattr(rec, "finding_id", "?"), getattr(rec, "payload_index", "?"), e,
                )
    except Exception as e:
        # Shadow mode must NEVER affect the main batch — swallow everything.
        logger.warning(f"[FUZZER · SHADOW] Shadow pass aborted (swallowed): {e}")


async def dry_run_auth_refresh(auth_refresh_request: dict, approved_host: str = "") -> dict:
    """
    Step 8 Objective A: execute a candidate re-auth request ONCE (scope-locked)
    and report whether a usable credential could be extracted. Powers the
    'Identity Provider Anchor' dry-run button. Never persists anything.
    """
    req = auth_refresh_request or {}
    url = req.get("url", "")
    if not url:
        return {"success": False, "message": "No URL provided in the refresh request."}
    scope_policy = ScopePolicy.from_declaration([approved_host]) if approved_host else None
    if scope_policy is not None and not scope_policy.netloc_allowed(_host_of(url)):
        return {
            "success": False,
            "message": (
                f"Refusing out-of-scope dry-run: host '{_host_of(url)}' is not the "
                f"approved target '{approved_host.lower()}'."
            ),
        }

    method = str(req.get("method", "POST")).upper()
    headers = req.get("headers", {}) or {}
    body = req.get("body")
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
                read=settings.FUZZER_HTTP_TIMEOUT_READ,
                write=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
                pool=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
            ),
            verify=False,
        ) as client:
            kwargs: Dict[str, Any] = {
                "method": method, "url": url, "headers": headers, "follow_redirects": True,
            }
            if body is not None and method in ("POST", "PUT", "PATCH", "DELETE"):
                if isinstance(body, dict):
                    kwargs["json"] = body
                else:
                    kwargs["content"] = str(body)
            resp = await client.request(**kwargs)

        value, kind = _extract_new_auth_value(resp)
        if value:
            preview = (value[:12] + "…") if len(value) > 12 else value
            return {
                "success": True,
                "status_code": resp.status_code,
                "extracted_kind": kind,
                "extracted_preview": preview,
                "message": f"Extracted a fresh {kind} successfully.",
            }
        return {
            "success": False,
            "status_code": resp.status_code,
            "message": "Request completed but no access_token/token/Set-Cookie could be extracted.",
        }
    except Exception as e:
        return {"success": False, "message": f"Dry-run failed: {str(e)[:200]}"}


def _extract_payloads(finding: VulnerabilityFinding) -> List[dict]:
    """
    Resolves the automation_payloads for a finding.

    Step D resolution order:
        1. The explicit ``automation_payloads`` JSON column (Hunter findings).
        2. LEGACY fallback: a JSON string embedded in ai_patch / poc_request
           (the pre-Step-D convention) — preserved for backward compatibility.
    """
    # --- Step D: explicit typed column takes precedence ---
    column_payloads = getattr(finding, "automation_payloads", None)
    if isinstance(column_payloads, list) and column_payloads:
        return column_payloads
    if isinstance(column_payloads, dict) and column_payloads.get("automation_payloads"):
        return column_payloads["automation_payloads"]

    # --- LEGACY fallback: JSON embedded in text columns ---
    for field_value in [finding.ai_patch, finding.poc_request]:
        if not field_value:
            continue
        try:
            data = json.loads(field_value)
            if isinstance(data, dict) and "automation_payloads" in data:
                return data["automation_payloads"]
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, TypeError):
            continue
    return []


def _extract_parsed_request(finding: VulnerabilityFinding) -> dict:
    """
    Resolves the parsed HTTP request structure for a finding.

    Step D resolution order:
        1. The explicit ``parsed_request`` JSON column (Hunter findings).
        2. LEGACY fallback: JSON embedded in poc_request / ai_patch.
        3. Last resort: a minimal GET request derived from matched_at.
    """
    # --- Step D: explicit typed column takes precedence ---
    column_parsed = getattr(finding, "parsed_request", None)
    if isinstance(column_parsed, dict) and column_parsed:
        # Support both a wrapped {"parsed_data": {...}} and a bare request dict.
        if isinstance(column_parsed.get("parsed_data"), dict):
            return column_parsed["parsed_data"]
        if "method" in column_parsed:
            return column_parsed

    # --- LEGACY fallback: JSON embedded in text columns ---
    for field_value in [finding.poc_request, finding.ai_patch]:
        if not field_value:
            continue
        try:
            data = json.loads(field_value)
            if isinstance(data, dict) and "parsed_data" in data:
                return data["parsed_data"]
            if isinstance(data, dict) and "method" in data:
                return data
        except (json.JSONDecodeError, TypeError):
            continue

    # Fallback: construct minimal GET request from matched_at
    matched_at = finding.matched_at or ""
    parsed = urlparse(matched_at)
    return {
        "method": "GET",
        "path": parsed.path or "/",
        "query_params": {},
        "headers": {"Host": parsed.netloc} if parsed.netloc else {},
        "body": None,
    }


async def _compute_baseline(
    client: httpx.AsyncClient,
    parsed_request: dict,
    base_url: str,
    custody: Optional["AuthCustodyController"] = None,
) -> Optional[Dict[str, Any]]:
    """
    Sends 2 baseline requests and averages the metrics.
    Returns None if both requests fail.
    """
    results = []
    for attempt in range(2):
        try:
            r = await _send_request(client, parsed_request, base_url, custody=custody)
            results.append(r)
        except Exception as e:
            logger.warning(f"[FUZZER · BASELINE] Attempt {attempt + 1} failed: {e}")

    if not results:
        return None

    avg_len = sum(r["content_length"] for r in results) // len(results)
    avg_elapsed = round(sum(r["elapsed_ms"] for r in results) / len(results), 2)

    return {
        "status_code": results[0]["status_code"],
        "content_length": avg_len,
        "response_body": results[0]["response_body"],
        "elapsed_ms": avg_elapsed,
        "url": results[0]["url"],
    }


async def _execute_single_fuzz(
    result_queue: "asyncio.Queue",
    client: httpx.AsyncClient,
    finding_id: int,
    payload_index: int,
    payload_instruction: dict,
    parsed_request: dict,
    base_url: str,
    baseline: Dict[str, Any],
    semaphore: asyncio.Semaphore,
    custody: Optional["AuthCustodyController"] = None,
) -> None:
    """
    Executes a single fuzz cycle: mutate → send → diff → enqueue result.

    Step 8 Single-Writer Consumer: this worker performs ONLY network I/O and
    pure computation. It NEVER touches the database — every result is handed to
    `result_queue`, drained by the lone `_db_writer_consumer`. This is what makes
    true parallelism safe under SQLite (no concurrent writers, no shared session).

    Section 7.2: after each send, runs heuristic auth-death detection. On
    detection it clears the barrier, fires a single-flight re-auth, then either
    replays this payload with the refreshed credential or fails it fast.
    """
    record_id = str(uuid.uuid4())

    def _item(received: str, status: str, diff: dict, sent: str) -> dict:
        return {
            "record_id": record_id,
            "finding_id": finding_id,
            "payload_index": payload_index,
            "sent_request": sent,
            "received_response": received,
            "verification_status": status,
            "diff_details": diff,
        }

    async with semaphore:
        try:
            # 1. Mutate (deep-copied internally — no shared-state race)
            mutated = await mutate_request(parsed_request, payload_instruction)
            sent_log = _serialize_request_for_log(mutated, base_url)

            # 2. Send
            try:
                test_result = await _send_request(client, mutated, base_url, custody=custody)
            except ScopeViolationError as sve:
                # Constraint 2: refused an out-of-scope dispatch — fail this payload.
                logger.warning(f"[FUZZER · SCOPE] Payload #{payload_index} blocked: {sve}")
                await result_queue.put(_item(
                    f"SCOPE_VIOLATION: {str(sve)[:200]}", "failed",
                    {"error": "scope_violation", "analysis_notes": str(sve)[:200]}, sent_log,
                ))
                return
            except httpx.TimeoutException:
                logger.warning(f"[FUZZER] Payload #{payload_index} timed out.")
                await result_queue.put(_item(
                    "TIMEOUT: Request timed out", "failed",
                    {"error": "timeout", "analysis_notes": "Target did not respond in time"}, sent_log,
                ))
                return
            except httpx.ConnectError as ce:
                logger.warning(f"[FUZZER] Payload #{payload_index} connection refused: {ce}")
                await result_queue.put(_item(
                    f"CONNECTION_ERROR: {str(ce)[:200]}", "failed",
                    {"error": "connection_refused", "analysis_notes": str(ce)[:200]}, sent_log,
                ))
                return

            # 2b. Section 7.2: heuristic auth-death detection & recovery
            if custody is not None and _is_auth_death(
                test_result["status_code"], test_result["response_body"]
            ):
                logger.warning(
                    f"[CUSTODY · {finding_id}] Auth death detected on payload "
                    f"#{payload_index} (status={test_result['status_code']}). "
                    f"Clearing barrier and dispatching single-flight re-auth."
                )
                # Section 7.2.2: block all other concurrent workers at the barrier
                custody.session_valid_event.clear()
                # Single-flight guarded; finally-block always re-opens the gate
                await custody._refresh_session_and_resume()

                if custody.refresh_failed:
                    # Circuit breaker tripped — fail this payload fast.
                    # The gate is already re-opened, so siblings exit gracefully.
                    await result_queue.put(_item(
                        custody.last_diagnostic or "RE-AUTH FAILED", "failed",
                        {"error": "reauth_failed", "analysis_notes": custody.last_diagnostic}, sent_log,
                    ))
                    return

                # Resume: replay this payload ONCE with the refreshed credential.
                try:
                    test_result = await _send_request(client, mutated, base_url, custody=custody)
                except ScopeViolationError as sve:
                    await result_queue.put(_item(
                        f"SCOPE_VIOLATION after re-auth: {str(sve)[:200]}", "failed",
                        {"error": "scope_violation", "analysis_notes": str(sve)[:200]}, sent_log,
                    ))
                    return
                except httpx.TimeoutException:
                    await result_queue.put(_item(
                        "TIMEOUT after re-auth", "failed",
                        {"error": "timeout", "analysis_notes": "Timed out after session refresh"}, sent_log,
                    ))
                    return
                except httpx.ConnectError as ce:
                    await result_queue.put(_item(
                        f"CONNECTION_ERROR after re-auth: {str(ce)[:200]}", "failed",
                        {"error": "connection_refused", "analysis_notes": str(ce)[:200]}, sent_log,
                    ))
                    return

            # 3. Differential analysis
            diff = _differential_verdict(baseline, test_result, payload_instruction)

            # 4. Enqueue result for the single DB writer
            response_log = (
                f"HTTP {test_result['status_code']}\n"
                f"Content-Length: {test_result['content_length']}\n"
                f"Elapsed: {test_result['elapsed_ms']}ms\n\n"
                f"{test_result['response_body'][:_RECORD_RESPONSE_LOG_MAX_LENGTH]}"
            )
            await result_queue.put(_item(response_log, diff["verdict"], diff, sent_log))

            logger.info(
                f"[FUZZER] Payload #{payload_index} [{payload_instruction.get('type', '?')}] "
                f"-> verdict={diff['verdict']} | deviation={diff['length_deviation_ratio']:.2%} "
                f"| similarity={diff.get('similarity_ratio', 0):.2%}"
            )

        except Exception as e:
            logger.error(f"[FUZZER] Error on payload #{payload_index}: {e}")
            try:
                await result_queue.put(_item(
                    str(e)[:500], "failed",
                    {"error": "exception", "analysis_notes": str(e)[:200]}, "ERROR",
                ))
            except Exception:
                logger.exception("[FUZZER] Failed to enqueue error record")

    # Jittered cooldown OUTSIDE semaphore to simulate human pacing and evade WAF triggers
    await asyncio.sleep(random.uniform(0.2, 0.5))


def _persist_record(
    db: AsyncSession,
    record_id: str,
    finding_id: int,
    payload_index: int,
    sent_request: str,
    received_response: str,
    verification_status: str,
    diff_details: dict,
) -> None:
    """Helper to create and add a FuzzingRecord to the session."""
    record = FuzzingRecord(
        id=record_id,
        finding_id=finding_id,
        payload_index=payload_index,
        sent_request=sent_request,
        received_response=received_response,
        verification_status=verification_status,
        diff_details=diff_details,
        created_at=utcnow(),
    )
    db.add(record)
