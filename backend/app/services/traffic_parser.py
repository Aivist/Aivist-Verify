# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Raw HTTP Traffic Parser — Structured Request Decomposition Engine
# ==============================================================================

import json
import logging
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("app.services.traffic_parser")

# Headers worth preserving for security analysis (lowercased for comparison).
# All others are stripped to save LLM token costs.
_SECURITY_RELEVANT_HEADERS = frozenset({
    "cookie",
    "authorization",
    "content-type",
    "referer",
    "origin",
    "x-forwarded-for",
    "x-real-ip",
    "x-csrf-token",
    "x-xsrf-token",
    "x-requested-with",
    "x-api-key",
    "x-auth-token",
    "host",
    "content-length",
})


def parse_raw_http_request(raw_text: str) -> Dict[str, Any]:
    """
    Parses a raw HTTP request string (as pasted by the user) into a structured
    dictionary suitable for LLM consumption.

    Extraction pipeline:
        1. Split on first blank line → head section / body section.
        2. Parse the request line → method, path, query_params.
        3. Parse headers → filtered dict (security-relevant only).
        4. Parse body → JSON dict if Content-Type is application/json, else raw text.

    Robustness:
        - Never raises; returns a best-effort dict with an ``errors`` list.
        - Handles \\r\\n, \\n, and mixed line endings.
        - Gracefully degrades on malformed input.

    :param raw_text: The raw HTTP request as a single multi-line string.
    :return: A dict with keys: method, path, query_params, headers, body, errors.
    """
    result: Dict[str, Any] = {
        "method": "UNKNOWN",
        "path": "/",
        "query_params": {},
        "headers": {},
        "body": None,
        "errors": [],
    }

    if not raw_text or not raw_text.strip():
        result["errors"].append("Empty or blank raw traffic input received.")
        return result

    try:
        # ------------------------------------------------------------------ #
        # Step 1: Normalise line endings and split head / body
        # ------------------------------------------------------------------ #
        normalised = raw_text.replace("\r\n", "\n").replace("\r", "\n")

        # First blank line separates headers from body
        if "\n\n" in normalised:
            head_section, body_section = normalised.split("\n\n", 1)
        else:
            head_section = normalised
            body_section = ""

        head_lines: List[str] = head_section.strip().split("\n")

        if not head_lines:
            result["errors"].append("No request line found in head section.")
            return result

        # ------------------------------------------------------------------ #
        # Step 2: Parse the request line (first line)
        # ------------------------------------------------------------------ #
        request_line = head_lines[0].strip()
        _parse_request_line(request_line, result)

        # ------------------------------------------------------------------ #
        # Step 3: Parse headers (remaining head lines)
        # ------------------------------------------------------------------ #
        raw_headers: Dict[str, str] = {}
        for line in head_lines[1:]:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                result["errors"].append(f"Malformed header line skipped: '{line[:80]}'")
                continue
            key, _, value = line.partition(":")
            raw_headers[key.strip()] = value.strip()

        # Filter to security-relevant headers only
        for key, value in raw_headers.items():
            if key.lower() in _SECURITY_RELEVANT_HEADERS:
                result["headers"][key] = value

        # ------------------------------------------------------------------ #
        # Step 4: Parse the body
        # ------------------------------------------------------------------ #
        body_text = body_section.strip() if body_section else ""
        if body_text:
            content_type = raw_headers.get("Content-Type", raw_headers.get("content-type", ""))
            if "application/json" in content_type.lower():
                try:
                    result["body"] = json.loads(body_text)
                except json.JSONDecodeError as je:
                    result["body"] = body_text
                    result["errors"].append(f"Body declared as JSON but failed to parse: {str(je)[:120]}")
            else:
                result["body"] = body_text

    except Exception as e:
        logger.error(f"[TRAFFIC PARSER] Unexpected error during request parsing: {e}")
        result["errors"].append(f"Unexpected parsing error: {str(e)[:200]}")

    return result


def _parse_request_line(request_line: str, result: Dict[str, Any]) -> None:
    """
    Extracts method, path, and query_params from the HTTP request line.
    Example input: ``POST /api/v1/user/update?id=123 HTTP/1.1``
    """
    parts = request_line.split()
    if len(parts) < 2:
        result["errors"].append(f"Request line has fewer than 2 tokens: '{request_line[:120]}'")
        # Still try to extract method
        if parts:
            result["method"] = parts[0].upper()
        return

    result["method"] = parts[0].upper()
    full_uri = parts[1]

    try:
        parsed = urlparse(full_uri)
        result["path"] = parsed.path or "/"
        qs = parse_qs(parsed.query, keep_blank_values=True)
        # parse_qs returns lists; flatten single-value lists for cleaner LLM input
        result["query_params"] = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
    except Exception as e:
        result["path"] = full_uri
        result["errors"].append(f"Failed to parse URI query string: {str(e)[:120]}")
