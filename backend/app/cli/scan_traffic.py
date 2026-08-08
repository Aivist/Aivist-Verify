# ==============================================================================
# scan — LIGHT passive endpoint discovery from a CAPTURED-TRAFFIC FILE (HAR or raw-HTTP dump).
#
# The CONNECTOR that lets `scan` discover a spec-less target's attack surface from traffic the operator
# already proxied (mitmproxy / Burp / a browser HAR): it reads a capture, keeps ONLY the requests that
# hit THIS target, folds their concrete paths back to {id} templates, and emits the SAME "METHOD /path"
# endpoints list scan's existing endpoints path already consumes. It is pure WIRING over three existing
# pieces — traffic_parser (parse one request), endpoint_catalog.templatize_endpoints (concrete -> {id}),
# and scan_run's endpoints input — and touches NO verdict / engine logic. It only PRODUCES candidates
# for the existing judge, so a mis-templatized path is judged / SKIPPED, never a false positive.
#
# SCOPE RED LINE (welded): a captured request whose host is NOT the target's origin is DROPPED here,
# BEFORE it can ever become a candidate. An operator's HAR routinely carries off-target traffic
# (analytics, CDNs, third parties, other tabs); none of it may leak into a scan. The host match reuses
# the ONE audited ScopePolicy — the same matcher the engine locks every active request to — so passive
# discovery and active confirmation can never disagree on what "in scope" means.
#
# SECRETS: only (method, host, path) is read from each flow. Auth headers, cookies and request bodies
# are NEVER extracted, so nothing secret is carried into the catalog or persisted. (Any downstream
# render still passes through confirm_render's credential redactor, belt-and-suspenders.)
# ==============================================================================
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

from backend.app.services.traffic_parser import parse_raw_http_request
from backend.app.services.endpoint_catalog import templatize_endpoints
from backend.app.services.scope import ScopePolicy
from backend.app.cli.external_verify import _approved_host

logger = logging.getLogger("app.cli.scan_traffic")

_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE")
# A request line starts a new raw-HTTP flow: 'METHOD /path ...' or 'METHOD http://host/path ...'.
_REQ_LINE_RE = re.compile(r"^(?:%s)\s+(?:/|https?://)\S*" % "|".join(_HTTP_METHODS), re.IGNORECASE)


class TrafficFileError(ValueError):
    """A malformed / unreadable / empty traffic file. Raised so the caller can render a clear
    '[NOT DATA] could not read the traffic file' message instead of crashing. NOTE: a file that reads
    fine but yields 0 IN-SCOPE flows is NOT this error — it returns [] (the honest-empty path)."""


def _host_header(headers: Dict[str, str]) -> str:
    """The Host header value (case-insensitive), or '' if none was captured."""
    for k, v in (headers or {}).items():
        if str(k).lower() == "host":
            return str(v).strip()
    return ""


def _split_raw_http_flows(text: str) -> List[str]:
    """Split a multi-request raw-HTTP dump into per-request blocks (each parseable by
    parse_raw_http_request). A new block starts at every line that looks like an HTTP request line;
    any preamble before the first request line is ignored. Blank lines inside a block (the
    header/body separator) are preserved."""
    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    blocks: List[str] = []
    cur: List[str] = []
    for line in norm.split("\n"):
        if _REQ_LINE_RE.match(line.strip()):
            if cur:
                blocks.append("\n".join(cur))
            cur = [line]
        elif cur:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur))
    return [b for b in blocks if b.strip()]


def _flows_from_raw(text: str) -> List[Tuple[str, str, str]]:
    """(method, host, path) per request in a raw-HTTP dump. host comes from the Host header; a flow
    with no Host header is DROPPED — without a host we cannot prove it is in scope, so we fail closed."""
    out: List[Tuple[str, str, str]] = []
    for block in _split_raw_http_flows(text):
        parsed = parse_raw_http_request(block)
        method = str(parsed.get("method") or "").upper().strip()
        path = str(parsed.get("path") or "")
        host = _host_header(parsed.get("headers") or {})
        if method in ("", "UNKNOWN") or not path.startswith("/") or not host:
            continue
        out.append((method, host, path))
    return out


def _flows_from_har(data: Any) -> List[Tuple[str, str, str]]:
    """(method, netloc, path) per entry of a HAR 1.2 document ({"log": {"entries": [...]}} or a flat
    {"entries": [...]}). A JSON that is not a HAR (no entries array) yields [] — the honest-empty path,
    not an error."""
    log = data.get("log", data) if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        return []
    out: List[Tuple[str, str, str]] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        req = e.get("request") or {}
        method = str(req.get("method") or "").upper().strip()
        url = str(req.get("url") or "").strip()
        if not method or not url:
            continue
        parts = urlsplit(url)
        netloc = parts.netloc
        if "@" in netloc:                              # strip any userinfo (user:pass@host)
            netloc = netloc.rsplit("@", 1)[1]
        path = parts.path or "/"
        out.append((method, netloc, path))
    return out


def endpoints_from_traffic_file(path: str, base_url: str) -> List[str]:
    """Read a captured-traffic FILE (HAR or raw-HTTP dump) and return the {id}-templated "METHOD /path"
    endpoints list scan consumes — keeping ONLY requests to the target's origin.

    Raises TrafficFileError on an unreadable / empty / malformed-JSON file (the caller turns it into a
    clear '[NOT DATA] could not read the traffic file' message). A file that reads fine but contains 0
    in-scope requests returns [] (the caller renders the honest-empty message, never a row of zeros).
    Only (method, host, path) is read from each flow — never auth headers / cookies / bodies."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as ex:
        raise TrafficFileError(f"could not read the traffic file: {ex}") from ex
    if not text or not text.strip():
        raise TrafficFileError("the traffic file is empty")

    if text.lstrip()[:1] in "{[":                      # JSON/HAR export
        try:
            data = json.loads(text)
        except json.JSONDecodeError as ex:
            raise TrafficFileError(
                f"the traffic file looks like JSON/HAR but did not parse: {ex}") from ex
        flows = _flows_from_har(data)
    else:                                              # raw-HTTP dump
        flows = _flows_from_raw(text)

    approved = _approved_host(base_url)
    if not approved:
        raise TrafficFileError(f"could not determine the target origin from base_url {base_url!r}")
    policy = ScopePolicy.from_declaration([approved])  # the ONE audited matcher, LOCKED to the target

    in_scope: List[str] = []
    off_target = 0
    for method, netloc, p in flows:
        if policy.netloc_allowed(netloc):
            in_scope.append(f"{method} {p.split('?', 1)[0]}")   # query stripped; templatize the path
        else:
            off_target += 1
    if off_target:
        logger.info("[SCAN·TRAFFIC] dropped %d off-target flow(s) not matching %s", off_target, approved)

    return templatize_endpoints(in_scope)              # concrete -> {id}, de-duplicated + normalized
