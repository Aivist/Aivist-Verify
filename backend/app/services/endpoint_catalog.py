# ==============================================================================
# Endpoint / attack-surface catalog  (D18 — real endpoint discovery, Step 1)
# ==============================================================================
#
# A small, PURE, offline module that turns a real API-surface description into the
# normalized `["METHOD /path  [tags: ...; operationId: ...]", ...]` list that the
# deep verifier already consumes as `available_endpoints` (see
# deep_verifier._build_turn1_prompt). It exists to replace the fuzzer's
# `_shadow_endpoint_catalog` placeholder — which only ever offers the finding's own
# path + a same-resource GET — with a catalog derived from a genuine source of truth
# (an OpenAPI/Swagger doc today; HAR / proxy-capture inventory later via the same
# interface).
#
# B-1 STEP 1 (this change): the builder no longer DISCARDS the operation's semantic
# metadata. Each entry still LEADS with "METHOD /path" (so path/method extraction by
# prefix is unchanged), then carries the GENUINE, pre-existing OpenAPI semantics the
# operation already declares — its `tags` and `operationId` — so the model can reason
# about what an endpoint IS (e.g. that "GET /api/audit-log [tags: audit]" is a record
# of writes) when choosing its one follow-up read-back. We INVENT NOTHING: only fields
# literally present in the supplied spec are surfaced, verbatim.
#
#   NOT surfaced (deliberate, Step 1): the operation `summary`. FastAPI auto-derives a
#   title-cased summary from the function name (e.g. "Get Audit Log") and it IS present
#   in app.openapi(), but it carries no signal beyond `operationId`/the path and the
#   target maintainer's note treats it as absent — so to stay well clear of the "author
#   a hint" (Fix-A) line we keep to the explicitly-sanctioned set {tags, operationId}.
#   `description` is genuinely absent (no docstrings on the routes) so there is nothing
#   to surface there either. No summary/description/docstring is ever AUTHORED here or
#   in the target; that would be forbidden answer-key §6 "Fix-A" cheating.
#
# DESIGN CONTRACT (kept deliberately narrow):
#   * NO network, NO disk, NO settings, NO fuzzer import at module load or call.
#     Callers parse/fetch the source themselves and hand this module a plain dict
#     (a later step decides how a spec reaches a run: explicit pass for the module,
#     settings-pointed for integration, live fetch optional).
#   * Pure functions only: same input -> same output, fully offline-testable.
#   * Output is normalized and stable: each entry LEADS with "METHOD /path", METHOD
#     uppercased, path verbatim (OpenAPI templated form, e.g.
#     "/api/users/{user_id}/profile"), optionally followed by a genuine-metadata
#     annotation; entries are de-duplicated and sorted (by path, then method) for
#     deterministic prompts.
#
# This module does NOT decide WHICH endpoint the verifier should request; it only
# supplies the honest list of what exists (now with what each thing IS). Selection
# stays with the model.
# ==============================================================================

import re
from typing import Any, Dict, List, Optional

# The operation keys an OpenAPI 3.x / Swagger 2.0 Path Item Object may carry. Any
# other key under a path (e.g. "parameters", "summary", "description", "servers",
# "$ref") is metadata, NOT an HTTP operation, and must be ignored.
_OPENAPI_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)

# Supported source kinds for the pluggable dispatcher.
SOURCE_OPENAPI = "openapi"
SOURCE_HAR = "har"


def _normalize(entries: List[str]) -> List[str]:
    """De-duplicate and deterministically sort catalog entries.

    Each entry LEADS with "METHOD /path" (an optional "  [..]" annotation may follow).
    Sort key is (path, method) — derived from the leading "METHOD /path" token, with the
    annotation stripped — so endpoints sharing a path group together and the output is
    stable across runs (important: the catalog is fed into an LLM prompt, and a stable
    order keeps that prompt reproducible).
    """
    unique = set(entries)

    def _key(item: str):
        method, _, rest = item.partition(" ")
        # rest is "/path" or "/path  [annotation]"; sort on the bare path only.
        path = rest.split("  [", 1)[0]
        return (path, method)

    return sorted(unique, key=_key)


def _format_entry(method: str, path: str, operation: Dict[str, Any]) -> str:
    """Render one catalog entry: "METHOD /path" optionally followed by a genuine-
    metadata annotation built ONLY from fields the operation actually declares.

    Surfaced (verbatim, when present): `tags`, `operationId`. These are pre-existing
    OpenAPI fields — nothing is invented or authored. When neither is present the entry
    is the bare "METHOD /path" (byte-identical to the pre-D18 format), so a degenerate
    operation never gains a spurious annotation.
    """
    head = f"{method.upper()} {path}"

    segments: List[str] = []

    tags = operation.get("tags")
    if isinstance(tags, list):
        tag_strs = [str(t).strip() for t in tags if isinstance(t, (str, int)) and str(t).strip()]
        if tag_strs:
            segments.append("tags: " + ", ".join(tag_strs))

    op_id = operation.get("operationId")
    if isinstance(op_id, str) and op_id.strip():
        segments.append("operationId: " + op_id.strip())

    if not segments:
        return head
    return f"{head}  [{'; '.join(segments)}]"


def catalog_from_openapi(spec: Dict[str, Any]) -> List[str]:
    """Build a normalized endpoint catalog from a parsed OpenAPI/Swagger document.

    Args:
        spec: a parsed OpenAPI 3.x or Swagger 2.0 document (already JSON-decoded
            into a dict). For a FastAPI app this is exactly `app.openapi()`.

    Returns:
        A de-duplicated, deterministically sorted list of catalog entries. Each entry
        LEADS with "METHOD /path" — METHOD uppercased, /path the OpenAPI templated path
        verbatim (e.g. "GET /api/users/{user_id}/profile") — optionally followed by a
        "  [tags: ...; operationId: ...]" annotation carrying the operation's GENUINE,
        pre-existing OpenAPI metadata (only fields actually present are surfaced; nothing
        is invented). An operation with no such metadata yields the bare "METHOD /path".
        Returns [] for a missing/empty or malformed `paths` section rather than raising —
        a degenerate spec yields an empty catalog, never a crash.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []

    entries: List[str] = []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path:
            continue
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if not isinstance(method, str):
                continue
            if method.lower() not in _OPENAPI_HTTP_METHODS:
                continue
            # An operation should be a mapping (Operation Object); skip anything
            # that clearly is not, so we never emit metadata as an endpoint.
            if operation is None or not isinstance(operation, dict):
                continue
            entries.append(_format_entry(method, path, operation))

    return _normalize(entries)


def catalog_from_har(har: Dict[str, Any]) -> List[str]:
    """Build a catalog from a HAR / proxy-capture inventory.

    STUB (Step 1): the HAR adapter is an intentional, documented seam so the
    dispatcher's interface is pluggable from day one. The real implementation
    (aggregate observed flows from the Step 9 proxy radar / an imported HAR,
    template numeric/opaque path segments back into {id} form, dedupe) lands in a
    later step. It raises NotImplementedError so a caller can never silently get
    an empty catalog and mistake "not implemented" for "no endpoints".
    """
    raise NotImplementedError(
        "HAR / proxy-capture catalog source is not implemented yet (D18 stub); "
        "use catalog_from_openapi for now."
    )


def build_catalog(source: Dict[str, Any]) -> List[str]:
    """Dispatch to the right adapter based on a source descriptor.

    Args:
        source: a descriptor dict of the form
            {"kind": "openapi", "spec": <parsed openapi dict>} or
            {"kind": "har",     "har":  <parsed har dict>}.

    Returns:
        The normalized endpoint catalog from the selected adapter.

    Raises:
        ValueError: if `source` is malformed or names an unknown kind.
        NotImplementedError: if the selected adapter is a stub (e.g. HAR).
    """
    if not isinstance(source, dict):
        raise ValueError(f"source must be a dict descriptor, got {type(source).__name__}")

    kind = source.get("kind")
    if kind == SOURCE_OPENAPI:
        return catalog_from_openapi(source.get("spec") or {})
    if kind == SOURCE_HAR:
        return catalog_from_har(source.get("har") or {})
    raise ValueError(f"unknown catalog source kind: {kind!r}")


# ==============================================================================
# Structural catalog QUERIES (B-1 — target-agnostic, used by the deep verifier to
# DETERMINISTICALLY gather a write-record read-back instead of relying on the model
# to choose it). Pure string/structure functions over the "METHOD /path  [..]"
# catalog entries. NOTHING here is specific to any target: no concrete path, no field
# name, no tag value is hardcoded — only GENERAL API vocabulary and path structure.
# ==============================================================================

# General, target-agnostic vocabulary for an endpoint that is an explicit RECORD of
# write activity (a log / history / events / audit trail / journal / changelog). These
# are universal API concepts; the SAME words identify such endpoints in ANY OpenAPI
# surface. This is a generic CATEGORY, not the practice target's concrete endpoint.
_WRITE_RECORD_KEYWORDS = frozenset({
    "audit", "audits",
    "log", "logs", "logging",
    "history", "histories", "historical",
    "event", "events",
    "journal", "journals",
    "trail", "trails",
    "activity", "activities",
    "record", "records",
    "changelog", "changelogs",
    "feed", "feeds",
    "timeline", "timelines",
    "ledger", "ledgers",
})

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> set:
    """Lower-cased alphanumeric tokens (split on every non-alphanumeric boundary).

    So "/api/audit-log" -> {"api","audit","log"} and "login" -> {"login"} (NOT "log").
    Whole-token matching avoids spurious substring hits (e.g. 'log' in 'login').
    """
    return {t for t in _TOKEN_SPLIT_RE.split((text or "").lower()) if t}


def entry_prefix(entry: str) -> str:
    """The leading 'METHOD /path' of a (possibly annotated) catalog entry."""
    return (entry or "").split("  [", 1)[0]


def entry_method(entry: str) -> str:
    return entry_prefix(entry).partition(" ")[0].upper()


def entry_path(entry: str) -> str:
    return entry_prefix(entry).partition(" ")[2]


def is_write_record_entry(entry: str) -> bool:
    """True iff this catalog entry GENERICALLY reads like a record/log/history/events
    endpoint. Target-agnostic: matches the general record vocabulary against the WHOLE
    entry (path segments + surfaced tags + operationId tokens). Only READ (GET) endpoints
    qualify — you READ a record/log; a POST is not a read-back. NO concrete target path,
    field, or tag is hardcoded; this same rule flags such endpoints in any API."""
    if entry_method(entry) != "GET":
        return False
    return bool(_tokens(entry) & _WRITE_RECORD_KEYWORDS)


def select_write_record_endpoint(
    entries: List[str], *, attacked_object_id: Optional[str] = None
) -> Optional[str]:
    """Deterministically choose ONE write-record read-back PATH from the catalog, or None.

    Generic selection (no hardcoding): among GET endpoints that read like a record/log
    (`is_write_record_entry`), prefer a parameter-less path; otherwise take the first in
    the catalog's deterministic order and, if it is templated, best-effort fill its
    `{...}` segment(s) with the attacked object id (a runtime param). Returns a concrete
    relative path ready to fetch, or None when no record-style endpoint exists (in which
    case the caller must NOT fabricate one — it stays inconclusive)."""
    candidates = [e for e in (entries or []) if is_write_record_entry(e)]
    if not candidates:
        return None
    paramless = [e for e in candidates if "{" not in entry_path(e)]
    chosen_path = entry_path((paramless or candidates)[0])
    if "{" in chosen_path and attacked_object_id is not None:
        chosen_path = re.sub(r"\{[^}]+\}", str(attacked_object_id), chosen_path)
    return chosen_path


def _templates_match(catalog_path: str, concrete_path: str) -> bool:
    """Segment-wise match where a catalog '{templated}' segment is a wildcard.

    A REAL templated read-back (e.g. '/api/users/{id}/profile') matches the attacked
    concrete path ('/api/users/2/profile'); a CONCRETE placeholder on a different id
    ('/api/users/1/display-name') does NOT match the attack ('/api/users/2/display-name').
    """
    a = (catalog_path or "").split("/")
    b = (concrete_path or "").split("/")
    if len(a) != len(b):
        return False
    for seg_a, seg_b in zip(a, b):
        if seg_a.startswith("{") and seg_a.endswith("}"):
            continue  # templated wildcard
        if seg_a != seg_b:
            return False
    return True


def has_same_path_readback(entries: List[str], attack_path: str) -> bool:
    """True iff the catalog advertises a GET on the SAME resource path the attack targeted
    (templated match). A concrete placeholder GET on a DIFFERENT id does not count, so a
    genuinely cross-path write (one whose resource has no real same-path GET) is detected
    as having NO same-path read-back. Target-agnostic structure only."""
    ap = (attack_path or "").split("?", 1)[0]
    for e in (entries or []):
        if entry_method(e) != "GET":
            continue
        if _templates_match(entry_path(e), ap):
            return True
    return False
