# ==============================================================================
# Endpoint / attack-surface catalog  (D18 — real endpoint discovery, Step 1)
# ==============================================================================
#
# A small, PURE, offline module that turns a real API-surface description into the
# normalized `["METHOD /path", ...]` list that the deep verifier already consumes
# as `available_endpoints` (see deep_verifier._build_turn1_prompt). It exists to
# replace the fuzzer's `_shadow_endpoint_catalog` placeholder — which only ever
# offers the finding's own path + a same-resource GET — with a catalog derived
# from a genuine source of truth (an OpenAPI/Swagger doc today; HAR / proxy-capture
# inventory later via the same interface).
#
# DESIGN CONTRACT (kept deliberately narrow for Step 1):
#   * NO network, NO disk, NO settings, NO fuzzer import at module load or call.
#     Callers parse/fetch the source themselves and hand this module a plain dict
#     (Step 3 will decide how a spec reaches a run: explicit pass for the module,
#     settings-pointed for integration, live fetch optional).
#   * Pure functions only: same input -> same output, fully offline-testable.
#   * Output is normalized and stable: "METHOD /path" strings, METHOD uppercased,
#     path verbatim (OpenAPI templated form, e.g. "/api/users/{user_id}/profile"),
#     de-duplicated, and sorted (by path, then method) for deterministic prompts.
#
# This module does NOT decide WHICH endpoint the verifier should request; it only
# supplies the honest list of what exists. Selection stays with the model.
# ==============================================================================

from typing import Any, Dict, List

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
    """De-duplicate and deterministically sort 'METHOD /path' entries.

    Sort key is (path, method) so endpoints sharing a path group together and the
    output is stable across runs (important: the catalog is fed into an LLM prompt,
    and a stable order keeps that prompt reproducible).
    """
    unique = set(entries)

    def _key(item: str):
        method, _, path = item.partition(" ")
        return (path, method)

    return sorted(unique, key=_key)


def catalog_from_openapi(spec: Dict[str, Any]) -> List[str]:
    """Build a normalized endpoint catalog from a parsed OpenAPI/Swagger document.

    Args:
        spec: a parsed OpenAPI 3.x or Swagger 2.0 document (already JSON-decoded
            into a dict). For a FastAPI app this is exactly `app.openapi()`.

    Returns:
        A de-duplicated, deterministically sorted list of "METHOD /path" strings,
        where METHOD is uppercased and /path is the OpenAPI templated path verbatim
        (e.g. "GET /api/users/{user_id}/profile"). Returns [] for a missing/empty
        or malformed `paths` section rather than raising — a degenerate spec yields
        an empty catalog, never a crash.
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
            entries.append(f"{method.upper()} {path}")

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
