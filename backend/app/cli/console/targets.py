# ==============================================================================
# Named, reusable targets — saved under ~/.<brand>/targets/<name>.toml so the user
# configures the tedious parts ONCE (URL / spec / endpoint / ids / id-location) and
# re-selects them anytime. NON-SECRET fields only: tokens are NEVER written here —
# they are prompted (masked) at verify time. Reuses the config_flow 0600 TOML writer
# and the branding path helper (no second config/path mechanism).
# ==============================================================================
from __future__ import annotations

import glob
import os
import tomllib
from dataclasses import dataclass
from typing import Dict, List, Optional

from backend.app.cli import branding
from backend.app.cli.config_flow import write_config

# The persisted fields. Deliberately no token/credential field — see module header.
_FIELDS = (
    "name", "base_url", "spec_path", "method", "path_template",
    "id_location", "id_param", "attacker_id", "victim_id", "auth_spec_path",
)
# Public alias — the persisted, NON-SECRET target schema. Callers (the interactive flow, the editable
# template, the file loader) reference this ONE tuple so the format can never fork.
SAVE_FIELDS = _FIELDS

# Per-field onboarding guidance — the SINGLE source shared by the interactive `target` flow
# (controller.do_target) AND the editable template (target_file.dump_template) AND the file loader's
# error messages, so the three can never drift. NON-SECRET fields only (tokens are never a field here).
# `required` drives both the interactive re-prompt and the template's validation. `label` is the prompt
# label; `hint`/`example`/`why` are the exact strings the interactive `_guide()` shows.
FIELD_GUIDE = {
    "name": {
        "label": "Target name", "required": True,
        "hint": "A label to save and re-select this target.", "example": "crapi-orders"},
    "base_url": {
        "label": "Base URL", "required": True,
        "hint": "The target's base URL (localhost only).", "example": "http://localhost:8888",
        "why": "Every request is scope-locked to this host."},
    "spec_path": {
        "label": "OpenAPI spec path (blank if the target has none)", "required": False,
        "hint": "Path to the target's OpenAPI/Swagger file (.json or .yml), or BLANK.",
        "example": r"C:\Users\you\crapi-openapi-spec.json",
        "why": "Used to list endpoints. Blank => a spec-less target; `scan` runs from an endpoints "
               "list you provide at scan time."},
    "method": {
        "label": "HTTP method", "required": True,
        "hint": "The endpoint's HTTP method. One of: GET, POST, PUT, DELETE, PATCH.", "example": "GET"},
    "path_template": {
        "label": "Path template", "required": True,
        "hint": "The path, with the id written as a {template}.",
        "example": "/workshop/api/shop/orders/{order_id}"},
    "id_location": {
        "label": "Where is the object id?", "required": True,
        "hint": 'Where the object id lives: "path" (e.g. /orders/{id}) or "query" (e.g. ?report_id=123).',
        "example": "path",
        "why": "The tool swaps the id in this location to attempt cross-user access."},
    "id_param": {
        "label": "Id parameter", "required": True,
        "hint": "For a PATH id: the {template} variable name (e.g. order_id in /orders/{order_id}). "
                "For a QUERY id: the query parameter name (e.g. report_id).",
        "example": "order_id"},
    "attacker_id": {
        "label": "Attacker's OWN resource id", "required": True,
        "hint": "An id the ATTACKER legitimately owns - the safe baseline.", "example": "8",
        "why": "The tool compares this against the victim's to detect a real leak."},
    "victim_id": {
        "label": "Victim's resource id", "required": True,
        "hint": "The id the attacker should NOT be able to reach.", "example": "7",
        "why": "The tool swaps this in to attempt the cross-user access."},
    "auth_spec_path": {
        "label": "Login file", "required": False,
        "hint": "OPTIONAL path to a login-declaration JSON (auto-relogin for tokens that expire mid-run).",
        "example": "leave BLANK to just paste tokens at verify time",
        "why": "Only needed if the target's tokens expire during a run."},
}


@dataclass
class Target:
    """A reusable confirmation target. All fields are non-secret."""
    name: str
    base_url: str
    spec_path: str
    method: str
    path_template: str            # e.g. /workshop/api/shop/orders/{order_id}
    id_location: str              # "path" | "query"
    id_param: str                 # path template var name, or query param name
    attacker_id: str              # the attacker's OWN resource id (the baseline)
    victim_id: str                # the resource id to reach (the attack)
    auth_spec_path: str = ""      # optional login-declaration path (auto-relogin)

    def to_op(self) -> Dict[str, object]:
        """Build the op dict the engine consumes (the same shape external_verify uses)."""
        return build_op(self.method, self.path_template, self.id_location, self.id_param,
                        self.attacker_id, self.victim_id, shape=f"console:{self.name}")


def build_op(method: str, path_template: str, id_location: str, id_param: str,
             attacker_id: str, victim_id: str, *, shape: str) -> Dict[str, object]:
    """Build the flat op dict the engine's `--op` consumes, from its parts. Shared by the
    interactive `target` command and the `scan` auto-discovery onramp so BOTH produce the exact
    same op schema (no second op-gen path).
      path  -> baseline_path carries the attacker id in the PATH, payload=path_segment.
      query -> baseline_path carries the attacker id in the QUERY, payload=query_param
               (D29: the baseline query id is carried and the attack swaps only it)."""
    method = (method or "GET").upper()
    if id_location == "query":
        sep = "&" if "?" in path_template else "?"
        baseline_path = f"{path_template}{sep}{id_param}={attacker_id}"
        payload = {"location": "query_param", "target_param": id_param,
                   "payload_string": victim_id, "type": "BOLA"}
    else:
        baseline_path = path_template.replace("{" + id_param + "}", attacker_id)
        payload = {"location": "path_segment", "target_param": attacker_id,
                   "payload_string": victim_id, "type": "BOLA"}
    return {"method": method, "baseline_path": baseline_path, "body": None,
            "payload": payload, "shape": shape}


def targets_dir() -> str:
    """~/.<brand>/targets/ — derived from the ONE branding path helper (≡ Path.home())."""
    return os.path.join(branding.config_dir(), "targets")


def _safe_name(name: str) -> str:
    keep = "".join(c if (c.isalnum() or c in "-_") else "_" for c in (name or "").strip())
    return keep or "target"


def target_path(name: str) -> str:
    return os.path.join(targets_dir(), _safe_name(name) + ".toml")


def save_target(t: Target) -> str:
    """Persist a target (0600, non-secret fields only). Returns the file path."""
    data = {f: str(getattr(t, f) or "") for f in _FIELDS}
    path = target_path(t.name)
    write_config(data, path)          # reuse the audited 0600 TOML writer
    return path


def load_target(name: str) -> Optional[Target]:
    path = target_path(name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as fh:
            d = tomllib.load(fh)
    except Exception:
        return None
    return Target(**{f: str(d.get(f, "")) for f in _FIELDS})


def list_targets() -> List[str]:
    """Names of saved targets (sorted). Missing dir -> empty list."""
    d = targets_dir()
    if not os.path.isdir(d):
        return []
    out: List[str] = []
    for p in sorted(glob.glob(os.path.join(d, "*.toml"))):
        try:
            with open(p, "rb") as fh:
                dd = tomllib.load(fh)
            out.append(str(dd.get("name") or os.path.splitext(os.path.basename(p))[0]))
        except Exception:
            continue
    return out
