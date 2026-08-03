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
        """Build the op dict the engine consumes (the same shape external_verify uses).
        path  -> baseline_path carries the attacker id in the PATH, payload=path_segment.
        query -> baseline_path carries the attacker id in the QUERY, payload=query_param
                 (D29: the baseline query id is carried and the attack swaps only it)."""
        method = (self.method or "GET").upper()
        if self.id_location == "query":
            sep = "&" if "?" in self.path_template else "?"
            baseline_path = f"{self.path_template}{sep}{self.id_param}={self.attacker_id}"
            payload = {"location": "query_param", "target_param": self.id_param,
                       "payload_string": self.victim_id, "type": "BOLA"}
        else:
            baseline_path = self.path_template.replace("{" + self.id_param + "}", self.attacker_id)
            payload = {"location": "path_segment", "target_param": self.attacker_id,
                       "payload_string": self.victim_id, "type": "BOLA"}
        return {"method": method, "baseline_path": baseline_path, "body": None,
                "payload": payload, "shape": f"console:{self.name}"}


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
