# ==============================================================================
# Editable target TEMPLATE file - the "form" way to create a target in ONE pass.
#
# The pain this kills: the interactive `target` flow asks one field at a time with no overview and no
# way to go back. Here the user DUMPS a fully-commented template (every field at once, each with its
# why + example), fills it in a single editor pass, and LOADS it - validation reports ALL errors at
# once (each bad field named), so the user fixes them in the file and reloads.
#
# RED LINES (welded):
#   * The template IS the SAME TOML the interactive flow produces (targets.SAVE_FIELDS + the audited
#     0600 writer via targets.save_target) - NOT a second target format.
#   * NON-SECRET only: there is NO token field, and this module never reads/writes a token. Tokens stay
#     off the target file (the deliberate off-disk discipline); the non-interactive scan sources them
#     from env / a runtime tokens-file instead (see scan_cli.py).
#   * Validation is PURE and offline (the only I/O is reading the file being validated + optionally
#     stat/parse of a referenced spec/login file). It touches NO verdict/engine logic.
# ==============================================================================
from __future__ import annotations

import os
import tomllib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from backend.app.cli.console import targets
from backend.app.cli.console.targets import Target, SAVE_FIELDS, FIELD_GUIDE

_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")
_ID_LOCATIONS = ("path", "query")


def _toml_escape(s: str) -> str:
    return (s or "").replace("\\", "\\\\").replace('"', '\\"')


def _comment_block(field: str) -> List[str]:
    """The inline `#` comment lines for one field - reused verbatim from the interactive guidance
    (FIELD_GUIDE), so the template teaches exactly what the prompts do."""
    g = FIELD_GUIDE.get(field, {})
    out = [f"# {g.get('label', field)}  ({'REQUIRED' if g.get('required') else 'optional - may be blank'})"]
    if g.get("hint"):
        out.append(f"#   {g['hint']}")
    if g.get("why"):
        out.append(f"#   why: {g['why']}")
    if g.get("example"):
        out.append(f"#   example: {g['example']}")
    return out


def render_template() -> str:
    """The fully-commented template TEXT (every SAVE_FIELD present at once). Pure - no I/O."""
    lines: List[str] = [
        "# =========================================================================",
        "# Target definition - fill in the values below in ONE pass, then load it with:",
        f"#     {targets.branding.command_name()} target --from-file <this-file>",
        "# All fields are shown at once; edit any of them and fix errors before it is created.",
        "#",
        "# NON-SECRET only: there is deliberately NO token field. Tokens are NEVER stored here -",
        "# at scan/verify time they come from env vars (TARGET_ATTACKER_TOKEN / _OWNER_TOKEN /",
        "# _BYSTANDER_TOKEN) or a runtime --tokens-file, never this file.",
        "# =========================================================================",
        "",
    ]
    for field in SAVE_FIELDS:
        lines.extend(_comment_block(field))
        lines.append(f'{field} = ""')
        lines.append("")
    return "\n".join(lines)


def dump_template(path: str) -> str:
    """Write the commented template to `path` (creating parent dirs). Returns the path. The template
    holds no secrets, so it is written with normal permissions (unlike the 0600 config/target files)."""
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_template())
    return path


def _norm_base_url(v: str) -> str:
    """Mirror the interactive `_ask_url`: accept a bare host (prepend http://) and require a hostname."""
    v = (v or "").strip()
    if not v:
        return ""
    u = v if "://" in v else "http://" + v
    return u if urlsplit(u).hostname else ""


def validate_fields(data: Dict[str, object]) -> Tuple[Optional[Target], List[str]]:
    """Validate ALL target fields, collecting EVERY error (not one-at-a-time). On success returns
    (Target, []); on any error returns (None, [all errors]) and creates NOTHING. Unknown keys in the
    file are ignored (forward/backward compatible). A token-looking key is REJECTED (tokens never
    belong in a target file)."""
    errors: List[str] = []
    vals: Dict[str, str] = {f: str(data.get(f, "") or "").strip() for f in SAVE_FIELDS}

    # RED LINE: a token/credential key must never appear in a target file.
    for k in data:
        kl = str(k).lower()
        if "token" in kl or "password" in kl or "secret" in kl:
            errors.append(f"'{k}': a target file must NEVER contain a token/credential "
                          "(tokens come from env vars or --tokens-file at scan time).")

    if not vals["name"]:
        errors.append("name: required - a label to save and re-select this target.")

    base = _norm_base_url(vals["base_url"])
    if not base:
        errors.append("base_url: required and must be a URL with a host, e.g. http://localhost:8888.")
    else:
        vals["base_url"] = base

    # spec_path: optional; if present must be a readable OpenAPI file.
    if vals["spec_path"]:
        if not os.path.isfile(vals["spec_path"]):
            errors.append(f"spec_path: file not found: {vals['spec_path']} "
                          "(leave blank for a spec-less target).")
        else:
            try:
                from backend.app.cli.external_verify import _load_spec_file
                _load_spec_file(vals["spec_path"])
            except Exception as ex:
                errors.append(f"spec_path: not a readable OpenAPI JSON/YAML file "
                              f"({type(ex).__name__}). Leave blank for a spec-less target.")

    method = vals["method"].upper()
    if method not in _METHODS:
        errors.append(f"method: required - one of {', '.join(_METHODS)} (got {vals['method']!r}).")
    else:
        vals["method"] = method

    if not vals["path_template"].startswith("/"):
        errors.append("path_template: required and must start with '/', "
                      "e.g. /workshop/api/shop/orders/{order_id}.")

    id_location = vals["id_location"].lower()
    if id_location not in _ID_LOCATIONS:
        errors.append('id_location: required - "path" or "query" '
                      f"(got {vals['id_location']!r}).")
    else:
        vals["id_location"] = id_location

    if not vals["id_param"]:
        errors.append("id_param: required - the {template} var name (path) or query parameter name.")
    elif id_location == "path" and vals["path_template"].startswith("/") \
            and ("{" + vals["id_param"] + "}") not in vals["path_template"]:
        errors.append(f"id_param: {vals['id_param']!r} must appear as {{{vals['id_param']}}} in the "
                      f"path_template for a path id (got path {vals['path_template']!r}).")

    if not vals["attacker_id"]:
        errors.append("attacker_id: required - an id the ATTACKER legitimately owns (the baseline).")
    if not vals["victim_id"]:
        errors.append("victim_id: required - the id the attacker should NOT be able to reach.")

    if vals["auth_spec_path"] and not os.path.isfile(vals["auth_spec_path"]):
        errors.append(f"auth_spec_path: file not found: {vals['auth_spec_path']} "
                      "(leave blank to paste/provide tokens instead).")

    if errors:
        return None, errors
    return Target(**{f: vals[f] for f in SAVE_FIELDS}), []


def load_target_file(path: str) -> Tuple[Optional[Target], List[str]]:
    """Read + validate a target file. Returns (Target, []) or (None, [all errors]). A parse/read
    failure is reported as a single error (never a crash). Creates/saves NOTHING."""
    if not os.path.isfile(path):
        return None, [f"file not found: {path}"]
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception as ex:
        return None, [f"could not parse the target file as TOML ({type(ex).__name__}): {ex}"]
    if not isinstance(data, dict):
        return None, ["the target file must be a TOML table of field = \"value\" lines."]
    return validate_fields(data)


def save_target_from_file(path: str) -> Tuple[Optional[Target], List[str]]:
    """Load + validate + (only if valid) SAVE the target via the audited 0600 writer. Returns
    (Target, []) on success, else (None, errors) with NOTHING created."""
    t, errors = load_target_file(path)
    if errors:
        return None, errors
    targets.save_target(t)               # reuse the existing 0600 TOML writer (no second format)
    return t, []
