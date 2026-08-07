# ==============================================================================
# Feature 1 — the editable target TEMPLATE file. Proves the "form" workflow: dump a fully-commented
# template, fill it, load it -> a valid Target IDENTICAL to what the interactive flow would build; a
# file with misplaced/invalid fields -> ALL errors reported at once, NOTHING created. Also proves the
# TOKEN RED LINE: a target file never carries a token (a token key is rejected; a saved target has none).
# Zero network / no engine.
# ==============================================================================
import os
import sys
import tomllib

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli import branding, target_file
from backend.app.cli.console import targets as tg


def _spec(tmp_path):
    p = tmp_path / "spec.json"
    p.write_text('{"openapi":"3.0.0","paths":{"/api/orders/{order_id}":{"get":{}}}}', encoding="utf-8")
    return str(p)


def _filled(tmp_path, spec_path, **over):
    """A valid, filled target TOML. `spec_path` written as a TOML LITERAL string so Windows backslashes
    stay literal (no escape headaches)."""
    fields = dict(name="crapi-orders", base_url="http://localhost:8888", method="get",
                  path_template="/api/orders/{order_id}", id_location="path", id_param="order_id",
                  attacker_id="8", victim_id="7", auth_spec_path="")
    fields.update(over)
    lines = [f'{k} = "{v}"' for k, v in fields.items()]
    lines.insert(2, f"spec_path = '{spec_path}'")   # literal string, Windows-safe
    p = tmp_path / "filled.toml"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


# ------------------------------------------------------------------ dump
def test_dump_template_has_every_field_with_guidance_and_no_token_field(tmp_path):
    p = tmp_path / "template.toml"
    target_file.dump_template(str(p))
    text = p.read_text(encoding="utf-8")
    for f in tg.SAVE_FIELDS:
        assert f'{f} = ""' in text                       # every persisted field present, editable
    assert "REQUIRED" in text and "example:" in text     # guidance reused from FIELD_GUIDE
    assert "NEVER" in text and "token" in text.lower()   # the tokens-never-here discipline is stated
    # deliberately NO token/credential field in the form
    assert "token =" not in text.lower() and "password" not in text.lower()


# ------------------------------------------------------------------ round-trip == interactive
def test_fill_then_load_equals_the_interactive_target(tmp_path):
    spec = _spec(tmp_path)
    path = _filled(tmp_path, spec)
    t, errors = target_file.load_target_file(path)
    assert errors == []
    # the SAME Target the interactive `target` flow produces for these answers
    expected = tg.Target(name="crapi-orders", base_url="http://localhost:8888", spec_path=spec,
                         method="GET", path_template="/api/orders/{order_id}", id_location="path",
                         id_param="order_id", attacker_id="8", victim_id="7", auth_spec_path="")
    assert t == expected
    assert t.to_op()["baseline_path"] == "/api/orders/8"     # feeds the same op schema


def test_save_target_from_file_persists_no_token(tmp_path, monkeypatch):
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))
    spec = _spec(tmp_path)
    t, errors = target_file.save_target_from_file(_filled(tmp_path, spec))
    assert errors == [] and t.name == "crapi-orders"
    saved = tomllib.loads((tmp_path / "targets" / "crapi-orders.toml").read_text(encoding="utf-8"))
    assert saved["attacker_id"] == "8"
    assert not any("token" in k.lower() or "password" in k.lower() for k in saved)   # NEVER on disk


# ------------------------------------------------------------------ ALL errors at once
def test_invalid_file_reports_all_errors_and_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))
    bad = tmp_path / "bad.toml"
    bad.write_text(
        'name = ""\n'                                        # 1 missing name
        'base_url = ""\n'                                    # 2 missing url
        "spec_path = 'C:/nope/does_not_exist.json'\n"        # 3 spec file not found
        'method = "BOGUS"\n'                                 # 4 bad method
        'path_template = "orders/{order_id}"\n'              # 5 no leading /
        'id_location = "elsewhere"\n'                        # 6 bad location
        'id_param = ""\n'                                    # 7 missing id_param
        'attacker_id = ""\n'                                 # 8 missing attacker id
        'victim_id = ""\n'                                   # 9 missing victim id
        'TARGET_ATTACKER_TOKEN = "leaked"\n',                # 10 token key -> REJECTED
        encoding="utf-8")
    t, errors = target_file.load_target_file(str(bad))
    assert t is None
    joined = "\n".join(errors).lower()
    for field in ("name", "base_url", "spec_path", "method", "path_template",
                  "id_location", "id_param", "attacker_id", "victim_id"):
        assert field in joined                               # EVERY bad field named, at once
    assert "token" in joined                                 # the token key was rejected
    assert len(errors) >= 10
    # nothing was created
    assert not os.path.isdir(tmp_path / "targets")


def test_valid_but_id_param_not_in_path_is_flagged(tmp_path):
    # a path id whose param is not actually in the template is a common misplaced value -> caught.
    spec = _spec(tmp_path)
    path = _filled(tmp_path, spec, id_param="wrong_id")
    t, errors = target_file.load_target_file(path)
    assert t is None and any("id_param" in e for e in errors)
