# ==============================================================================
# Offline tests for the per-user config-file settings source (config.py) and the
# CLI's friendly first-run detection. Zero API cost, no network.
#
# Proves the gated config.py change does EXACTLY what was signed off:
#   * env / .env WIN over the file (the file only fills gaps);
#   * an absent / malformed file is byte-identical (defaults hold, no crash);
#   * a key read from the file becomes a SecretStr and never shows a plaintext repr;
#   * verdict flags (AI_DEEP_VERIFY_*) are untouched by the file;
#   * `<brand> verify` with no key guides the user to `<brand> config` (no stack trace).
# ==============================================================================
import os
import sys
import importlib.util

from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.core.config import Settings, reveal_secret
from backend.app.cli import branding


def _write_cfg(tmp_path, text: str) -> str:
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def _point_at(monkeypatch, path: str):
    monkeypatch.setenv(branding.config_file_env_var(), path)
    # LLM_* are not in backend/.env; clear any process env so the file source is what's tested.
    for k in ("LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY", "LLM_PROVIDER"):
        monkeypatch.delenv(k, raising=False)


# ------------------------------------------------------------------ precedence
def test_absent_file_is_byte_identical(monkeypatch, tmp_path):
    _point_at(monkeypatch, str(tmp_path / "does-not-exist.toml"))
    s = Settings()
    assert s.LLM_MODEL is None                    # default unchanged
    assert s.LLM_BASE_URL is None
    assert s.LLM_PROVIDER == "gemini"
    assert s.AI_DEEP_VERIFY_ENABLED is False      # flags unchanged


def test_file_fills_gap_when_env_absent(monkeypatch, tmp_path):
    cfg = _write_cfg(tmp_path, 'LLM_MODEL = "file-model"\nLLM_BASE_URL = "https://relay.example/v1"\n')
    _point_at(monkeypatch, cfg)
    s = Settings()
    assert s.LLM_MODEL == "file-model"
    assert s.LLM_BASE_URL == "https://relay.example/v1"


def test_env_wins_over_file(monkeypatch, tmp_path):
    cfg = _write_cfg(tmp_path, 'LLM_MODEL = "file-model"\n')
    _point_at(monkeypatch, cfg)
    monkeypatch.setenv("LLM_MODEL", "env-model")   # explicit env set AFTER _point_at cleared it
    s = Settings()
    assert s.LLM_MODEL == "env-model"              # env beats the file


# ------------------------------------------------------------------ secret discipline
def test_file_key_is_secretstr_and_never_plaintext_repr(monkeypatch, tmp_path):
    cfg = _write_cfg(tmp_path, 'LLM_API_KEY = "sk-from-file-canary-4242"\n')
    _point_at(monkeypatch, cfg)
    s = Settings()
    assert isinstance(s.LLM_API_KEY, SecretStr)
    assert reveal_secret(s.LLM_API_KEY) == "sk-from-file-canary-4242"   # reaches point of use
    assert "sk-from-file-canary-4242" not in repr(s.LLM_API_KEY)        # never in the field repr
    assert "sk-from-file-canary-4242" not in str(s)                     # never in the model repr


# ------------------------------------------------------------------ fail-safe / no drift
def test_malformed_file_fails_safe(monkeypatch, tmp_path):
    _point_at(monkeypatch, _write_cfg(tmp_path, "this is : not = valid toml [[[\n"))
    s = Settings()                                 # must NOT raise
    assert s.LLM_MODEL is None                     # malformed file ignored


def test_file_cannot_flip_a_verdict_flag(monkeypatch, tmp_path):
    cfg = _write_cfg(tmp_path, 'LLM_PROVIDER = "openai"\nLLM_MODEL = "m"\n')
    _point_at(monkeypatch, cfg)
    s = Settings()
    assert s.LLM_PROVIDER == "openai"              # the file filled the LLM_* gap
    assert s.AI_DEEP_VERIFY_ENABLED is False       # ...but verdict flags stay at their defaults
    assert s.AI_DEEP_VERIFY_SHADOW is False
    assert s.AI_DEEP_VERIFY_PROMOTE is False


# ------------------------------------------------------------------ first-run detection
def _load_root_run():
    path = os.path.join(_REPO_ROOT, "run.py")
    spec = importlib.util.spec_from_file_location("_root_run_first_run", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_first_run_detection_guides_to_config_without_crashing(monkeypatch, capsys):
    run = _load_root_run()
    # No resolvable key -> the verify path must guide, not crash.
    monkeypatch.setattr(run.settings, "LLM_API_KEY", None)
    monkeypatch.setattr(run.settings, "GEMINI_API_KEY", None)
    code = run.confirm("no-such-caseset.json", None, None)   # key check is FIRST; caseset never read
    assert code == 2                                          # NOT DATA exit, no exception raised
    err = capsys.readouterr().err
    assert "config" in err
    assert run.command_name() in err                         # names the `<brand> config` command
