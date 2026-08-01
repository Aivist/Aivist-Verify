# ==============================================================================
# Offline tests for the CLI packaging / branding / interactive config flow.
# Zero API cost, no network, no real terminal or home directory: the config flow's
# I/O (prompt / secret_prompt / echo / path) is fully injected.
#
# Proves: every brand string derives from the single BRAND_NAME constant (no stray
# hard-coded copy); the console script declared in pyproject matches that constant;
# the parser exposes `verify` (+ `confirm` alias) and `config`; the config flow writes
# the expected TOML with restrictive perms; and the API key is NEVER echoed/printed.
# ==============================================================================
import os
import sys
import stat
import tomllib
import importlib.util

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli import branding
from backend.app.cli.config_flow import run_config_flow, write_config, redacted_summary


def _load_root_run():
    """Load the repo-root run.py by explicit PATH under a unique module name.

    A bare `import run` is ambiguous: `backend/run.py` (the uvicorn server launcher) also
    exists, and pytest puts `backend/` on sys.path, so `import run` would resolve to the
    WRONG file. Loading by path pins the test to the CLI entry point we actually ship."""
    path = os.path.join(_REPO_ROOT, "run.py")
    spec = importlib.util.spec_from_file_location("_root_run_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------ branding
def test_brand_single_source_of_truth():
    b = branding.BRAND_NAME
    assert branding.command_name() == b
    assert branding.display_name().lower() == b.lower()
    assert branding.product_name() == branding.display_name() + " Verify"
    assert branding.verify_command() == b + " verify"
    assert branding.config_dir().endswith("." + b)
    # config file lives under the brand dir when no override is set
    os.environ.pop(branding.config_file_env_var(), None)
    assert branding.config_dir() in branding.config_file_path()


def test_brand_is_derived_not_hardcoded(monkeypatch):
    # Change ONLY the constant; every derived string must follow it. This is the
    # guard that finalizing the name is a one-line change, never a find-replace.
    monkeypatch.setattr(branding, "BRAND_NAME", "zzztestbrand")
    monkeypatch.delenv(branding.config_file_env_var(), raising=False)
    assert branding.command_name() == "zzztestbrand"
    assert branding.display_name() == "Zzztestbrand"
    assert branding.product_name() == "Zzztestbrand Verify"
    assert branding.verify_command() == "zzztestbrand verify"
    assert branding.config_dir().endswith(".zzztestbrand")
    assert branding.config_dir() in branding.config_file_path()


def test_config_file_path_env_override(monkeypatch, tmp_path):
    p = str(tmp_path / "somewhere.toml")
    monkeypatch.setenv(branding.config_file_env_var(), p)
    assert branding.config_file_path() == p


def test_console_script_declared_matches_brand():
    # The pyproject console-script KEY is the one static brand token; assert it equals
    # the constant and points at run:main, so packaging cannot drift from branding.py.
    with open(os.path.join(_REPO_ROOT, "pyproject.toml"), "rb") as fh:
        pj = tomllib.load(fh)
    scripts = pj["project"]["scripts"]
    assert branding.command_name() in scripts
    assert scripts[branding.command_name()] == "run:main"


# ------------------------------------------------------------------ config flow
def test_config_flow_openai_writes_expected_toml(tmp_path):
    path = str(tmp_path / "config.toml")
    secret = "sk-super-secret-DO-NOT-LEAK-12345"
    inputs = iter(["openai", "https://relay.example/v1", "gpt-4o-mini"])
    echoed = []
    rc = run_config_flow(
        prompt=lambda *_: next(inputs),
        secret_prompt=lambda *_: secret,
        echo=lambda *a: echoed.append(" ".join(str(x) for x in a)),
        path=path,
    )
    assert rc == 0
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    assert data["LLM_PROVIDER"] == "openai"
    assert data["LLM_BASE_URL"] == "https://relay.example/v1"
    assert data["LLM_MODEL"] == "gpt-4o-mini"
    assert data["LLM_API_KEY"] == secret            # persisted plaintext in the 0600 file


def test_config_flow_never_echoes_the_key(tmp_path):
    path = str(tmp_path / "config.toml")
    secret = "sk-leak-canary-98765"
    inputs = iter(["openai", "https://host/v1", "m"])
    echoed = []
    run_config_flow(
        prompt=lambda *_: next(inputs),
        secret_prompt=lambda *_: secret,
        echo=lambda *a: echoed.append(" ".join(str(x) for x in a)),
        path=path,
    )
    joined = "\n".join(echoed)
    assert secret not in joined                      # the key is NEVER printed
    assert "***REDACTED***" in joined
    # redacted_summary itself never contains the key
    assert secret not in "\n".join(redacted_summary({"LLM_PROVIDER": "openai", "LLM_API_KEY": secret}))


def test_config_flow_gemini_defaults(tmp_path):
    path = str(tmp_path / "config.toml")
    inputs = iter(["", ""])                          # provider default gemini, model default
    rc = run_config_flow(
        prompt=lambda *_: next(inputs),
        secret_prompt=lambda *_: "gkey-abc",
        echo=lambda *a: None,
        path=path,
    )
    assert rc == 0
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    assert data["LLM_PROVIDER"] == "gemini"
    assert data["LLM_API_KEY"] == "gkey-abc"
    assert data["LLM_MODEL"] == "gemini-2.5-pro"     # gemini prompt default applied
    assert "LLM_BASE_URL" not in data                # base_url is openai-only


def test_config_flow_sets_restrictive_perms_where_supported(tmp_path):
    path = str(tmp_path / "config.toml")
    run_config_flow(
        prompt=lambda *_: "", secret_prompt=lambda *_: "k", echo=lambda *a: None, path=path,
    )
    assert os.path.exists(path)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_write_config_escapes_toml_special_chars(tmp_path):
    path = str(tmp_path / "config.toml")
    tricky = 'quote"and\\backslash'
    write_config({"LLM_PROVIDER": "openai", "LLM_API_KEY": tricky}, path)
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    assert data["LLM_API_KEY"] == tricky             # round-trips through TOML escaping


# ------------------------------------------------------------------ entry point
def test_parser_exposes_verify_config_and_confirm_alias():
    run = _load_root_run()
    p = run.build_parser()
    assert p.parse_args(["verify", "--caseset", "x"]).cmd == "verify"
    assert p.parse_args(["confirm", "--caseset", "x"]).cmd in ("verify", "confirm")  # alias
    assert p.parse_args(["config"]).cmd == "config"
    assert p.prog == branding.command_name()         # prog derives from the brand
