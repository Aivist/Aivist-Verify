# ==============================================================================
# Offline tests for the interactive console (backend/app/cli/console/*). Zero API,
# no real terminal: I/O is injected, the engine/lab are faked. Proves the usability
# overhaul — validate-at-entry + re-prompt, numbered menus, clear-text non-secret
# fields vs masked key/tokens, the guided help, the confused-first-user walk, and the
# `demo` command — plus the terminal-safety paths. Direct-command regression stays in
# test_external_verify.py; the lived experience is proven by the cold walk-through.
# ==============================================================================
import io
import os
import sys
import types
import tomllib
import importlib.util

import pytest
from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli import branding
from backend.app.cli.console.controller import ConsoleController
from backend.app.cli.console import targets as tg
from backend.app.cli.console import launcher as lz
from backend.app.core.config import settings


# ------------------------------------------------------------------ helpers
def _load_cli_run():
    """Load the repo-root run.py by PATH (a bare `import run` can hit another module under
    pytest). Pins the tests to the CLI entry we ship."""
    path = os.path.join(_REPO_ROOT, "run.py")
    spec = importlib.util.spec_from_file_location("_root_run_console_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scripted(answers):
    it = iter(answers)
    return lambda *_a: next(it, "")


class _Spy:
    """Records the labels it was called with; returns queued answers."""
    def __init__(self, answers):
        self._it = iter(answers)
        self.labels = []

    def __call__(self, label=""):
        self.labels.append(label)
        return next(self._it, "")


def _ctrl(tmp_path, monkeypatch, *, prompt=None, secret=None, engine=None):
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))   # targets under tmp/targets
    lines = []
    c = ConsoleController(
        prompt=prompt or _scripted([]), secret_prompt=secret or _scripted([]),
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        config_path=str(tmp_path / "config.toml"), engine=engine,
    )
    return c, lines


def _spec(tmp_path):
    p = tmp_path / "spec.json"
    p.write_text('{"openapi":"3.0.0","paths":{"/api/orders/{order_id}":{"get":{}}}}', encoding="utf-8")
    return str(p)


def _fake_engine(**over):
    base = dict(
        status="completed", ai_verdict="verified", ai_verdict_raw="verified",
        guard_override=None, degraded_reason=None, caller_identity_anchor=None,
        payload_causality_anchor=None, state_jump_anchor=None, negative_assertion_anchor=None,
        anchoring_result=None, pre_flight_status=None, owner_view_corroborated=True,
        follow_up_response=None, baseline={"response": {"status_code": 200}},
        attack={"response": {"status_code": 200}},
    )
    base.update(over)

    async def eng(**kw):
        return types.SimpleNamespace(**base)

    return eng


# ------------------------------------------------------------------ help / basic
def test_help_lists_all_commands_with_explanations(tmp_path, monkeypatch):
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.dispatch("help")
    out = "\n".join(lines)
    for cmd in ("help", "demo", "config", "target", "targets", "verify", "status", "quit"):
        assert cmd in out
    assert "when:" in out                                    # each command explains WHEN to use it
    assert "Typical flow" in out


def test_quit_returns_false(tmp_path, monkeypatch):
    c, _ = _ctrl(tmp_path, monkeypatch)
    assert c.dispatch("quit") is False
    assert c.dispatch("help") is True


# ------------------------------------------------------------------ config (numbered + validated + masked key)
def test_config_numbered_provider_and_model_writes_file_redacts_key(tmp_path, monkeypatch):
    monkeypatch.setattr(ConsoleController, "_refresh_settings", lambda self: None)   # hermetic
    c, lines = _ctrl(tmp_path, monkeypatch,
                     prompt=_scripted(["1", "1"]),           # provider=1 gemini, model menu=1
                     secret=_scripted(["SECRET-KEY-CANARY"]))
    c.dispatch("config")
    data = tomllib.loads((tmp_path / "config.toml").read_text(encoding="utf-8"))
    assert data["LLM_PROVIDER"] == "gemini" and data["LLM_MODEL"] == "gemini-2.5-pro"
    assert data["LLM_API_KEY"] == "SECRET-KEY-CANARY"
    out = "\n".join(lines)
    assert "SECRET-KEY-CANARY" not in out                    # never echoed
    assert "received (17 characters)" in out                 # but confirmed


def test_config_invalid_custom_model_reprompts(tmp_path, monkeypatch):
    monkeypatch.setattr(ConsoleController, "_refresh_settings", lambda self: None)
    c, lines = _ctrl(tmp_path, monkeypatch,
                     prompt=_scripted(["1", "3", "2.5", "gemini-2.5-pro"]),   # custom "2.5" bad -> retype
                     secret=_scripted(["k"]))
    c.dispatch("config")
    out = "\n".join(lines)
    assert "doesn't look like a model id" in out
    data = tomllib.loads((tmp_path / "config.toml").read_text(encoding="utf-8"))
    assert data["LLM_MODEL"] == "gemini-2.5-pro"             # recovered to a valid value


def test_status_redacts_key(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("STATUS-KEY-CANARY"))
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.dispatch("status")
    out = "\n".join(lines)
    assert "set (redacted)" in out and "STATUS-KEY-CANARY" not in out


# ------------------------------------------------------------------ target (validated + numbered + no tokens)
def test_target_happy_path_saves_selects_no_tokens(tmp_path, monkeypatch):
    spec = _spec(tmp_path)
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=_scripted([
        "mytarget", "http://localhost:8888", spec,
        "1",          # endpoint pick -> GET /api/orders/{order_id}
        "1",          # id location -> path
        "8", "7", "", # attacker id, victim id, login (blank)
    ]))
    c.dispatch("target")
    assert c.selected and c.selected.name == "mytarget"
    d = tomllib.loads((tmp_path / "targets" / "mytarget.toml").read_text(encoding="utf-8"))
    assert d["attacker_id"] == "8" and d["id_param"] == "order_id"
    assert not any("token" in k.lower() or "password" in k.lower() for k in d)   # never on disk
    assert c.selected.to_op()["baseline_path"] == "/api/orders/8"


def test_target_allows_blank_spec_for_spec_less_target(tmp_path, monkeypatch):
    # scan "1": a target can be created with NO spec (blank) -> endpoints provided at scan time.
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=_scripted([
        "specless", "http://localhost:8888", "",   # name, url, BLANK spec (spec-less)
        "1",                                         # method menu -> GET (manual entry, no spec)
        "/api/orders/{order_id}",                    # path template (manual)
        "1",                                         # id location -> path
        "8", "7", "",                                # attacker id, victim id, login (blank)
    ]))
    c.dispatch("target")
    assert c.selected and c.selected.name == "specless"
    d = tomllib.loads((tmp_path / "targets" / "specless.toml").read_text(encoding="utf-8"))
    assert d["spec_path"] == ""                       # spec-less target persisted
    assert c.selected.to_op()["baseline_path"] == "/api/orders/8"


def test_help_documents_scan_without_a_spec(tmp_path, monkeypatch):
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.dispatch("help")
    out = "\n".join(lines).lower()
    assert "without an openapi spec" in out and "endpoints" in out   # discoverable no-spec scan


def test_target_bad_spec_path_reprompts(tmp_path, monkeypatch):
    spec = _spec(tmp_path)
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=_scripted([
        "t", "http://localhost:8888",
        str(tmp_path / "does_not_exist.json"), spec,      # bad spec -> re-prompt -> valid
        "1", "1", "8", "7", "",
    ]))
    c.dispatch("target")
    assert "wasn't found" in "\n".join(lines)
    assert c.selected and c.selected.name == "t"


def test_target_query_location_builds_query_op():
    t = tg.Target(name="m", base_url="http://localhost:8888", spec_path="", method="GET",
                  path_template="/workshop/api/mechanic/mechanic_report", id_location="query",
                  id_param="report_id", attacker_id="7", victim_id="6")
    op = t.to_op()
    assert op["baseline_path"] == "/workshop/api/mechanic/mechanic_report?report_id=7"
    assert op["payload"] == {"location": "query_param", "target_param": "report_id",
                             "payload_string": "6", "type": "BOLA"}


def test_targets_list_and_select(tmp_path, monkeypatch):
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))
    tg.save_target(tg.Target(name="alpha", base_url="http://localhost:8888", spec_path="",
                             method="GET", path_template="/a/{id}", id_location="path",
                             id_param="id", attacker_id="1", victim_id="2"))
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=_scripted(["1"]))
    c.dispatch("targets")
    assert "alpha" in "\n".join(lines) and c.selected and c.selected.name == "alpha"


# ------------------------------------------------------------------ Feature 3: overview / review / saved-state
def test_target_review_lets_a_field_be_corrected_before_save(tmp_path, monkeypatch):
    # A misplaced value (a URL typed into the NAME slot) is caught at the REVIEW step and fixed BEFORE
    # anything is saved — the "errors flagged, edit, resubmit" the director asked for, interactively.
    spec = _spec(tmp_path)
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=_scripted([
        "http://misplaced-url-in-name",         # name slot (wrong on purpose)
        "http://localhost:8888",                # base url
        spec, "1", "1", "8", "7", "",           # spec, endpoint, id-loc, attacker, victim, login
        "1",                                    # review -> edit field 1 (name)
        "crapi-orders",                         # corrected name
        "",                                     # review -> blank -> save
    ]))
    c.dispatch("target")
    out = "\n".join(lines)
    assert "Review - the target as entered" in out              # the review step ran
    assert "you'll provide these" in out.lower() or "You'll provide these" in out   # overview, not blind
    assert c.selected and c.selected.name == "crapi-orders"     # corrected, not the misplaced URL
    d = tomllib.loads((tmp_path / "targets" / "crapi-orders.toml").read_text(encoding="utf-8"))
    assert d["name"] == "crapi-orders" and d["base_url"] == "http://localhost:8888"


def test_startup_shows_key_configured_and_saved_targets(tmp_path, monkeypatch):
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("startup-key"))
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.run_intro()
    out = "\n".join(lines)
    assert "API key: configured" in out and "startup-key" not in out    # KNOWN configured, never echoed
    # with a saved target, the startup names it so the user doesn't re-create it
    tg.save_target(tg.Target(name="alpha", base_url="http://localhost:8888", spec_path="", method="GET",
                             path_template="/a/{id}", id_location="path", id_param="id",
                             attacker_id="1", victim_id="2"))
    lines.clear()
    c.run_intro()
    out2 = "\n".join(lines)
    assert "Saved targets" in out2 and "alpha" in out2


# ------------------------------------------------------------------ MASKING invariant (bug #1)
def test_only_key_and_tokens_are_masked(tmp_path, monkeypatch):
    # do_target: every field is non-secret -> the masked prompt is NEVER used.
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))
    spec = _spec(tmp_path)
    prompt_spy = _Spy(["t", "http://localhost:8888", spec, "1", "1", "8", "7", ""])
    secret_spy = _Spy([])
    c = ConsoleController(prompt=prompt_spy, secret_prompt=secret_spy, echo=lambda *a: None,
                          config_path=str(tmp_path / "config.toml"))
    c.dispatch("target")
    assert len(secret_spy.labels) == 0                       # NO target field was masked
    assert any("Target name" in lbl for lbl in prompt_spy.labels)   # shown in clear text

    # do_config: exactly ONE masked prompt (the API key); provider/model are clear.
    monkeypatch.setattr(ConsoleController, "_refresh_settings", lambda self: None)
    prompt_spy2 = _Spy(["1", "1"])
    secret_spy2 = _Spy(["thekey"])
    c2 = ConsoleController(prompt=prompt_spy2, secret_prompt=secret_spy2, echo=lambda *a: None,
                           config_path=str(tmp_path / "config.toml"))
    c2.dispatch("config")
    assert len(secret_spy2.labels) == 1                      # only the key is masked


# ------------------------------------------------------------------ verify (guided masked+confirmed tokens)
def test_verify_without_selected_target(tmp_path, monkeypatch):
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.dispatch("verify")
    assert "No target selected" in "\n".join(lines)


def test_verify_without_key_guides(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", None)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", None)
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.selected = tg.Target(name="t", base_url="http://localhost:8888", spec_path="", method="GET",
                           path_template="/a/{id}", id_location="path", id_param="id",
                           attacker_id="1", victim_id="2")
    c.dispatch("verify")
    assert "No API key configured" in "\n".join(lines)       # guided, not a crash


def test_verify_confirms_and_confirms_token_receipt(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    (tmp_path / "s.json").write_text('{"openapi":"3.0.0","paths":{}}', encoding="utf-8")
    # secret order (2a): bystander (blank -> skip), then attacker, then owner.
    c, lines = _ctrl(tmp_path, monkeypatch, secret=_scripted(["", "Bearer atk", "Bearer own"]),
                     engine=_fake_engine())
    c.selected = tg.Target(name="t", base_url="http://localhost:8888", spec_path=str(tmp_path / "s.json"),
                           method="GET", path_template="/api/orders/{id}", id_location="path",
                           id_param="id", attacker_id="8", victim_id="7")
    c.dispatch("verify")
    out = "\n".join(lines)
    assert "CONFIRMED" in out and "verified" in out.lower()  # verdict from the engine
    assert "received (" in out                               # token receipt confirmed (masked)


# ------------------------------------------------------------------ 2a: bystander / assert_owner_only / #7 labels
def _capturing_engine(**over):
    """A fake engine that RECORDS the kwargs of its last call (for asserting routing)."""
    cap = {}
    base = dict(
        status="completed", ai_verdict="verified", ai_verdict_raw="verified", guard_override=None,
        degraded_reason=None, caller_identity_anchor=None, payload_causality_anchor=None,
        state_jump_anchor=None, negative_assertion_anchor=None, anchoring_result=None,
        pre_flight_status=None, owner_view_corroborated=True, owner_view_status=None,
        owner_view_body=None, follow_up_response=None, follow_up_request=None,
        baseline={"response": {"status_code": 200}}, attack={"response": {"status_code": 200}})
    base.update(over)

    async def eng(**kw):
        cap.clear()
        cap.update(kw)
        return types.SimpleNamespace(**base)

    eng.captured = cap
    return eng


def _verify_target(tmp_path):
    (tmp_path / "s.json").write_text('{"openapi":"3.0.0","paths":{}}', encoding="utf-8")
    return tg.Target(name="t", base_url="http://localhost:8888", spec_path=str(tmp_path / "s.json"),
                     method="GET", path_template="/api/orders/{id}", id_location="path",
                     id_param="id", attacker_id="8", victim_id="7")


def test_verify_bystander_prompt_masked_and_routes_to_bystander_only(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    from backend.app.services.deep_verifier import OwnerCredential
    eng = _capturing_engine()
    # secret order: bystander, attacker, owner
    c, lines = _ctrl(tmp_path, monkeypatch,
                     secret=_scripted(["BYST-CANARY-999", "Bearer atk", "Bearer own"]), engine=eng)
    c.selected = _verify_target(tmp_path)
    c.dispatch("verify")
    out = "\n".join(lines)
    bys = eng.captured["bystander_credential"]
    assert isinstance(bys, OwnerCredential) and "BYST-CANARY-999" in bys.header_value  # -> bystander_credential
    assert "BYST-CANARY-999" not in str(eng.captured["auth_context"])                  # NEVER the attack path
    assert "BYST-CANARY-999" not in eng.captured["owner_credential"].header_value      # nor owner
    assert "BYST-CANARY-999" not in out                                                # masked, never echoed


def test_verify_assert_owner_only_yes_sets_op_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    eng = _capturing_engine()
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=_scripted(["y"]),   # assert=yes; account-labels="" -> no
                     secret=_scripted(["", "Bearer atk", "Bearer own"]), engine=eng)
    c.selected = _verify_target(tmp_path)
    c.dispatch("verify")
    assert eng.captured["assert_owner_only"] is True


def test_verify_defaults_are_byte_identical(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    eng = _capturing_engine()
    c, lines = _ctrl(tmp_path, monkeypatch, secret=_scripted(["", "Bearer atk", "Bearer own"]), engine=eng)
    c.selected = _verify_target(tmp_path)
    c.dispatch("verify")
    assert eng.captured["assert_owner_only"] is False          # default No
    assert eng.captured["bystander_credential"] is None        # blank bystander -> none (D30 off)


def test_verify_cli_selected_attacker_equals_owner_label_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    # both roles point at the SAME label -> the SAME config key -> the SAME token -> must be REFUSED.
    (tmp_path / "config.toml").write_text('TARGET_SAME_TOKEN = "identical-tok"\n', encoding="utf-8")
    (tmp_path / "s.json").write_text('{"openapi":"3.0.0","paths":{}}', encoding="utf-8")

    calls = {"n": 0}
    base = _fake_engine()

    async def eng(**kw):
        calls["n"] += 1
        return await base(**kw)

    # prompt: assert=n, use-labels=y, attacker label=SAME, owner label=SAME, bystander label=blank
    c, lines = _ctrl(tmp_path, monkeypatch,
                     prompt=_scripted(["n", "y", "SAME", "SAME", ""]),
                     secret=_scripted([""]), engine=eng)   # tokens come from config; only bystander prompt (blank)
    c.selected = tg.Target(name="t", base_url="http://localhost:8888", spec_path=str(tmp_path / "s.json"),
                           method="GET", path_template="/api/orders/{id}", id_location="path",
                           id_param="id", attacker_id="8", victim_id="7")
    c.dispatch("verify")
    out = "\n".join(lines)
    assert calls["n"] == 0                                  # REFUSED -> the engine NEVER ran (no verdict)
    assert "SAME identity" in out and "NOT DATA" in out     # the fail-closed guard fired via the CLI labels


def test_help_documents_the_new_capability_options(tmp_path, monkeypatch):
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.dispatch("help")
    out = "\n".join(lines).lower()
    assert "scan" in out
    assert "bystander" in out                               # discoverable without reading code
    assert "broken-for-all" in out and "account label" in out


# ------------------------------------------------------------------ THE confused-first-user walk (unit)
def test_confused_first_user_walk_every_error_caught_and_recovered(tmp_path, monkeypatch):
    """One session with several WRONG inputs — bad spec path, '2.5' model, the word
    'targets' in the login field, an out-of-range endpoint number — each caught, explained,
    and re-prompted, ending in a correctly-saved target. No silent failure, no crash."""
    monkeypatch.setattr(ConsoleController, "_refresh_settings", lambda self: None)
    spec = _spec(tmp_path)
    prompt = _scripted([
        # config: provider ok, model menu -> custom -> "2.5" (bad) -> valid
        "1", "3", "2.5", "gemini-2.5-pro",
        # target: name, url, BAD spec -> valid spec, BAD endpoint number -> valid, id-loc,
        #         ids, LOGIN word 'targets' (bad path) -> blank
        "crapi-orders", "http://localhost:8888",
        str(tmp_path / "nope.json"), spec,
        "9", "1",           # endpoint: 9 out of range -> re-prompt -> 1
        "1",                # id location -> path
        "8", "7",
        "targets", "",      # login: 'targets' is not a file -> re-prompt -> blank
    ])
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=prompt, secret=_scripted(["test-key"]))
    c.dispatch("config")
    c.dispatch("target")
    out = "\n".join(lines)
    # every wrong input produced a plain-language error + a re-prompt
    assert "doesn't look like a model id" in out
    assert "wasn't found" in out                             # bad spec path
    assert "number from the list" in out                     # out-of-range endpoint
    assert "login file wasn't found" in out                  # the 'targets' word
    # and the session still ended with a correct, saved target — bad login NEVER saved
    assert c.selected and c.selected.name == "crapi-orders"
    d = tomllib.loads((tmp_path / "targets" / "crapi-orders.toml").read_text(encoding="utf-8"))
    assert d["auth_spec_path"] == ""                         # 'targets' was rejected, not persisted


# ------------------------------------------------------------------ demo
def test_demo_no_key_guides_and_returns_2(monkeypatch, capsys):
    run = _load_cli_run()
    monkeypatch.setattr(settings, "LLM_API_KEY", None)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", None)
    called = {"confirm": 0}
    monkeypatch.setattr(run, "confirm", lambda *a, **k: called.__setitem__("confirm", 1) or 0)
    code = run.demo()
    assert code == 2 and called["confirm"] == 0             # guided, engine never invoked
    assert "needs an API key" in capsys.readouterr().err


def test_demo_with_key_renders_confirmed_tree(monkeypatch, capsys):
    run = _load_cli_run()
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr(run.vm, "_boot_target", lambda *a, **k: None)
    monkeypatch.setattr(run.vm, "_stop_target", lambda *a, **k: None)
    monkeypatch.setattr(run.vm, "_rm_db", lambda *a, **k: None)

    async def fake_run_one(case, cs, model, *a):
        return {"final_verdict": "verified", "ai_verdict": "verified", "status": "completed",
                "guard_override": "write_record_readback_decisive", "ground_truth": "REAL"}

    monkeypatch.setattr(run.vm, "_run_one", fake_run_one)
    code = run.demo()
    out = capsys.readouterr().out
    assert code == 1 and ("CONFIRMED" in out or "verified" in out.lower())


# ------------------------------------------------------------------ terminal safety (unchanged; first-class)
class _FakeTTY:
    def __init__(self, tty): self._tty = tty
    def isatty(self): return self._tty


def test_select_mode_text_on_non_tty():
    assert lz._select_mode(stdin=_FakeTTY(False), stdout=_FakeTTY(False), env={"TERM": "xterm"}) == "text"


def test_select_mode_tui_when_tty_and_prompt_toolkit_present():
    assert lz._select_mode(stdin=_FakeTTY(True), stdout=_FakeTTY(True), env={"TERM": "xterm"}) == "tui"


def test_select_mode_text_when_prompt_toolkit_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "prompt_toolkit", None)
    assert lz._select_mode(stdin=_FakeTTY(True), stdout=_FakeTTY(True), env={"TERM": "xterm"}) == "text"


def test_restore_terminal_resets_when_tty():
    class _S(io.StringIO):
        def isatty(self): return True
    s = _S()
    assert lz._restore_terminal(stream=s) is True
    assert "\x1b[?25h" in s.getvalue() and "\x1b[0m" in s.getvalue()


def test_restore_terminal_noop_when_not_tty():
    class _S(io.StringIO):
        def isatty(self): return False
    s = _S()
    assert lz._restore_terminal(stream=s) is False and s.getvalue() == ""


def test_ctrl_c_exits_clean_and_restores(monkeypatch):
    restored = []
    monkeypatch.setattr(lz, "_restore_terminal", lambda *a, **k: restored.append(True) or True)
    c = ConsoleController(prompt=lambda *_: "", secret_prompt=lambda *_: "",
                          echo=lambda *a: None, config_path="x")

    def kb():
        raise KeyboardInterrupt

    assert lz._guarded_run(c, kb, "text", None) == 130 and restored


def test_tui_exception_falls_back_to_text(monkeypatch):
    called = {"text": 0}

    def fake_make_text(engine=None):
        called["text"] += 1
        c = ConsoleController(prompt=lambda *_: "", secret_prompt=lambda *_: "",
                              echo=lambda *a: None, config_path="x")
        return c, (lambda: (_ for _ in ()).throw(EOFError()))

    monkeypatch.setattr(lz, "make_text_console", fake_make_text)
    monkeypatch.setattr(lz, "_restore_terminal", lambda *a, **k: True)
    c = ConsoleController(prompt=lambda *_: "", secret_prompt=lambda *_: "",
                          echo=lambda *a: None, config_path="x")

    def boom():
        raise RuntimeError("tui broke")

    assert lz._guarded_run(c, boom, "tui", None) == 0 and called["text"] == 1


# ------------------------------------------------------------------ display polish (#1,#2,#3,#9 + color)
def test_prompt_shows_example_before_input_blank_line_and_echoes_value(tmp_path, monkeypatch):
    # #3 example BEFORE the input cursor; #2 a blank line opens the block; #1 the entered value is echoed.
    events = []
    answers = iter(["mytarget"])

    def prm(label):
        events.append(("PROMPT", label))
        return next(answers, "")

    def ech(*a):
        events.append(("ECHO", " ".join(str(x) for x in a)))

    c = ConsoleController(prompt=prm, secret_prompt=lambda *a: "", echo=ech,
                          config_path=str(tmp_path / "c.toml"))
    c._ask_required("Target name", hint="A label to save and re-select this target.", example="crapi-orders")
    ex_i = next(i for i, (k, v) in enumerate(events) if k == "ECHO" and "example: crapi-orders" in v)
    pr_i = next(i for i, (k, v) in enumerate(events) if k == "PROMPT" and "Target name" in v)
    assert ex_i < pr_i                                           # #3: the example appears BEFORE the prompt
    assert events[0] == ("ECHO", "")                            # #2: a blank line opens the Q&A block
    assert any(k == "ECHO" and "-> mytarget" in v for k, v in events)   # #1: the entered value is echoed back


def test_optional_prompt_shows_skip_hint_and_color_degrades_to_plain(tmp_path, monkeypatch):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    lines = []
    c = ConsoleController(prompt=lambda *a: "", secret_prompt=lambda *a: "",
                          echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
                          config_path=str(tmp_path / "c.toml"))
    c._ask_optional_login_file("Login file", hint="OPTIONAL path to a login-declaration JSON.")
    out = "\n".join(lines)
    assert "press Enter to skip" in out                         # #9: optional prompts say how to skip
    assert "\033[" not in out                                   # color OFF (not a TTY) -> NO raw escape codes


def test_color_is_applied_when_forced(tmp_path, monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    lines = []
    c = ConsoleController(prompt=lambda *a: "", secret_prompt=lambda *a: "",
                          echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
                          config_path=str(tmp_path / "c.toml"))
    c._guide(hint="hello")
    assert any("\033[" in l for l in lines)                     # ANSI present when FORCE_COLOR set (degrades cleanly)


def test_env_token_value_is_never_echoed(tmp_path, monkeypatch):
    # #6 red line at the helper level: the env token VALUE never reaches output; only a masked receipt.
    lines = []
    c = ConsoleController(prompt=lambda *a: "", secret_prompt=lambda *a: "SHOULD-NOT-BE-USED",
                          echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
                          config_path=str(tmp_path / "c.toml"))
    c._environ = {"TARGET_ATTACKER_TOKEN": "super-secret-value"}
    got = c._env_or_secret("attacker", "Attacker token")
    assert got == "super-secret-value"                          # the value is returned to the caller
    out = "\n".join(lines)
    assert "super-secret-value" not in out                      # but NEVER echoed
    assert "from environment" in out and "TARGET_ATTACKER_TOKEN" in out   # masked receipt only
