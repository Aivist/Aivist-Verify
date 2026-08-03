# ==============================================================================
# Offline tests for the interactive console (backend/app/cli/console/*). Zero API,
# no real terminal: I/O is injected, the engine is a fake. Proves the plumbing —
# help/config/target/targets/status/verify, credential redaction, the non-secret
# target file, and (first-class) the terminal-safety paths: mode select, TUI->text
# fallback, Ctrl+C clean exit, and terminal restore. The lived experience is proven
# by the director's live walk-through, not here.
# ==============================================================================
import io
import os
import sys
import types
import tomllib

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
def _scripted(answers):
    it = iter(answers)
    return lambda *_a: next(it, "")


def _ctrl(tmp_path, monkeypatch, *, prompt=None, secret=None, engine=None):
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))   # targets under tmp/targets
    lines = []
    c = ConsoleController(
        prompt=prompt or _scripted([]), secret_prompt=secret or _scripted([]),
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        config_path=str(tmp_path / "config.toml"), engine=engine,
    )
    return c, lines


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


# ------------------------------------------------------------------ commands
def test_help_lists_all_commands(tmp_path, monkeypatch):
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.dispatch("help")
    out = "\n".join(lines)
    for cmd in ("help", "config", "target", "targets", "verify", "status", "quit"):
        assert cmd in out


def test_quit_returns_false(tmp_path, monkeypatch):
    c, _ = _ctrl(tmp_path, monkeypatch)
    assert c.dispatch("quit") is False
    assert c.dispatch("help") is True


def test_config_writes_file_and_redacts_key(tmp_path, monkeypatch):
    # config screen reuses run_config_flow; refresh is a same-session settings reload —
    # patched out here so the test stays hermetic (verified live by the director instead).
    monkeypatch.setattr(ConsoleController, "_refresh_settings", lambda self: None)
    c, lines = _ctrl(tmp_path, monkeypatch,
                     prompt=_scripted(["gemini", "gemini-2.5-pro"]),
                     secret=_scripted(["SECRET-KEY-CANARY"]))
    c.dispatch("config")
    cfg = tmp_path / "config.toml"
    assert cfg.exists()
    data = tomllib.loads(cfg.read_text(encoding="utf-8"))
    assert data.get("LLM_API_KEY") == "SECRET-KEY-CANARY"        # written to the 0600 file
    assert "SECRET-KEY-CANARY" not in "\n".join(lines)           # NEVER echoed


def test_status_redacts_key(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("STATUS-KEY-CANARY"))
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.dispatch("status")
    out = "\n".join(lines)
    assert "set (redacted)" in out
    assert "STATUS-KEY-CANARY" not in out


def test_target_save_selects_and_stores_no_tokens(tmp_path, monkeypatch):
    # spec path doesn't exist -> _pick_endpoint falls back to manual method/path entry.
    prompts = _scripted([
        "crapi-orders", "http://localhost:8888", str(tmp_path / "nospec.json"),
        "GET", "/workshop/api/shop/orders/{order_id}",     # manual endpoint
        "path", "", "8", "7", "",                          # location, id_param(default), ids, auth
    ])
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=prompts)
    c.dispatch("target")
    assert c.selected and c.selected.name == "crapi-orders"
    # persisted, with NO credential field on disk
    tfile = tmp_path / "targets" / "crapi-orders.toml"
    assert tfile.exists()
    d = tomllib.loads(tfile.read_text(encoding="utf-8"))
    assert d["attacker_id"] == "8" and d["id_param"] == "order_id"
    assert not any("token" in k.lower() or "password" in k.lower() for k in d)
    # op assembly is correct (path shape)
    op = c.selected.to_op()
    assert op["baseline_path"] == "/workshop/api/shop/orders/8"
    assert op["payload"] == {"location": "path_segment", "target_param": "8",
                             "payload_string": "7", "type": "BOLA"}


def test_targets_list_and_select(tmp_path, monkeypatch):
    monkeypatch.setattr(branding, "config_dir", lambda: str(tmp_path))
    tg.save_target(tg.Target(name="alpha", base_url="http://localhost:8888", spec_path="",
                             method="GET", path_template="/a/{id}", id_location="path",
                             id_param="id", attacker_id="1", victim_id="2"))
    c, lines = _ctrl(tmp_path, monkeypatch, prompt=_scripted(["1"]))
    c.dispatch("targets")
    out = "\n".join(lines)
    assert "alpha" in out
    assert c.selected and c.selected.name == "alpha"


def test_target_query_location_builds_query_op():
    t = tg.Target(name="m", base_url="http://localhost:8888", spec_path="", method="GET",
                  path_template="/workshop/api/mechanic/mechanic_report", id_location="query",
                  id_param="report_id", attacker_id="7", victim_id="6")
    op = t.to_op()
    assert op["baseline_path"] == "/workshop/api/mechanic/mechanic_report?report_id=7"
    assert op["payload"] == {"location": "query_param", "target_param": "report_id",
                             "payload_string": "6", "type": "BOLA"}


def test_verify_without_selected_target(tmp_path, monkeypatch):
    c, lines = _ctrl(tmp_path, monkeypatch)
    c.dispatch("verify")
    assert "No target selected" in "\n".join(lines)


def test_verify_runs_external_verify_and_renders_engine_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)   # restored at teardown
    (tmp_path / "s.json").write_text('{"openapi":"3.0.0","paths":{}}', encoding="utf-8")
    c, lines = _ctrl(tmp_path, monkeypatch, secret=_scripted(["atk", "own"]),
                     engine=_fake_engine())
    c.selected = tg.Target(name="t", base_url="http://localhost:8888", spec_path=str(tmp_path / "s.json"),
                           method="GET", path_template="/api/orders/{id}", id_location="path",
                           id_param="id", attacker_id="8", victim_id="7")
    c.dispatch("verify")
    out = "\n".join(lines)
    assert "CONFIRMED" in out and "verified" in out.lower()          # verdict came from the engine


# ------------------------------------------------------------------ terminal safety (first-class)
class _FakeTTY:
    def __init__(self, tty): self._tty = tty
    def isatty(self): return self._tty


def test_select_mode_text_on_non_tty():
    assert lz._select_mode(stdin=_FakeTTY(False), stdout=_FakeTTY(False), env={"TERM": "xterm"}) == "text"


def test_select_mode_tui_when_tty_and_prompt_toolkit_present():
    assert lz._select_mode(stdin=_FakeTTY(True), stdout=_FakeTTY(True), env={"TERM": "xterm"}) == "tui"


def test_select_mode_text_when_prompt_toolkit_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "prompt_toolkit", None)          # import prompt_toolkit -> ImportError
    assert lz._select_mode(stdin=_FakeTTY(True), stdout=_FakeTTY(True), env={"TERM": "xterm"}) == "text"


def test_restore_terminal_resets_when_tty():
    class _S(io.StringIO):
        def isatty(self): return True
    s = _S()
    assert lz._restore_terminal(stream=s) is True
    assert "\x1b[?25h" in s.getvalue() and "\x1b[0m" in s.getvalue()   # show cursor + reset SGR


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

    code = lz._guarded_run(c, kb, "text", None)
    assert code == 130 and restored                                   # clean exit + terminal restored


def test_eof_exits_clean(monkeypatch):
    monkeypatch.setattr(lz, "_restore_terminal", lambda *a, **k: True)
    c = ConsoleController(prompt=lambda *_: "", secret_prompt=lambda *_: "",
                          echo=lambda *a: None, config_path="x")

    def eof():
        raise EOFError

    assert lz._guarded_run(c, eof, "text", None) == 0


def test_tui_exception_falls_back_to_text(monkeypatch):
    called = {"text": 0}

    def fake_make_text(engine=None):
        called["text"] += 1
        c = ConsoleController(prompt=lambda *_: "", secret_prompt=lambda *_: "",
                              echo=lambda *a: None, config_path="x")
        return c, (lambda: (_ for _ in ()).throw(EOFError()))         # clean exit on the fallback

    monkeypatch.setattr(lz, "make_text_console", fake_make_text)
    monkeypatch.setattr(lz, "_restore_terminal", lambda *a, **k: True)
    c = ConsoleController(prompt=lambda *_: "", secret_prompt=lambda *_: "",
                          echo=lambda *a: None, config_path="x")

    def boom():
        raise RuntimeError("tui broke")

    code = lz._guarded_run(c, boom, "tui", None)
    assert called["text"] == 1 and code == 0                          # fell back to text, exited cleanly
