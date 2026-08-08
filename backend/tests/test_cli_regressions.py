# ==============================================================================
# CLI EXPERIENCE/DISCOVERY regression fixes (director hands-on run). ALL are experience-layer — NO
# verdict/engine change. Covers:
#   #1 color degrades to PLAIN on non-ANSI (no raw '\033[' leak); NO_COLOR / non-TTY -> plain.
#   #2 owner + bystander tokens read from the ENV (masked, message), like attacker.
#   #3 required-CHOICE framing: spec/traffic/endpoints all empty -> a clear "provide one of..." message.
#   #4 guidance (example) shown BEFORE the input, inline at the token prompts.
#   #5 a mistyped token can be re-entered from the scan review (no restart).
#   #6 ANY {templated} path segment (e.g. {book_title}) is an accepted candidate; 0-candidates ->
#      suggest `verify`.
# Offline: no network, provider stubbed, engine faked (reused from test_scan_run).
# ==============================================================================
import os
import sys
import json

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from pydantic import SecretStr

from backend.app.core.config import settings
from backend.app.cli.console.controller import ConsoleController
from backend.tests.test_scan_run import _SPEC, _CANDS, _ID_MAP, _ScriptedEngine, _stub_provider, _prompts


def _ctl(tmp_path, lines, prompt, secret=None, **kw):
    return ConsoleController(
        prompt=prompt, secret_prompt=secret or _prompts(),
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        config_path=str(tmp_path / "no-config.toml"), **kw)


# ------------------------------------------------------------------ #1 COLOR
def test_supports_color_false_on_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    from backend.app.cli.confirm_render import _supports_color
    assert _supports_color() is False


def test_supports_color_false_when_not_a_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    from backend.app.cli.confirm_render import _supports_color
    assert _supports_color() is False               # pytest captures stdout -> not a TTY -> plain


def test_prompts_are_plain_with_zero_raw_escape_codes(tmp_path, monkeypatch):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    lines = []
    c = _ctl(tmp_path, lines, prompt=lambda *a: "")
    c._guide(hint="pick the endpoint", example="/orders/{id}", why="it carries an object id")
    out = "\n".join(lines)
    assert "pick the endpoint" in out and "/orders/{id}" in out
    assert "\033[" not in out and "\x1b[" not in out   # PLAIN — never the raw codes


# ------------------------------------------------------------------ #2 env owner/bystander (masked)
def test_owner_read_from_env_masked_with_message(monkeypatch):
    monkeypatch.setenv("TARGET_ATTACKER_TOKEN", "atk-SECRET")
    monkeypatch.setenv("TARGET_OWNER_TOKEN", "own-SECRET")
    from backend.app.cli.external_verify import _resolve_tokens

    def _no_prompt(_p):
        raise AssertionError("should NOT prompt when env tokens are set")

    lines = []
    a, o = _resolve_tokens("/no/config.toml", _no_prompt,
                           echo=lambda *x: lines.append(" ".join(str(y) for y in x)))
    assert a.get_secret_value() == "atk-SECRET" and o.get_secret_value() == "own-SECRET"
    out = "\n".join(lines)
    assert "Using attacker token from environment" in out and "Using owner token from environment" in out
    assert "atk-SECRET" not in out and "own-SECRET" not in out   # masked — value never printed


def test_bystander_read_from_env_masked_with_message(monkeypatch):
    monkeypatch.setenv("TARGET_BYSTANDER_TOKEN", "byst-SECRET")
    from backend.app.cli.external_verify import _resolve_bystander_token
    lines = []
    b = _resolve_bystander_token("/no/config.toml",
                                 echo=lambda *x: lines.append(" ".join(str(y) for y in x)))
    assert b is not None and b.get_secret_value() == "byst-SECRET"
    out = "\n".join(lines)
    assert "Using bystander token from environment" in out and "byst-SECRET" not in out


def test_attacker_owner_collision_still_refused(monkeypatch):
    # RED LINE unchanged: same attacker==owner is refused BEFORE any verdict (per-account guard intact).
    from backend.app.cli.external_verify import _identity_collision_reason
    assert _identity_collision_reason("same-tok", "same-tok", None)          # collision -> truthy reason
    assert not _identity_collision_reason("atk", "own", "byst")              # distinct -> allowed


# ------------------------------------------------------------------ #4 example BEFORE input (inline)
def test_verify_token_prompts_carry_inline_example(monkeypatch):
    monkeypatch.delenv("TARGET_ATTACKER_TOKEN", raising=False)
    monkeypatch.delenv("TARGET_OWNER_TOKEN", raising=False)
    from backend.app.cli.external_verify import _resolve_tokens
    seen = []

    def ps(prompt):
        seen.append(prompt)
        return "tok"

    _resolve_tokens("/no/config.toml", ps)
    assert any("e.g." in p and "Bearer" in p for p in seen)   # example shown AT/BEFORE the input (#4)


# ------------------------------------------------------------------ #3 required-choice framing
def test_scan_required_choice_all_empty_message(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    from backend.app.cli.console import targets as tmod
    sel = tmod.Target(name="specless", base_url="http://127.0.0.1:5000", spec_path="", method="GET",
                      path_template="/books/v1/{book_title}", id_location="path", id_param="book_title",
                      attacker_id="a", victim_id="b")
    lines = []
    c = _ctl(tmp_path, lines, prompt=_prompts("", ""))    # traffic blank, endpoints blank
    c.selected = sel
    c.do_scan()
    out = "\n".join(lines)
    assert "Provide ONE source" in out                              # required-choice preamble
    assert "You must provide one of" in out                         # clear message (not "nothing to scan")


# ------------------------------------------------------------------ #5 re-enter tokens from review
def test_scan_review_can_reenter_tokens(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")
    monkeypatch.setenv("TARGET_ATTACKER_TOKEN", "atk-tok")
    monkeypatch.setenv("TARGET_OWNER_TOKEN", "own-tok")
    monkeypatch.setenv("TARGET_BYSTANDER_TOKEN", "byst-tok")
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_SPEC), encoding="utf-8")
    ids_path = tmp_path / "ids.json"
    ids_path.write_text(json.dumps({"ids": _ID_MAP}), encoding="utf-8")
    from backend.app.cli.console import targets as tmod
    sel = tmod.Target(name="t", base_url="http://localhost:8888", spec_path=str(spec_path), method="GET",
                      path_template="/api/reports/{report_id}", id_location="path", id_param="report_id",
                      attacker_id="1", victim_id="2")
    lines = []
    # prompts: id-hints file, login(blank), assert(blank/no), review->"3" (re-enter), review->"" (run)
    c = _ctl(tmp_path, lines, prompt=_prompts(str(ids_path), "", "", "3", ""),
             engine=_ScriptedEngine(), scan_provider_factory=_stub_provider(_CANDS))
    c.selected = sel
    c.do_scan()
    out = "\n".join(lines)
    assert "re-enter tokens" in out.lower()          # the review offers the correction (#5)
    assert "Tokens updated." in out                  # the re-entry succeeded
    assert "scan report:" in out                     # and the scan still ran with the re-entered tokens
    assert "atk-tok" not in out and "own-tok" not in out and "byst-tok" not in out   # never printed


# ------------------------------------------------------------------ #6 non-numeric templated id proposed
def test_book_title_templated_endpoint_is_accepted_candidate():
    from backend.app.cli.scan_discovery import discover_candidate_parts
    catalog = ["GET /books/v1/{book_title}"]
    raw = [{"method": "GET", "path_template": "/books/v1/{book_title}",
            "id_location": "path", "id_param": "book_title"}]
    accepted, dropped = discover_candidate_parts(catalog, raw)
    assert len(accepted) == 1 and dropped == []                     # accepted > 0 (fence does not require numeric)
    assert accepted[0]["id_param"] == "book_title" and accepted[0]["shape"] == "path_segment_bola"


def test_discovery_prompt_broadened_to_any_templated_segment():
    from backend.app.cli.scan_discovery import _DISCOVERY_SYSTEM_PROMPT as P
    assert "book_title" in P and "numeric" in P.lower()             # explicitly says id need not be numeric


def test_no_candidates_report_suggests_verify_for_templated_endpoint():
    from backend.app.cli.scan_report import _no_candidates_report
    templated = _no_candidates_report(["GET /books/v1/{book_title}"], accepted=[], dropped=[])
    assert "verify" in templated.lower()                            # suggests testing it directly
    plain = _no_candidates_report(["GET /health"], accepted=[], dropped=[])
    assert "run `verify`" not in plain                              # not suggested when there's no templated id
