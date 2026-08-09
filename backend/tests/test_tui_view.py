# ==============================================================================
# TUI view — the "masked input sticks after a secret prompt" fix. On the installed prompt_toolkit,
# `is_password=True` PERSISTS on a PromptSession, so a single shared session leaked masking onto the NEXT
# prompt after a hidden token entry (the `lanivist>` command, a later field) — rendering it as `****`.
# The fix gives masked input its OWN session and passes is_password=False explicitly on the main session.
#
# This test pins the KWARG CONTRACT offline (Linux-verifiable) — it does NOT rely on a real TTY. The
# actual "quit echoes normally on Windows PowerShell" is a runtime check owned by the director.
# ==============================================================================
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)


def test_masked_input_never_leaks_to_command_or_field_prompts(monkeypatch):
    import backend.app.cli.console.tui_view as tui

    class _FakeSession:
        made = []                                # every PromptSession created, in order

        def __init__(self, *a, **k):
            self.pw_calls = []                   # is_password recorded per .prompt() call
            _FakeSession.made.append(self)

        def prompt(self, label="", *, is_password=False, **kw):
            self.pw_calls.append(is_password)
            return "typed"

    monkeypatch.setattr(tui, "PromptSession", _FakeSession)

    controller, read_line = tui.make_tui_console()
    main_session, secret_session = _FakeSession.made         # order: session, then secret_session
    assert main_session is not secret_session                # masked input is on a DEDICATED session

    # Replay the exact transcript order that exposed the bug: a masked token, THEN the next command at
    # `lanivist>`, THEN a later normal field in the same flow.
    controller.secret_prompt("Attacker token (input hidden): ")   # _secret  -> masked
    read_line()                                                   # the `lanivist>` command (e.g. quit)
    controller.prompt("Owner id: ")                               # a later normal field

    # (a) the secret path STILL masks (is_password=True intact) — and only on the dedicated session.
    assert secret_session.pw_calls == [True]

    # (b) every main-session call (command + field) after the secret is UNMASKED, and the main session was
    #     NEVER handed is_password=True — so masking can never leak onto it.
    assert main_session.pw_calls == [False, False]
    assert True not in main_session.pw_calls
