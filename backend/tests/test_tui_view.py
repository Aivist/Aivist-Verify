# ==============================================================================
# TUI view — two view-layer contracts pinned offline (Linux-verifiable; no real TTY needed):
#
#  1. MASKING (prior commit): `is_password=True` PERSISTS on a prompt_toolkit PromptSession, so a shared
#     session leaked masking onto the NEXT prompt after a hidden token entry (`lanivist>`, later fields
#     rendered `****`). Masked input has its OWN session; the main session is never masked.
#  2. ANSI WRAP (this commit): the controller paints labels with raw ANSI SGR codes, and prompt_toolkit
#     renders a raw `str` message LITERALLY (it does not interpret embedded ANSI), so on conhost the codes
#     leak as visible `^[[36m`. Every message must be wrapped in prompt_toolkit's ANSI() so the SGR is
#     PARSED (not leaked). Safe when the painter is off: ANSI(plain) renders the plain text unchanged.
#
# The runtime proof (labels actually render as COLOR on real Windows PowerShell) is the operator's; this
# test only pins that ANSI() is applied and that masking is not regressed.
# ==============================================================================
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from prompt_toolkit.formatted_text import ANSI


def test_tui_wraps_every_prompt_in_ansi_and_keeps_masking_isolated(monkeypatch):
    import backend.app.cli.console.tui_view as tui

    class _FakeSession:
        made = []                                # every PromptSession created, in order

        def __init__(self, *a, **k):
            self.pw_calls = []                   # is_password recorded per .prompt() call
            self.messages = []                   # the message arg recorded per .prompt() call
            _FakeSession.made.append(self)

        def prompt(self, message="", *, is_password=False, **kw):
            self.pw_calls.append(is_password)
            self.messages.append(message)
            return "typed"

    monkeypatch.setattr(tui, "PromptSession", _FakeSession)

    controller, read_line = tui.make_tui_console()
    main_session, secret_session = _FakeSession.made         # order: session, then secret_session
    assert main_session is not secret_session                # masked input on a DEDICATED session

    # Replay the transcript order that exposed both bugs: a masked token, THEN the next command at
    # `lanivist>`, THEN a later normal field in the same flow.
    controller.secret_prompt("Attacker token (input hidden): ")   # _secret  -> masked
    read_line()                                                   # the `lanivist>` command (e.g. quit)
    controller.prompt("Owner id: ")                               # a later normal field

    # (1) ANSI WRAP: EVERY message handed to prompt_toolkit is an ANSI instance (never a raw str), so no
    #     literal `^[[` can leak on conhost.
    for sess in (main_session, secret_session):
        assert sess.messages, "expected at least one prompt call"
        assert all(isinstance(m, ANSI) for m in sess.messages)
        assert all(not isinstance(m, str) for m in sess.messages)

    # (2) MASKING intact (not regressed): the secret path masks on its OWN session; the main session's
    #     command + field calls are UNMASKED, and it was NEVER handed is_password=True.
    assert secret_session.pw_calls == [True]
    assert main_session.pw_calls == [False, False]
    assert True not in main_session.pw_calls
