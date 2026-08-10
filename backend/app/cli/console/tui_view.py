# ==============================================================================
# prompt_toolkit console — mature, cross-platform, strong on Windows Terminal AND
# classic conhost. LINE-ORIENTED (no alt-screen), which is the safest choice for
# terminal restoration. Masked input via is_password=True. Returns (controller,
# read_line); the launcher runs the REPL and owns exit safety.
#
# prompt_toolkit is imported at MODULE level, so this module is imported LAZILY by
# the launcher (only when the TUI mode is selected) — the text fallback never needs
# prompt_toolkit installed.
# ==============================================================================
from __future__ import annotations

from typing import Callable, Optional, Tuple

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import ANSI

from backend.app.cli import branding
from backend.app.cli.console.controller import ConsoleController
from backend.app.cli.console.intro import COMMANDS


def make_tui_console(engine: Optional[Callable] = None) -> Tuple[ConsoleController, Callable[[], str]]:
    # TWO sessions on purpose: `is_password=True` PERSISTS on a prompt_toolkit session, so a single
    # shared session leaks masking onto the NEXT prompt (the `aivist>` command, a later field) after a
    # masked token entry — rendering it as `****`. Masked input gets its OWN session; the main session is
    # NEVER masked (and every main call passes is_password=False explicitly, belt-and-suspenders).
    session: PromptSession = PromptSession()          # commands + normal fields, NEVER masked
    secret_session: PromptSession = PromptSession()   # masked input ONLY
    completer = WordCompleter([c for c, _ in COMMANDS] + ["quit"], ignore_case=True)

    # The controller paints labels with raw ANSI SGR codes. prompt_toolkit renders a raw `str` message
    # LITERALLY (it does NOT interpret embedded ANSI), so on conhost the codes leak as visible `^[[36m`.
    # Wrap every message in ANSI() so prompt_toolkit PARSES the SGR. Safe when the painter is off
    # (NO_COLOR / non-TTY): the label is already plain and ANSI(plain) renders it unchanged.
    def _prompt(label: str) -> str:
        return session.prompt(ANSI(label), is_password=False)

    def _secret(label: str) -> str:
        return secret_session.prompt(ANSI(label), is_password=True)   # masked, never echoed; isolated session

    controller = ConsoleController(prompt=_prompt, secret_prompt=_secret, echo=print, engine=engine)
    prompt_str = f"{branding.command_name()}> "

    def read_line() -> str:
        return session.prompt(ANSI(prompt_str), completer=completer, is_password=False)  # EOF/Ctrl+C -> launcher

    return controller, read_line
