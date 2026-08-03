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

from backend.app.cli import branding
from backend.app.cli.console.controller import ConsoleController
from backend.app.cli.console.intro import COMMANDS


def make_tui_console(engine: Optional[Callable] = None) -> Tuple[ConsoleController, Callable[[], str]]:
    session: PromptSession = PromptSession()
    completer = WordCompleter([c for c, _ in COMMANDS] + ["quit"], ignore_case=True)

    def _prompt(label: str) -> str:
        return session.prompt(label)

    def _secret(label: str) -> str:
        return session.prompt(label, is_password=True)     # masked, never echoed

    controller = ConsoleController(prompt=_prompt, secret_prompt=_secret, echo=print, engine=engine)
    prompt_str = f"{branding.command_name()}> "

    def read_line() -> str:
        return session.prompt(prompt_str, completer=completer)   # EOF/Ctrl+C bubble to launcher

    return controller, read_line
