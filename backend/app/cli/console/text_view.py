# ==============================================================================
# Text-mode console — the fallback (and the reference behavior). Pure stdlib:
# input() / getpass. Nothing to leave broken; input() restores nothing to corrupt.
# Returns (controller, read_line); the launcher runs the REPL and owns exit safety.
# ==============================================================================
from __future__ import annotations

import getpass
from typing import Callable, Optional, Tuple

from backend.app.cli import branding
from backend.app.cli.console.controller import ConsoleController


def make_text_console(engine: Optional[Callable] = None) -> Tuple[ConsoleController, Callable[[], str]]:
    controller = ConsoleController(
        prompt=input, secret_prompt=getpass.getpass, echo=print, engine=engine,
    )
    prompt_str = f"{branding.command_name()}> "

    def read_line() -> str:
        return input(prompt_str)          # EOFError / KeyboardInterrupt bubble to the launcher

    return controller, read_line
