# ==============================================================================
# Launcher — terminal detection + the "NEVER leave a broken terminal" guard.
#
# Mode select: TUI when we have a real TTY, a usable TERM (POSIX), and prompt_toolkit
# imports; otherwise TEXT. Any failure to build/run the TUI falls back to text or
# exits cleanly with a plain message. Ctrl+C / Ctrl+D / any exception restore the
# terminal (show cursor, reset SGR) and land the user at a normal prompt — never a
# hung, garbled, or cursor-hidden state. This is a first-class acceptance criterion.
# ==============================================================================
from __future__ import annotations

import os
import sys
from typing import Callable, Optional, Tuple

from backend.app.cli.console.controller import ConsoleController
from backend.app.cli.console.text_view import make_text_console


def _select_mode(stdin=None, stdout=None, env=None) -> str:
    """"tui" | "text". Text on: no TTY, dumb/empty TERM (POSIX), or no prompt_toolkit."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    env = env if env is not None else os.environ
    try:
        if not (stdin.isatty() and stdout.isatty()):
            return "text"
    except Exception:
        return "text"
    if os.name != "nt" and env.get("TERM", "").lower() in ("", "dumb"):
        return "text"
    try:
        import prompt_toolkit  # noqa: F401
    except Exception:
        return "text"
    return "tui"


def _restore_terminal(stream=None) -> bool:
    """Best-effort terminal reset: show cursor + reset SGR. Idempotent, never raises."""
    stream = stream if stream is not None else sys.stdout
    try:
        if stream.isatty():
            stream.write("\x1b[?25h\x1b[0m")     # DECTCEM show cursor + SGR reset
            stream.flush()
            return True
    except Exception:
        pass
    return False


def _repl(controller: ConsoleController, read_line: Callable[[], str]) -> None:
    """The command loop. read_line() raises EOFError/KeyboardInterrupt on Ctrl+D/Ctrl+C —
    both are caught by _guarded_run, which owns the clean exit + terminal restore."""
    controller.run_intro()
    while True:
        line = read_line()
        if not controller.dispatch(line):
            controller.echo("Goodbye.")
            break


def _make_tui_console(engine: Optional[Callable]) -> Tuple[ConsoleController, Callable[[], str]]:
    from backend.app.cli.console.tui_view import make_tui_console   # lazy: needs prompt_toolkit
    return make_tui_console(engine)


def _guarded_run(controller: ConsoleController, read_line: Callable[[], str],
                 mode: str, engine: Optional[Callable]) -> int:
    """Run the REPL with total terminal-state safety. Returns a process exit code."""
    try:
        _repl(controller, read_line)
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted - exiting.")
        return 130
    except EOFError:
        print()
        return 0
    except Exception as e:
        # A TUI that failed mid-run: restore, then fall back to text mode. A text-mode
        # failure exits cleanly with a plain message — never a garbled terminal.
        _restore_terminal()
        if mode == "tui":
            print(f"[console] the TUI could not run ({type(e).__name__}); switching to text mode.")
            c2, r2 = make_text_console(engine)
            return _guarded_run(c2, r2, "text", engine)
        print(f"[console] error: {type(e).__name__}: {e}")
        return 1
    finally:
        _restore_terminal()


def launch_console(*, engine: Optional[Callable] = None) -> int:
    """Entry point for `lanivist` with no args. Picks TUI or text and runs it safely."""
    try:
        mode = _select_mode()
        if mode == "tui":
            try:
                controller, read_line = _make_tui_console(engine)
            except Exception:
                mode = "text"
                controller, read_line = make_text_console(engine)
        else:
            controller, read_line = make_text_console(engine)
        return _guarded_run(controller, read_line, mode, engine)
    except KeyboardInterrupt:
        print("\nInterrupted - exiting.")
        return 130
    finally:
        _restore_terminal()
