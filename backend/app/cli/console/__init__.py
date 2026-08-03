# ==============================================================================
# Interactive console for Lanivist — the "download, configure, use" front door.
#
# A PRESENTATION LAYER only. `lanivist` with no args opens this console; it wraps the
# EXISTING machinery (run_external_verify, the config flow, confirm_render) and does
# NOT touch the engine, verdict logic, four channels, guard, D24, D19,
# fuzzer._differential_verdict, or scope.py enforcement. The verdict still comes only
# from the engine — this layer structurally cannot manufacture `verified`.
#
# Structure (controller/view split, so the logic is testable and the shell is
# throwaway-if-wrong):
#   controller.py  — all logic, I/O injected (the config_flow pattern)
#   targets.py     — named reusable targets (NON-SECRET fields only; tokens never on disk)
#   intro.py       — calm, honest intro + command list (no rejected styling)
#   text_view.py   — stdlib text-mode console (the fallback + reference behavior)
#   tui_view.py    — prompt_toolkit console (line-oriented; masked input)
#   launcher.py    — terminal detection + the "never leave a broken terminal" guard
# ==============================================================================
from backend.app.cli.console.launcher import launch_console

__all__ = ["launch_console"]
