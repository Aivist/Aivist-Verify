# ==============================================================================
# Bug A (real-path) — ANSI color must DEGRADE to plain, never leak raw '\033[..' bytes.
# The earlier unit test only checked the piped case; it missed that a real Windows console has VT
# processing OFF by default (mode 0x0003), so emitting ANSI without enabling VT leaks the raw codes.
# These tests drive the ACTUAL degrade decision (a captured child process; a TTY whose VT can't be
# enabled), not a mock that assumes VT.
# ==============================================================================
import os
import sys
import subprocess

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)


def test_captured_piped_output_has_zero_raw_ansi():
    """A child process paints text with stdout PIPED (how a captured / non-VT console sees it). The
    captured bytes must contain NO raw '\\x1b[' sequence — plain text, not leaked escape codes."""
    child = (
        "import sys;"
        "sys.path.insert(0, r'" + _REPO_ROOT + "');"
        "from backend.app.cli.confirm_render import _painter;"
        "p=_painter(None);"
        "sys.stdout.write(p('CONFIRMED','red','bold')+chr(10)+p('dim','dim'))"
    )
    out = subprocess.run([sys.executable, "-c", child], capture_output=True).stdout
    assert b"\x1b[" not in out and b"CONFIRMED" in out          # painted, but PLAIN


def test_supports_color_plain_on_tty_when_vt_cannot_be_enabled(monkeypatch):
    """The director's console: a real TTY whose VT mode cannot be enabled MUST degrade to plain (the
    old isatty-only helper returned True here and leaked). Exercises the real _supports_color decision."""
    import backend.app.cli.confirm_render as cr
    monkeypatch.setattr(cr.sys, "platform", "win32")
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setattr(cr.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cr, "_windows_vt_enabled", lambda: False)      # console can't enable VT
    assert cr._supports_color() is False
    painted = cr._painter(None)("X", "cyan", "bold")
    assert painted == "X" and "\033[" not in painted                  # plain, zero escape bytes


def test_supports_color_on_when_vt_is_enableable(monkeypatch):
    import backend.app.cli.confirm_render as cr
    monkeypatch.setattr(cr.sys, "platform", "win32")
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setattr(cr.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cr, "_windows_vt_enabled", lambda: True)       # VT enabled + confirmed
    assert cr._supports_color() is True


def test_supports_color_plain_on_no_color_and_non_tty(monkeypatch):
    import backend.app.cli.confirm_render as cr
    monkeypatch.setenv("NO_COLOR", "1")
    assert cr._supports_color() is False                              # NO_COLOR -> plain
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setattr(cr.sys.stdout, "isatty", lambda: False, raising=False)
    assert cr._supports_color() is False                             # non-TTY -> plain


def test_windows_vt_enabled_is_a_bool_and_never_raises():
    from backend.app.cli.confirm_render import _windows_vt_enabled
    assert isinstance(_windows_vt_enabled(), bool)                    # smoke on the real ctypes path
