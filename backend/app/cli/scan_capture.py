# ==============================================================================
# scan — HEAVY passive discovery, version B: CLI-native LIVE proxy capture -> the LIGHT loader -> scan.
#
# A SHORT-LIVED, SYNCHRONOUS mitmdump spawner for the CLI. It starts mitmdump (scoped to the target)
# writing captured requests to a temp FILE via capture_addon.py, tells the user to proxy their traffic
# through it, and on stop tears the subprocess down CLEANLY and hands the flow file to the LIGHT loader
# (scan_traffic.endpoints_from_traffic_file) -> the existing scan.
#
# It deliberately does NOT drive the async ProxyManager / ingest pipeline / WriterService / SQLite /
# SSE — flows land in a FILE, nothing routes through the web stack. It DOES mirror ProxyManager's
# hard-won subprocess discipline (see proxy_manager.py): a new process GROUP at spawn + an OS-agnostic
# process-tree kill at teardown (Windows `taskkill /F /T`, POSIX `killpg`) so NO mitmdump child is ever
# orphaned and the listen port is never leaked; plus boot-grace failure detection.
#
# NO verdict/engine change. Direction-safe: it only produces endpoints for the existing judge. SECRETS:
# the addon writes only method/host/path (never auth/cookies/body); the temp flow file lives OUTSIDE
# the repo and is removed after the scan.
# ==============================================================================
from __future__ import annotations

import os
import re
import sys
import signal
import shutil
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, List, Mapping, Optional

from backend.app.core.config import settings

logger = logging.getLogger("app.cli.scan_capture")

# Discipline constants mirror proxy_manager (kept in step with it — one documented source of the pattern).
_BOOT_GRACE_SECONDS = 1.5
_STOP_GRACE_SECONDS = 4.0
_CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


class CaptureError(RuntimeError):
    """mitmdump could not be found / failed to boot. Carries an ACTIONABLE message; the CLI turns it
    into a clear '[NOT DATA]' line, never a crash."""


def _addon_path() -> str:
    return str(Path(__file__).resolve().parent.parent / "proxy" / "capture_addon.py")


def _repo_root() -> str:
    # backend/app/cli/scan_capture.py -> parents[3] is the repo root (so the addon can import backend.*)
    return str(Path(__file__).resolve().parents[3])


def _resolve_mitmdump(override: Optional[List[str]]) -> List[str]:
    """The command PREFIX to run mitmdump: an explicit override (tests inject a fake), else
    settings.MITMDUMP_PATH, else `mitmdump` on PATH. Raises CaptureError (actionable) when not found —
    the 'mitmproxy not installed' path, surfaced clearly instead of crashing."""
    if override:
        return list(override)
    if settings.MITMDUMP_PATH:
        if os.path.isfile(settings.MITMDUMP_PATH):
            return [settings.MITMDUMP_PATH]
        raise CaptureError(f"MITMDUMP_PATH is set but is not a file: {settings.MITMDUMP_PATH}")
    found = shutil.which("mitmdump")
    if not found:
        raise CaptureError(
            "mitmproxy (mitmdump) is not installed or not on PATH. Install it with "
            "'pip install mitmproxy' (or 'brew install mitmproxy'), or set MITMDUMP_PATH, then retry.")
    return [found]


def _ca_cert_hint() -> str:
    """Reuse ProxyManager's CA-cert location discipline (a pure @staticmethod) WITHOUT starting its
    async lifecycle, so the HTTPS-trust instructions point at the real cert when it exists."""
    try:
        from backend.app.services.proxy_manager import ProxyManager
        cert = ProxyManager.ca_cert_path()
    except Exception:
        cert = None
    if cert is not None:
        return (f"For HTTPS, trust the mitmproxy CA once (cert: {cert}) — import it into your OS/browser "
                "trust store. Docs: https://docs.mitmproxy.org/stable/concepts-certificates/")
    return ("For HTTPS, the mitmproxy CA is generated on first run — then browse to http://mitm.it "
            "THROUGH the proxy to download + trust it. "
            "Docs: https://docs.mitmproxy.org/stable/concepts-certificates/")


def _target_scope(base_url: str) -> str:
    """The target origin declaration ('host' or 'host:port') — the SAME string the LIGHT loader and the
    engine lock scope to (external_verify._approved_host)."""
    from backend.app.cli.external_verify import _approved_host
    return _approved_host(base_url)


def _build_command(mitmdump: List[str], port: int, scope: str) -> List[str]:
    """mitmdump command: local-only listener, our capture addon, and `--allow-hosts <host>` so mitmdump
    does not needlessly intercept unrelated hosts (belt to the addon + loader scope drops). The host
    regex is derived from the scope's host part; port precision stays with the addon/loader."""
    host = scope.rsplit(":", 1)[0] if ":" in scope else scope
    cmd = list(mitmdump) + [
        "-q",                                # quiet; we do not parse stdout
        "--listen-host", "127.0.0.1",        # local-only proxy surface
        "--listen-port", str(port),
        "--ssl-insecure",                    # don't choke on upstream certs
    ]
    if host:
        cmd += ["--allow-hosts", re.escape(host)]
    cmd += ["-s", _addon_path()]
    return cmd


def _child_env(flow_file: str, scope: str, env_extra: Optional[Mapping[str, str]]) -> dict:
    env = os.environ.copy()
    env["CAPTURE_FLOW_FILE"] = flow_file
    env["CAPTURE_SCOPE"] = scope
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [_repo_root(), env.get("PYTHONPATH", "")]))
    if env_extra:
        env.update({str(k): str(v) for k, v in env_extra.items()})
    return env


def _kill_tree(proc: "subprocess.Popen") -> None:
    """OS-agnostic forced termination of mitmdump AND any children it spawned (mirrors
    ProxyManager._kill_tree, synchronous). Windows: `taskkill /F /T` kills the whole tree; POSIX:
    signal the process GROUP (start_new_session gave the child its own group). Idempotent / never raises
    — so NO orphaned proxy and NO leaked listen port survive a stop."""
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=_STOP_GRACE_SECONDS)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    else:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=_STOP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    try:
        proc.wait(timeout=_STOP_GRACE_SECONDS)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def capture_to_file(
    base_url: str, flow_file: str, *,
    listen_port: int,
    duration: Optional[float] = None,
    wait_for_stop: Optional[Callable[[], Any]] = None,
    mitmdump_cmd: Optional[List[str]] = None,
    boot_grace: float = _BOOT_GRACE_SECONDS,
    env_extra: Optional[Mapping[str, str]] = None,
    echo: Callable[..., None] = print,
) -> None:
    """Spawn mitmdump (scoped to `base_url`) capturing in-scope requests to `flow_file`, wait for the
    operator to stop (a keypress, or `duration` seconds, or an injected `wait_for_stop`), then tear the
    subprocess down CLEANLY. Raises CaptureError if mitmdump is missing or dies during boot. The flow
    file is left populated for the caller to feed to the LIGHT loader."""
    mitmdump = _resolve_mitmdump(mitmdump_cmd)          # raises CaptureError if not installed
    scope = _target_scope(base_url)
    cmd = _build_command(mitmdump, listen_port, scope)
    env = _child_env(flow_file, scope, env_extra)

    plat: dict = {}
    if sys.platform == "win32":
        plat["creationflags"] = _CREATE_NEW_PROCESS_GROUP
    else:
        plat["start_new_session"] = True                # own process group for killpg

    errf = tempfile.TemporaryFile()                     # drain stderr to a temp file (no pipe deadlock)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errf, env=env, **plat)
    logger.info("[SCAN·CAPTURE] spawned mitmdump pid=%s on 127.0.0.1:%s", proc.pid, listen_port)

    try:
        # Boot-grace: if mitmdump exits within the window it failed to bind/start (mirrors ProxyManager).
        try:
            rc = proc.wait(timeout=boot_grace)
            errf.seek(0)
            tail = errf.read().decode("utf-8", "replace").strip()[-400:]
            raise CaptureError(
                f"mitmdump exited during boot (code={rc}). "
                f"{tail or 'is the listen port already in use?'}")
        except subprocess.TimeoutExpired:
            pass                                        # still alive after grace => booted OK

        echo(f"  Live capture proxy is listening on http://127.0.0.1:{listen_port}")
        echo(f"    1) Point your client / browser HTTP(S) proxy at 127.0.0.1:{listen_port}.")
        echo(f"    2) {_ca_cert_hint()}")
        echo(f"    3) Browse the target ({base_url}). Only in-scope requests are captured; "
             "off-target traffic is ignored.")
        if duration is not None:
            echo(f"  Capturing for {duration:.0f}s...")
            _sleep(duration)
        elif wait_for_stop is not None:
            wait_for_stop()
        else:
            echo("  Press Enter to STOP capturing and scan...")
            try:
                input()
            except EOFError:
                pass
    finally:
        _kill_tree(proc)
        try:
            errf.close()
        except Exception:
            pass
    logger.info("[SCAN·CAPTURE] mitmdump torn down (pid=%s)", proc.pid)


def _sleep(seconds: float) -> None:
    import time
    time.sleep(max(0.0, seconds))


def run_scan_capture_from_file(
    target_file_path: str, *,
    capture_port: Optional[int] = None,
    capture_duration: Optional[float] = None,
    tokens_file: Optional[str] = None,
    id_source_file: Optional[str] = None,
    assert_owner_only: bool = False,
    model: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    echo: Callable[..., None] = print,
    err: Callable[..., None] = print,
    # capture seams (offline tests inject a fake mitmdump + an immediate stop)
    wait_for_stop: Optional[Callable[[], Any]] = None,
    mitmdump_cmd: Optional[List[str]] = None,
    boot_grace: float = _BOOT_GRACE_SECONDS,
    # scan seams (forwarded to run_scan_from_file — same fakes the other scan tests use)
    engine: Optional[Callable] = None,
    scan_provider_factory: Optional[Callable] = None,
    raw_candidates: Optional[list] = None,
    client_factory: Optional[Callable] = None,
) -> int:
    """LIVE-capture then scan: start mitmdump -> capture to a temp file -> feed it to the LIGHT loader
    via the EXISTING run_scan_from_file(traffic_file=...). Returns a process exit code (0 = ran; 2 = a
    setup / NOT-DATA before any verdict). The engine + its verdict are untouched."""
    from backend.app.cli import branding, target_file
    from backend.app.cli.scan_cli import run_scan_from_file
    from backend.app.core.config import reveal_secret

    # Cheap pre-checks BEFORE spawning a capture (don't make the user proxy traffic just to fail after).
    if not (reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY)):
        err("  ! No API key configured - scan needs one for candidate discovery AND the confirm judge. "
            f"Run `{branding.command_name()} config` first. Nothing was sent.")
        return 2
    t, errors = target_file.load_target_file(target_file_path)
    if errors:
        err(f"  ! [NOT DATA] the target file has {len(errors)} problem(s) - fix them and re-run:")
        for e in errors:
            err(f"      - {e}")
        return 2

    port = capture_port or settings.PROXY_LISTEN_PORT
    fd, flow_file = tempfile.mkstemp(prefix="aivist-capture-", suffix=".http")  # OUTSIDE the repo
    os.close(fd)                                         # the child writes it; we only read it later
    try:
        try:
            capture_to_file(
                t.base_url, flow_file, listen_port=port, duration=capture_duration,
                wait_for_stop=wait_for_stop, mitmdump_cmd=mitmdump_cmd, boot_grace=boot_grace, echo=echo)
        except CaptureError as ex:
            err(f"  ! [NOT DATA] live capture could not start: {ex}")
            return 2

        if os.path.getsize(flow_file) == 0:
            err(f"  ! [NOT DATA] no in-scope traffic was captured (0 flows) for {t.base_url}. Did you "
                f"proxy your client through 127.0.0.1:{port} and browse the target? Nothing to scan.")
            return 2

        # Hand the captured flow file to the EXISTING light loader path — nothing downstream changes.
        kw: dict = {}
        if engine is not None:
            kw["engine"] = engine
        if scan_provider_factory is not None:
            kw["scan_provider_factory"] = scan_provider_factory
        if raw_candidates is not None:
            kw["raw_candidates"] = raw_candidates
        if client_factory is not None:
            kw["client_factory"] = client_factory
        return run_scan_from_file(
            target_file_path, traffic_file=flow_file, tokens_file=tokens_file,
            id_source_file=id_source_file, assert_owner_only=assert_owner_only, model=model,
            environ=environ, echo=echo, err=err, **kw)
    finally:
        try:
            os.remove(flow_file)                        # temp capture file never lingers
        except OSError:
            pass
