# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Step 9 Proxy Radar — mitmdump Subprocess Manager (State Machine)
#
# Owns the lifecycle of the `mitmdump` intercepting proxy, which runs in its OWN
# Python interpreter (separate process). Guarantees:
#   * OS-agnostic CLEAN process-tree termination (Windows taskkill /F /T, Unix
#     process-group signals) so the listen port is never leaked.
#   * Supervised restart with a circuit breaker (no thrash).
#   * Tight lifespan integration — shutdown() is called on app teardown so a
#     crash of the web server never orphans the proxy.
#
# IPC token: a per-session secret is generated here, injected into the child via
# env var, and validated by the internal-ingest endpoint. It is in-memory only.
# ==============================================================================

import os
import sys
import signal
import shutil
import secrets
import asyncio
import logging
import subprocess
import datetime
from collections import deque
from pathlib import Path
from typing import List, Optional, Deque

from pydantic import SecretStr

from backend.app.core.config import settings, reveal_secret

logger = logging.getLogger("app.services.proxy_manager")

# ------------------------------------------------------------------------------
# State machine states
# ------------------------------------------------------------------------------
STOPPED = "STOPPED"
STARTING = "STARTING"
RUNNING = "RUNNING"
DEGRADED = "DEGRADED"
STOPPING = "STOPPING"
FAILED = "FAILED"

# Boot grace: if mitmdump exits within this window it failed to bind/start.
_BOOT_GRACE_SECONDS = 1.5
# Graceful-stop window before escalating to a forced tree kill.
_STOP_GRACE_SECONDS = 4.0
# Circuit breaker: more than N unexpected restarts within W seconds => FAILED.
_RESTART_MAX = 3
_RESTART_WINDOW_SECONDS = 60.0

_CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


class ProxyManager:
    """Singleton supervisor for the mitmdump child process."""

    def __init__(self) -> None:
        self._state: str = STOPPED
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._pid: Optional[int] = None
        # SecretStr so no repr / log / crash-dump ever emits the real IPC token; the real
        # value is revealed only at point of use (child env + constant-time verify).
        self._ingest_token: SecretStr = SecretStr("")
        self._scope: List[str] = []
        self._listen_port: int = settings.PROXY_LISTEN_PORT
        self._started_at: Optional[float] = None
        self._stopping: bool = False
        self._supervisor_task: "Optional[asyncio.Task]" = None
        self._stderr_task: "Optional[asyncio.Task]" = None
        self._stderr_ring: Deque[str] = deque(maxlen=50)
        self._restart_times: Deque[float] = deque(maxlen=_RESTART_MAX + 1)
        self._last_error: Optional[str] = None
        self._transition_lock = asyncio.Lock()

    # --- public read-only surface ------------------------------------------
    @property
    def state(self) -> str:
        return self._state

    @property
    def ingest_token(self) -> SecretStr:
        return self._ingest_token

    @property
    def scope(self) -> List[str]:
        return list(self._scope)

    @property
    def is_active(self) -> bool:
        return self._state in (STARTING, RUNNING, DEGRADED)

    def verify_ingest_token(self, token: Optional[str]) -> bool:
        """Constant-time token check; false if radar isn't active or no token."""
        tok = reveal_secret(self._ingest_token)
        if not tok or not token:
            return False
        return secrets.compare_digest(token, tok)

    def status(self) -> dict:
        uptime = None
        if self._started_at is not None and self._state in (RUNNING, DEGRADED):
            uptime = max(0.0, asyncio.get_event_loop().time() - self._started_at)
        return {
            "state": self._state,
            "pid": self._pid,
            "listen_port": self._listen_port if self.is_active else None,
            "uptime_seconds": uptime,
            "scope": list(self._scope),
            "ca_cert_available": self.ca_cert_path() is not None,
            "message": self._last_error,
        }

    # --- CA certificate -----------------------------------------------------
    @staticmethod
    def ca_cert_path() -> Optional[Path]:
        """
        Locate the mitmproxy CA cert (generated after mitmdump's first run).
        Prefer the Windows-installable .cer, else the PEM. Returns None if the
        radar has never run (cert not yet generated).
        """
        base = Path.home() / ".mitmproxy"
        for name in ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem"):
            p = base / name
            if p.is_file():
                return p
        return None

    # --- lifecycle ----------------------------------------------------------
    def _resolve_mitmdump(self) -> Optional[str]:
        if settings.MITMDUMP_PATH:
            return settings.MITMDUMP_PATH if os.path.isfile(settings.MITMDUMP_PATH) else None
        return shutil.which("mitmdump")

    @staticmethod
    def _addon_path() -> str:
        return str((Path(__file__).resolve().parent.parent / "proxy" / "radar_addon.py"))

    def _build_command(self, mitmdump: str, port: int) -> List[str]:
        return [
            mitmdump,
            "-q",                              # quiet; we don't parse stdout
            "--listen-host", "127.0.0.1",      # local-only proxy surface
            "--listen-port", str(port),
            "--ssl-insecure",                  # don't choke on upstream certs
            "-s", self._addon_path(),
        ]

    def _child_env(self) -> dict:
        env = os.environ.copy()
        env["RADAR_INGEST_URL"] = f"http://127.0.0.1:{settings.API_PORT}/api/v1/hunter/proxy/internal-ingest"
        env["RADAR_INGEST_TOKEN"] = reveal_secret(self._ingest_token) or ""
        env["RADAR_SCOPE"] = ",".join(self._scope)
        env["RADAR_BODY_CAP"] = str(settings.PROXY_BODY_CAP)
        # Ensure the addon can import backend.app.services.pruner (shared Tier-1).
        env["PYTHONPATH"] = os.pathsep.join(
            filter(None, [str(Path(__file__).resolve().parent.parent.parent.parent), env.get("PYTHONPATH", "")])
        )
        return env

    async def _spawn(self) -> None:
        mitmdump = self._resolve_mitmdump()
        if not mitmdump:
            raise RuntimeError(
                "mitmdump executable not found. Install mitmproxy or set MITMDUMP_PATH."
            )
        cmd = self._build_command(mitmdump, self._listen_port)
        plat_kwargs = {}
        if sys.platform == "win32":
            plat_kwargs["creationflags"] = _CREATE_NEW_PROCESS_GROUP
        else:
            plat_kwargs["start_new_session"] = True  # own process group for killpg

        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            env=self._child_env(),
            **plat_kwargs,
        )
        self._pid = self._proc.pid
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        logger.info(f"[PROXY-MGR] Spawned mitmdump pid={self._pid} on 127.0.0.1:{self._listen_port}")

    async def _drain_stderr(self) -> None:
        """Continuously drain child stderr into a ring buffer (prevents pipe block)."""
        if self._proc is None or self._proc.stderr is None:
            return
        try:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip()
                if text:
                    self._stderr_ring.append(text)
        except Exception:
            pass

    async def start(self, scope: Optional[List[str]] = None, listen_port: Optional[int] = None) -> dict:
        async with self._transition_lock:
            if self.is_active:
                return self.status()
            self._scope = [s.strip() for s in (scope or []) if s and s.strip()]
            # Node 3: validate the proxy scope against the ONE audited policy, exactly as the
            # active batch route does — reject an over-broad / malformed declaration early
            # (fail-fast) instead of spawning the child and silently over-capturing.
            from backend.app.services.scope import ScopePolicy, ScopeError
            try:
                ScopePolicy.from_declaration(self._scope)
            except ScopeError as e:
                self._state = FAILED
                self._last_error = f"Invalid scope declaration: {e}"
                logger.error(f"[PROXY-MGR] {self._last_error}")
                return self.status()
            self._listen_port = listen_port or settings.PROXY_LISTEN_PORT
            self._ingest_token = SecretStr(secrets.token_urlsafe(32))
            self._stopping = False
            self._last_error = None
            self._stderr_ring.clear()
            self._state = STARTING

            try:
                await self._spawn()
            except Exception as e:
                self._state = FAILED
                self._last_error = str(e)
                logger.error(f"[PROXY-MGR] Spawn failed: {e}")
                return self.status()

            # Boot confirm: if it dies within the grace window, it failed to bind.
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=_BOOT_GRACE_SECONDS)
                # wait() returned => process exited during boot => failure
                self._state = FAILED
                self._last_error = (
                    f"mitmdump exited during boot (code={self._proc.returncode}). "
                    f"stderr: {' | '.join(list(self._stderr_ring)[-3:]) or 'n/a'}"
                )
                logger.error(f"[PROXY-MGR] {self._last_error}")
                return self.status()
            except asyncio.TimeoutError:
                pass  # still alive after grace => booted OK

            self._state = RUNNING
            self._started_at = asyncio.get_event_loop().time()
            self._supervisor_task = asyncio.create_task(self._supervise())
            logger.info(f"[PROXY-MGR] Radar RUNNING (pid={self._pid}, scope={self._scope or 'ALL'})")
            return self.status()

    async def _supervise(self) -> None:
        """Watch the child; restart with a circuit breaker on unexpected death."""
        while True:
            if self._proc is None:
                return
            await self._proc.wait()
            if self._stopping:
                return  # intentional stop
            # Unexpected exit.
            now = asyncio.get_event_loop().time()
            self._restart_times.append(now)
            recent = [t for t in self._restart_times if now - t <= _RESTART_WINDOW_SECONDS]
            if len(recent) > _RESTART_MAX:
                self._state = FAILED
                self._last_error = "Restart budget exhausted; proxy disabled to avoid thrash."
                logger.error(f"[PROXY-MGR] {self._last_error}")
                return
            self._state = DEGRADED
            backoff = min(4.0, 1.0 * (2 ** (len(recent) - 1)))
            logger.warning(f"[PROXY-MGR] mitmdump died unexpectedly; restarting in {backoff:.1f}s")
            await asyncio.sleep(backoff)
            try:
                await self._spawn()
                self._state = RUNNING
                self._started_at = asyncio.get_event_loop().time()
            except Exception as e:
                self._state = FAILED
                self._last_error = f"Restart failed: {e}"
                return

    async def _kill_tree(self) -> None:
        """OS-agnostic forced termination of the child AND its descendants."""
        if self._proc is None or self._pid is None:
            return
        pid = self._pid
        if sys.platform == "win32":
            # taskkill /T kills the whole tree; mitmdump can spawn workers that a
            # bare terminate() would orphan (leaking the listen port).
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill", "/F", "/T", "/PID", str(pid),
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(killer.wait(), timeout=_STOP_GRACE_SECONDS)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        else:
            # Signal the whole process group (start_new_session gave us one).
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=_STOP_GRACE_SECONDS)
                except asyncio.TimeoutError:
                    os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass

    async def stop(self) -> dict:
        async with self._transition_lock:
            if self._state == STOPPED:
                return self.status()
            self._stopping = True
            self._state = STOPPING
            if self._supervisor_task:
                self._supervisor_task.cancel()
            await self._kill_tree()
            if self._stderr_task:
                self._stderr_task.cancel()
            self._proc = None
            self._pid = None
            self._started_at = None
            self._state = STOPPED
            logger.info("[PROXY-MGR] Radar STOPPED.")
            return self.status()

    async def shutdown(self) -> None:
        """Idempotent teardown for the FastAPI lifespan (never raises)."""
        try:
            if self.is_active or self._proc is not None:
                await self.stop()
        except Exception:
            logger.exception("[PROXY-MGR] Error during shutdown")


# Module-level singleton + accessor
proxy_manager = ProxyManager()


def get_proxy_manager() -> ProxyManager:
    return proxy_manager
