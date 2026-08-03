# ==============================================================================
# ConsoleController — ALL console logic, rendering-agnostic, with I/O injected
# (the same pattern config_flow.run_config_flow uses). The text and TUI views wire
# the right prompt/secret_prompt/echo callables and run a REPL over `dispatch`.
#
# It REUSES the existing machinery verbatim:
#   config screen  -> config_flow.run_config_flow (do NOT add a second config path)
#   verify         -> external_verify.run_external_verify (the same evidence tree)
#   targets        -> console.targets (non-secret, 0600)
# It reads verdicts ONLY from the engine's rendered output; it cannot manufacture one.
# ==============================================================================
from __future__ import annotations

import getpass
import json
import os
import tempfile
from typing import Callable, List, Optional

from backend.app.cli import branding
from backend.app.cli.config_flow import run_config_flow
from backend.app.cli.external_verify import run_external_verify, _load_spec_file
from backend.app.cli.console import intro, targets
from backend.app.core.config import settings, reveal_secret


class ConsoleController:
    def __init__(
        self,
        *,
        prompt: Callable[[str], str] = input,
        secret_prompt: Callable[[str], str] = getpass.getpass,
        echo: Callable[..., None] = print,
        config_path: Optional[str] = None,
        engine: Optional[Callable] = None,
    ) -> None:
        self.prompt = prompt
        self.secret_prompt = secret_prompt
        self.echo = echo
        self.config_path = config_path or branding.config_file_path()
        self.engine = engine                       # None -> run_external_verify's default
        self.selected: Optional[targets.Target] = None

    # -- REPL entry points -------------------------------------------------
    def run_intro(self) -> None:
        for line in intro.intro_lines(branding.product_name()):
            self.echo(line)

    def dispatch(self, line: str) -> bool:
        """Handle one command line. Returns False to quit, True to continue."""
        parts = (line or "").strip().split()
        if not parts:
            return True
        c = parts[0].lower()
        if c in ("quit", "exit", "q"):
            return False
        handler = {
            "help": self.do_help, "config": self.do_config, "target": self.do_target,
            "targets": self.do_targets, "verify": self.do_verify, "status": self.do_status,
        }.get(c)
        if handler:
            handler()
        else:
            self.echo(f"Unknown command: {parts[0]!r}. Type 'help'.")
        return True

    # -- small helpers -----------------------------------------------------
    def _ask(self, label: str) -> str:
        return (self.prompt(f"  {label}: ") or "").strip()

    # -- commands ----------------------------------------------------------
    def do_help(self) -> None:
        for line in intro.help_lines():
            self.echo(line)

    def do_config(self) -> None:
        """The config screen IS the existing run_config_flow (masked key, 0600 file),
        then refresh the in-memory settings so a same-session `verify` sees the new key."""
        run_config_flow(prompt=self.prompt, secret_prompt=self.secret_prompt,
                        echo=self.echo, path=self.config_path)
        self._refresh_settings()

    def _refresh_settings(self) -> None:
        """Re-read the just-written config into the shared settings singleton (mutated in
        place, so every `from config import settings` reference sees it). Guarded — a reload
        hiccup must never break the console. Forces the config-file source to self.config_path."""
        try:
            import backend.app.core.config as cfg
            env_var = branding.config_file_env_var()
            old = os.environ.get(env_var)
            os.environ[env_var] = self.config_path
            try:
                fresh = cfg.Settings()
            finally:
                if old is None:
                    os.environ.pop(env_var, None)
                else:
                    os.environ[env_var] = old
            for name in fresh.model_fields:
                setattr(cfg.settings, name, getattr(fresh, name))
        except Exception:
            pass

    def do_status(self) -> None:
        key_set = bool(reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY))
        self.echo("Status:")
        self.echo(f"  provider: {settings.LLM_PROVIDER}")
        if settings.LLM_MODEL:
            self.echo(f"  model:    {settings.LLM_MODEL}")
        if settings.LLM_BASE_URL:
            self.echo(f"  base_url: {settings.LLM_BASE_URL}")
        self.echo(f"  API key:  {'set (redacted)' if key_set else '(not set)'}")
        self.echo(f"  target:   {self.selected.name if self.selected else '(none)'}")

    def _pick_endpoint(self, spec_path: str):
        """List METHOD /path from the spec for the user to pick; fall back to manual entry
        if the spec can't be read or the user chooses. Returns (method, path_template)."""
        endpoints = []
        try:
            spec = _load_spec_file(spec_path)
            for p, ops in (spec.get("paths") or {}).items():
                for m in ("get", "post", "put", "delete", "patch"):
                    if isinstance(ops, dict) and m in ops:
                        endpoints.append((m.upper(), p))
        except Exception as ex:
            self.echo(f"  (could not read spec: {type(ex).__name__}; enter the endpoint manually)")
        if endpoints:
            self.echo("  endpoints:")
            for i, (m, p) in enumerate(endpoints, 1):
                self.echo(f"    {i:>3}. {m:6} {p}")
            pick = self._ask("Pick a number (or 'm' for manual)")
            if pick.isdigit() and 1 <= int(pick) <= len(endpoints):
                return endpoints[int(pick) - 1]
        method = (self._ask("Method [GET]") or "GET").upper()
        path = self._ask("Path template (e.g. /workshop/api/shop/orders/{order_id})")
        return method, path

    @staticmethod
    def _default_id_param(path_template: str, id_location: str) -> str:
        if id_location != "query" and "{" in path_template and "}" in path_template:
            return path_template[path_template.rfind("{") + 1: path_template.rfind("}")]
        return "id"

    def do_target(self) -> None:
        name = self._ask("Target name (e.g. crapi-orders)")
        if not name:
            self.echo("  cancelled (no name)")
            return
        base_url = self._ask("Base URL (e.g. http://localhost:8888)")
        spec_path = self._ask("OpenAPI spec path (.json / .yml)")
        method, path_template = self._pick_endpoint(spec_path)
        if not path_template:
            self.echo("  cancelled (no endpoint)")
            return
        loc = (self._ask("Id location - [path] / query") or "path").strip().lower()
        id_location = "query" if loc == "query" else "path"
        default_param = self._default_id_param(path_template, id_location)
        id_param = self._ask(f"Id parameter name [{default_param}]") or default_param
        attacker_id = self._ask("Attacker's OWN resource id (the baseline)")
        victim_id = self._ask("Victim's resource id (the one to reach)")
        auth = self._ask("Login-declaration path for auto-relogin (blank = static tokens at verify)")
        t = targets.Target(
            name=name, base_url=base_url, spec_path=spec_path, method=method,
            path_template=path_template, id_location=id_location, id_param=id_param,
            attacker_id=attacker_id, victim_id=victim_id, auth_spec_path=auth or "",
        )
        path = targets.save_target(t)
        self.selected = t
        self.echo(f"  saved target '{t.name}' -> {path}")
        self.echo(f"  selected: {t.name}")

    def do_targets(self) -> None:
        names = targets.list_targets()
        if not names:
            self.echo("  No saved targets yet. Use 'target' to create one.")
            return
        self.echo("  saved targets:")
        for i, n in enumerate(names, 1):
            mark = " *" if (self.selected and self.selected.name == n) else ""
            self.echo(f"    {i}. {n}{mark}")
        pick = self._ask("Select a number (blank to keep current)")
        if pick.isdigit() and 1 <= int(pick) <= len(names):
            t = targets.load_target(names[int(pick) - 1])
            if t:
                self.selected = t
                self.echo(f"  selected: {t.name}")
            else:
                self.echo("  (could not load that target)")

    def do_verify(self) -> None:
        """Run the SAME run_external_verify on the selected target and render its evidence
        tree. Tokens are prompted (masked) inside run_external_verify — never on disk."""
        if self.selected is None:
            self.echo("  No target selected. Use 'targets' to select one, or 'target' to create one.")
            return
        t = self.selected
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        try:
            json.dump(t.to_op(), tmp)
            tmp.close()
            kwargs = dict(
                target=t.base_url, spec_path=t.spec_path, op_path=tmp.name,
                config_path=self.config_path, prompt=self.prompt, prompt_secret=self.secret_prompt,
                echo=self.echo, err=self.echo, auth_spec_path=(t.auth_spec_path or None),
            )
            if self.engine is not None:
                kwargs["engine"] = self.engine
            code = run_external_verify(**kwargs)
            summary = {0: "nothing confirmed", 1: "confirmed", 2: "NOT DATA"}.get(code, str(code))
            self.echo(f"  (exit {code}: {summary})")
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
