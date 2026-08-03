# ==============================================================================
# ConsoleController — ALL console logic, rendering-agnostic, with I/O injected.
# The text and TUI views wire the right prompt/secret_prompt/echo callables and run
# a REPL over `dispatch`.
#
# UX principles (applied everywhere):
#   1. If it's a choice, make them pick a NUMBER — never type a string.
#   2. Explain everything — every step shows what it is, an example, and why.
#   3. Validate at ENTRY and re-prompt in plain language — never fail silently or
#      crash later. Only the API key and tokens are masked; every other field is
#      shown in clear text as typed.
#
# It REUSES the existing machinery verbatim (no second config/verdict path):
#   config     -> config_flow.write_config + redacted_summary (0600 file / source)
#   verify     -> external_verify.run_external_verify (the same evidence tree)
#   demo       -> run.demo (the built-in lab / confirm() path)
#   targets    -> console.targets (non-secret, 0600)
# It reads verdicts ONLY from the engine's rendered output; it cannot manufacture one.
# ==============================================================================
from __future__ import annotations

import getpass
import json
import os
import re
import tempfile
from typing import Callable, List, Optional
from urllib.parse import urlsplit

from backend.app.cli import branding
from backend.app.cli.config_flow import write_config, redacted_summary
from backend.app.cli.external_verify import run_external_verify, _load_spec_file
from backend.app.cli.console import intro, targets
from backend.app.core.config import settings, reveal_secret

# Conservative, provider-appropriate suggestions; a validated "custom" option always
# follows, so a valid model the list doesn't include is never hard-blocked.
_MODEL_SUGGESTIONS = {
    "gemini": ["gemini-2.5-pro", "gemini-2.5-flash"],
    "openai": ["gpt-4o-mini", "gpt-4o", "deepseek-chat"],
    "anthropic": ["claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"],
}
_PROVIDERS = ["gemini", "openai", "anthropic"]


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
            "demo": self.do_demo,
        }.get(c)
        if handler:
            handler()
        else:
            self.echo(f"Unknown command: {parts[0]!r}. Type 'help' for the list of commands.")
        return True

    # -- input helpers: guidance + validation + re-prompt ------------------
    def _guide(self, hint=None, example=None, why=None) -> None:
        if hint:
            self.echo(f"  {hint}")
        if example:
            self.echo(f"    example: {example}")
        if why:
            self.echo(f"    why: {why}")

    def _ask(self, label: str) -> str:
        """A single CLEAR-TEXT prompt (never masked)."""
        return (self.prompt(f"  {label}: ") or "").strip()

    def _ask_required(self, label: str, **g) -> str:
        self._guide(**g)
        while True:
            v = self._ask(label)
            if v:
                return v
            self.echo("  ! This field is required. Please enter a value.")

    def _ask_url(self, label: str, **g) -> str:
        self._guide(**g)
        while True:
            v = self._ask(label)
            u = v if "://" in v else ("http://" + v if v else "")
            if u and urlsplit(u).hostname:
                return u
            self.echo("  ! That doesn't look like a URL. Example: http://localhost:8888")

    def _ask_spec_path(self, label: str, **g) -> str:
        self._guide(**g)
        while True:
            v = self._ask(label)
            if not v:
                self.echo("  ! A spec file path is required (the target's OpenAPI/Swagger file).")
                continue
            if not os.path.isfile(v):
                self.echo(f"  ! That file wasn't found: {v}. Please enter the path again.")
                continue
            try:
                _load_spec_file(v)
            except Exception as ex:
                self.echo(f"  ! That file couldn't be read as OpenAPI JSON/YAML "
                          f"({type(ex).__name__}). Please enter a valid spec path.")
                continue
            return v

    def _ask_menu(self, label: str, options: List[str], **g) -> int:
        """Numbered pick. Returns the 0-based index; re-prompts on non-numeric/out-of-range."""
        self._guide(**g)
        for i, o in enumerate(options, 1):
            self.echo(f"    [{i}] {o}")
        while True:
            v = self._ask(f"{label} - enter a number")
            if v.isdigit() and 1 <= int(v) <= len(options):
                return int(v) - 1
            self.echo(f"  ! Please enter a number from the list (1-{len(options)}).")

    def _ask_optional_login_file(self, label: str, **g) -> str:
        self._guide(**g)
        while True:
            v = self._ask(label)
            if not v:
                return ""                       # blank = use static tokens at verify
            if os.path.isfile(v):
                return v
            self.echo(f"  ! That login file wasn't found: {v}. "
                      f"Leave blank to use tokens, or enter a valid path.")

    @staticmethod
    def _looks_like_model(v: str) -> bool:
        v = (v or "").strip()
        return (len(v) >= 2 and bool(re.search(r"[A-Za-z]", v))
                and ("-" in v or any(ch.isdigit() for ch in v)))

    def _ask_model(self, provider: str, **g) -> str:
        suggestions = _MODEL_SUGGESTIONS.get(provider, [])
        idx = self._ask_menu("Model", suggestions + ["enter a custom model id"], **g)
        if idx < len(suggestions):
            return suggestions[idx]
        self.echo("  Enter the provider's FULL model id.")
        self.echo("    example: gemini-2.5-pro / gpt-4o-mini / claude-3-5-sonnet-latest")
        while True:
            v = self._ask("Custom model id")
            if self._looks_like_model(v):
                return v
            self.echo("  ! That doesn't look like a model id ('gemini' or '2.5' won't work). "
                      "Use the full id, e.g. gemini-2.5-pro.")

    def _ask_secret(self, label: str, **g) -> str:
        """MASKED entry (key). Confirms receipt without ever showing the value."""
        self._guide(**g)
        v = (self.secret_prompt(f"  {label} (input hidden): ") or "").strip()
        if v:
            self.echo(f"    received ({len(v)} characters).")
        return v

    def _confirming_secret(self, label: str) -> str:
        """prompt_secret passed to run_external_verify (it supplies its own label).
        Masked + 'received' confirmation so the user always knows it worked."""
        v = (self.secret_prompt(label) or "").strip()
        if v:
            self.echo(f"    received ({len(v)} characters).")
        return v

    # -- commands ----------------------------------------------------------
    def do_help(self) -> None:
        for line in intro.help_lines():
            self.echo(line)

    def do_config(self) -> None:
        """Guided config screen (numbered provider, validated model/base_url, masked+confirmed
        key). Reuses write_config/redacted_summary (the 0600 file + settings source), then
        refreshes settings so a same-session verify/demo sees the new key."""
        self.echo("Configure the AI provider the verifier calls to read evidence.")
        self.echo("(Code still adjudicates the verdict; the model only reads what code gathered.)")
        provider = _PROVIDERS[self._ask_menu(
            "Provider",
            ["gemini (Google) - the default, measured model",
             "openai / OpenAI-compatible - incl. relays / DeepSeek / Kimi / GLM / Qwen / Grok / Ollama",
             "anthropic (Claude)"],
            why="Which model backend to call.")]
        data = {"LLM_PROVIDER": provider}
        key = self._ask_secret(
            "API key",
            hint="Your provider API key. Stored locally at 0600, redacted everywhere, never shown.",
            example="AIza... (gemini) / sk-... (openai)")
        if key:
            data["LLM_API_KEY"] = key
        else:
            self.echo("  (no key entered - run 'config' again later; 'verify' and 'demo' need a key.)")
        if provider == "openai":
            data["LLM_BASE_URL"] = self._ask_url(
                "Base URL",
                hint="The OpenAI-compatible endpoint (relay / gateway / local server).",
                example="https://host/v1",
                why="Routes OpenAI-format calls to your relay or local model.")
        data["LLM_MODEL"] = self._ask_model(provider, why="The exact model id to call.")
        write_config(data, self.config_path)
        self.echo(f"  saved to {self.config_path}")
        for line in redacted_summary(data):
            self.echo("  " + line)
        self.echo("  Next: create a target with 'target', then run 'verify'. "
                  "Or try 'demo' for a zero-setup example.")
        self._refresh_settings()

    def _refresh_settings(self) -> None:
        """Re-read the just-written config into the shared settings singleton (mutated in
        place, so every `from config import settings` reference sees it). Guarded - a reload
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
        self.echo(f"  API key:  {'set (redacted)' if key_set else '(not set - run config)'}")
        self.echo(f"  target:   {self.selected.name if self.selected else '(none - run target)'}")

    @staticmethod
    def _default_id_param(path_template: str, id_location: str) -> str:
        if id_location != "query" and "{" in path_template and "}" in path_template:
            return path_template[path_template.rfind("{") + 1: path_template.rfind("}")]
        return "id"

    def _pick_endpoint(self, spec_path: str):
        """Numbered pick of METHOD /path from the (already-validated) spec, with a manual
        fallback. Returns (method, path_template)."""
        endpoints = []
        try:
            spec = _load_spec_file(spec_path)
            for p, ops in (spec.get("paths") or {}).items():
                for m in ("get", "post", "put", "delete", "patch"):
                    if isinstance(ops, dict) and m in ops:
                        endpoints.append((m.upper(), p))
        except Exception:
            endpoints = []
        if endpoints:
            options = [f"{m:6} {p}" for m, p in endpoints] + ["enter the endpoint manually"]
            idx = self._ask_menu("Endpoint to test", options,
                                 hint="Pick the endpoint whose object id you can flip between two users.")
            if idx < len(endpoints):
                return endpoints[idx]
        self.echo("  Entering the endpoint manually.")
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        m = methods[self._ask_menu("Method", methods)]
        p = self._ask_required("Path template",
                               hint="The path, with the id written as a {template}.",
                               example="/workshop/api/shop/orders/{order_id}")
        return m, p

    def do_target(self) -> None:
        self.echo("Create a reusable target: where to attack, and the two ids to compare.")
        name = self._ask_required("Target name",
                                  hint="A label to save and re-select this target.",
                                  example="crapi-orders")
        base_url = self._ask_url("Base URL",
                                 hint="The target's base URL (localhost only).",
                                 example="http://localhost:8888",
                                 why="Every request is scope-locked to this host.")
        spec_path = self._ask_spec_path("OpenAPI spec path",
                                        hint="Path to the target's OpenAPI/Swagger file (.json or .yml).",
                                        example=r"C:\Users\you\crapi-openapi-spec.json",
                                        why="Used to list endpoints and describe the API to the verifier.")
        method, path_template = self._pick_endpoint(spec_path)
        loc_idx = self._ask_menu("Where is the object id?",
                                 ["path  - e.g. /orders/{id}", "query - e.g. ?report_id=123"],
                                 why="The tool swaps the id in this location to attempt cross-user access.")
        id_location = "query" if loc_idx == 1 else "path"
        if id_location == "path":
            id_param = self._default_id_param(path_template, "path")
            self.echo(f"  id parameter: {id_param}  (taken from the path template)")
        else:
            id_param = self._ask_required("Query parameter name that carries the id",
                                          hint="The name of the query parameter holding the object id.",
                                          example="report_id")
        attacker_id = self._ask_required("Attacker's OWN resource id",
                                         hint="An id the ATTACKER legitimately owns - the safe baseline.",
                                         example="8",
                                         why="The tool compares this against the victim's to detect a real leak.")
        victim_id = self._ask_required("Victim's resource id",
                                       hint="The id the attacker should NOT be able to reach.",
                                       example="7",
                                       why="The tool swaps this in to attempt the cross-user access.")
        auth = self._ask_optional_login_file(
            "Login file",
            hint="OPTIONAL path to a login-declaration JSON (auto-relogin for tokens that expire mid-run).",
            example="leave BLANK to just paste tokens at verify time",
            why="Only needed if the target's tokens expire during a run.")
        t = targets.Target(
            name=name, base_url=base_url, spec_path=spec_path, method=method,
            path_template=path_template, id_location=id_location, id_param=id_param,
            attacker_id=attacker_id, victim_id=victim_id, auth_spec_path=auth,
        )
        path = targets.save_target(t)
        self.selected = t
        self.echo(f"  saved target '{t.name}' -> {path}")
        self.echo(f"  selected '{t.name}'. Run 'verify' to confirm it.")

    def do_targets(self) -> None:
        names = targets.list_targets()
        if not names:
            self.echo("  No saved targets yet. Use 'target' to create one.")
            return
        self.echo("  Saved targets:")
        for i, n in enumerate(names, 1):
            mark = "   <- selected" if (self.selected and self.selected.name == n) else ""
            self.echo(f"    [{i}] {n}{mark}")
        while True:
            v = self._ask("Select a number (blank to keep current)")
            if not v:
                return
            if v.isdigit() and 1 <= int(v) <= len(names):
                t = targets.load_target(names[int(v) - 1])
                if t:
                    self.selected = t
                    self.echo(f"  selected '{t.name}'. Run 'verify' to confirm it.")
                else:
                    self.echo("  (could not load that target)")
                return
            self.echo(f"  ! Please enter a number from the list (1-{len(names)}), or leave blank.")

    def do_verify(self) -> None:
        """Run the SAME run_external_verify on the selected target and render its evidence
        tree. Tokens are prompted (masked, with a 'received' confirmation) - never on disk."""
        if self.selected is None:
            self.echo("  No target selected yet.")
            self.echo("  Use 'targets' to pick a saved one, or 'target' to create one. "
                      "Or try 'demo' for a zero-setup example.")
            return
        if not (reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY)):
            self.echo("  No API key configured - the verifier needs one to judge evidence.")
            self.echo("  Run 'config' to set your provider + key, then 'verify' again. Nothing was sent.")
            return
        t = self.selected
        self.echo(f"Confirming on {t.base_url}: can the attacker reach the victim's resource?")
        if not t.auth_spec_path:
            self.echo("  You'll be asked for two Bearer tokens (input hidden; the tool confirms receipt):")
            self.echo("    - Attacker token: from logging in as the ATTACKER account "
                      "(the tool sends the attack as the attacker).")
            self.echo("    - Owner token:    from logging in as the VICTIM/owner "
                      "(used ONLY to re-read as the owner; press Enter to skip).")
            self.echo("    Example value: Bearer eyJhbGciOi...")
        else:
            self.echo(f"  Using the login file for auto-relogin: {t.auth_spec_path}")
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        try:
            json.dump(t.to_op(), tmp)
            tmp.close()
            kwargs = dict(
                target=t.base_url, spec_path=t.spec_path, op_path=tmp.name,
                config_path=self.config_path, prompt=self.prompt,
                prompt_secret=self._confirming_secret, echo=self.echo, err=self.echo,
                auth_spec_path=(t.auth_spec_path or None),
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

    def do_demo(self) -> None:
        """Zero-setup example against the built-in lab (no Docker/target/tokens). Delegates to
        run.demo (the confirm() lab path). Lazy import avoids any import cycle."""
        import run
        run.demo()
