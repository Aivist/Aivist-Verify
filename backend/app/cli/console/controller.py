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
from backend.app.cli.confirm_render import _painter          # ANSI paint; auto-off when not a TTY / NO_COLOR
from backend.app.core.config import settings, reveal_secret

# The env keys the non-interactive scan reads; the interactive flow now reads them too (#6) so a user who
# already exported them isn't forced to paste. Values become SecretStr immediately and route per-account.
_ENV_TOKEN_KEYS = {"attacker": "TARGET_ATTACKER_TOKEN", "owner": "TARGET_OWNER_TOKEN",
                   "bystander": "TARGET_BYSTANDER_TOKEN"}

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
        scan_provider_factory: Optional[Callable] = None,
    ) -> None:
        self.prompt = prompt
        self.secret_prompt = secret_prompt
        self.echo = echo
        self.config_path = config_path or branding.config_file_path()
        self.engine = engine                       # None -> run_external_verify's default
        # scan discovery provider (None -> the configured LLM provider); a test seam for offline scans.
        self.scan_provider_factory = scan_provider_factory
        self.selected: Optional[targets.Target] = None
        # ANSI painter, detected ONCE (NO_COLOR / FORCE_COLOR / stdout.isatty). Off when piped / in tests,
        # so no raw escape codes ever reach a dumb terminal. `environ` is a test seam for the env-token read.
        self._paint = _painter(None)
        self._environ = os.environ

    # -- REPL entry points -------------------------------------------------
    def run_intro(self) -> None:
        for line in intro.intro_lines(branding.product_name()):
            self.echo(line)
        for line in self._startup_status_lines():     # so the user KNOWS what's already saved
            self.echo(line)

    def _startup_status_lines(self) -> List[str]:
        """Saved-state at startup: the API key (never re-enter it) + saved targets — so the user is not
        walking blind. Guarded: a read hiccup must never break the console."""
        out: List[str] = []
        try:
            key_set = bool(reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY))
            out.append("  API key: configured (run 'config' to change)." if key_set
                       else "  API key: not set - run 'config' to add one.")
            names = targets.list_targets()
            if names:
                shown = ", ".join(names[:6]) + (" ..." if len(names) > 6 else "")
                out.append(f"  Saved targets ({len(names)}): {shown} - run 'targets' to select.")
            else:
                out.append("  No saved targets yet - run 'target' (or 'target --dump-template' file form).")
        except Exception:
            pass
        return out

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
            "demo": self.do_demo, "scan": self.do_scan,
        }.get(c)
        if handler:
            handler()
        else:
            self.echo(f"Unknown command: {parts[0]!r}. Type 'help' for the list of commands.")
        return True

    # -- input helpers: guidance + validation + re-prompt ------------------
    def _guide(self, hint=None, example=None, why=None, *, optional: bool = False,
               optional_hint: Optional[str] = None) -> None:
        """Show guidance BEFORE the input line (#3/#4 - ALWAYS before, never after), one blank line above
        so blocks aren't cramped, dim-colored so it reads as guidance not answer. `optional` appends a
        press-Enter hint; `optional_hint` overrides its text (so a required CHOICE between inputs isn't
        mislabeled a plain 'optional' - #3)."""
        self.echo("")                                        # blank line between Q&A blocks
        if hint:
            self.echo(self._paint(f"  {hint}", "dim"))
        if example:
            self.echo(self._paint(f"    example: {example}", "dim"))
        if why:
            self.echo(self._paint(f"    why: {why}", "dim"))
        if optional:
            self.echo(self._paint("    " + (optional_hint or "(optional - just press Enter to skip)"), "dim"))

    def _ask(self, label: str) -> str:
        """A single CLEAR-TEXT prompt (never masked). The label is highlighted (#1) so it stands apart
        from the dim guidance; the entered value is echoed back on its own line in a distinct style (#1),
        so there's always a clear record of what was typed. Secrets NEVER go through here."""
        v = (self.prompt(self._paint(f"  {label}", "cyan", "bold") + ": ") or "").strip()
        if v:
            self.echo(self._paint(f"    -> {v}", "green"))   # echo back the entered value (distinct)
        return v

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

    def _ask_optional_spec_path(self, label: str, **g) -> str:
        """Like `_ask_spec_path` but BLANK is allowed => a spec-less target (scan runs from an
        endpoints list instead). A non-blank value must be a readable OpenAPI file (re-prompt otherwise)."""
        self._guide(**g, optional=True)
        while True:
            v = self._ask(label)
            if not v:
                return ""                       # spec-less target — endpoints provided at scan time
            if not os.path.isfile(v):
                self.echo(f"  ! That file wasn't found: {v}. Leave BLANK for a spec-less target, "
                          f"or enter a valid path.")
                continue
            try:
                _load_spec_file(v)
            except Exception as ex:
                self.echo(f"  ! That file couldn't be read as OpenAPI JSON/YAML ({type(ex).__name__}). "
                          f"Leave BLANK, or enter a valid spec path.")
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
        self._guide(**g, optional=True)
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

    def _ask_secret(self, label: str, *, optional: bool = False, **g) -> str:
        """MASKED entry (key/token). Confirms receipt without EVER showing the value. `optional` shows the
        press-Enter-to-skip hint (#9). The masked line + a length-only receipt are the only output — the
        value is never echoed."""
        self._guide(**g, optional=optional)
        v = (self.secret_prompt(self._paint(f"  {label} (input hidden)", "cyan", "bold") + ": ") or "").strip()
        if v:
            self.echo(self._paint(f"    received ({len(v)} characters).", "dim"))
        return v

    def _confirming_secret(self, label: str) -> str:
        """prompt_secret passed to run_external_verify (it supplies its own label).
        Masked + 'received' confirmation so the user always knows it worked."""
        v = (self.secret_prompt(label) or "").strip()
        if v:
            self.echo(self._paint(f"    received ({len(v)} characters).", "dim"))
        return v

    def _env_or_secret(self, role: str, label: str, *, optional: bool = False, **g) -> str:
        """#6: if the role's env token (TARGET_<ROLE>_TOKEN) is set, USE it instead of forcing a paste;
        otherwise fall back to the masked prompt. Returns the RAW token string — the caller wraps it in
        SecretStr and routes it per-account (attacker->auth_context, owner->owner_credential,
        bystander->bystander_credential). RED LINE: the value is NEVER echoed (only a masked 'from env'
        receipt), and the attacker!=owner collision guard still fires on it downstream."""
        key = _ENV_TOKEN_KEYS[role]
        env_val = (self._environ.get(key) or "").strip()
        if env_val:
            self.echo(self._paint(f"  Using {role} token from environment ({key}, masked).", "green"))
            return env_val
        return self._ask_secret(label, optional=optional, **g)

    def _ask_yes_no(self, label: str, default: bool = False, **g) -> bool:
        """A y/N prompt. Blank -> `default`. Re-prompts on anything unrecognized."""
        self._guide(**g)
        suffix = "[Y/n]" if default else "[y/N]"
        while True:
            v = self._ask(f"{label} {suffix}").lower()
            if not v:
                return default
            if v in ("y", "yes"):
                return True
            if v in ("n", "no"):
                return False
            self.echo("  ! Please answer y or n.")

    def _ask_account_labels(self) -> dict:
        """#7 (optional): point this run at a DIFFERENT configured account set by label — the
        TARGET_<LABEL>_TOKEN keys — instead of the default ATTACKER/OWNER/BYSTANDER, WITHOUT hand-
        writing an op. Returns op['accounts'] (role -> label); {} = default keys (byte-identical).
        The attacker!=owner fail-closed guard still fires on whatever labels are chosen."""
        if not self._ask_yes_no(
                "Use non-default account labels?", default=False,
                hint="OPTIONAL. Select a different configured account set (the TARGET_<LABEL>_TOKEN "
                     "keys) for one or more roles. Blank/No = the default ATTACKER/OWNER/BYSTANDER.",
                why="Same attacker and owner is REFUSED - a self-vs-self compare would false-confirm."):
            return {}
        accounts = {}
        for role in ("attacker", "owner", "bystander"):
            v = self._ask(f"{role} account label (blank = default {role.upper()})")
            if v:
                accounts[role] = v
        return accounts

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

    def _g(self, field: str) -> dict:
        """The guidance kwargs (hint/example/why) for a field, from the SINGLE shared FIELD_GUIDE so the
        interactive prompts and the editable template can never drift."""
        g = targets.FIELD_GUIDE[field]
        return {k: g[k] for k in ("hint", "example", "why") if k in g}

    def _target_overview(self) -> None:
        """A one-screen overview so the user is NOT walking blind — and (#7) surfaces the one-pass FILE
        form prominently at the top (not buried in help), plus (#4) announces the end-of-flow review."""
        self.echo("")
        self.echo(self._paint(
            f"  Tip: prefer filling ONE form instead of these prompts? Run  "
            f"{branding.command_name()} target --dump-template <file> , edit it once, then load it with  "
            f"{branding.command_name()} target --from-file <file> .", "cyan"))
        self.echo("")
        self.echo("Create a reusable target (saved as an editable file; tokens are NEVER stored on disk).")
        self.echo("You'll provide these, in order:")
        self.echo("  1) name   2) base URL   3) OpenAPI spec (or blank)   4) endpoint (method + path)")
        self.echo("  5) id location + parameter   6) attacker id   7) victim id   8) login file (optional)")
        self.echo("At the END you'll REVIEW everything and can fix any field before it's saved.")

    def _review_target(self, v: dict) -> None:
        """Show the target as entered, numbered to match the edit steps, so a misplaced value is caught
        BEFORE it is saved."""
        rows = [
            ("name", v.get("name", "")),
            ("base URL", v.get("base_url", "")),
            ("spec", v.get("spec_path", "") or "(none - spec-less; scan from an endpoints list)"),
            ("endpoint", f"{v.get('method', '')} {v.get('path_template', '')}".strip()),
            ("id", f"{v.get('id_location', '')} / {v.get('id_param', '')}".strip(" /")),
            ("attacker id", v.get("attacker_id", "")),
            ("victim id", v.get("victim_id", "")),
            ("login file", v.get("auth_spec_path", "") or "(none - paste tokens at verify time)"),
        ]
        self.echo("Review - the target as entered (nothing is saved yet):")
        for i, (lbl, val) in enumerate(rows, 1):
            self.echo(f"    [{i}] {lbl}: {val}")

    def do_target(self) -> None:
        self._target_overview()
        v: dict = {}

        def c_name() -> None:
            v["name"] = self._ask_required(targets.FIELD_GUIDE["name"]["label"], **self._g("name"))

        def c_url() -> None:
            v["base_url"] = self._ask_url(targets.FIELD_GUIDE["base_url"]["label"], **self._g("base_url"))

        def c_spec() -> None:
            v["spec_path"] = self._ask_optional_spec_path(
                targets.FIELD_GUIDE["spec_path"]["label"], **self._g("spec_path"))

        def c_endpoint() -> None:
            v["method"], v["path_template"] = self._pick_endpoint(v.get("spec_path", ""))

        def c_id() -> None:
            loc_idx = self._ask_menu(
                targets.FIELD_GUIDE["id_location"]["label"],
                ["path  - e.g. /orders/{id}", "query - e.g. ?report_id=123"],
                why=targets.FIELD_GUIDE["id_location"].get("why"))
            v["id_location"] = "query" if loc_idx == 1 else "path"
            if v["id_location"] == "path":
                v["id_param"] = self._default_id_param(v["path_template"], "path")
                self.echo(f"  id parameter: {v['id_param']}  (taken from the path template)")
            else:
                v["id_param"] = self._ask_required(
                    "Query parameter name that carries the id",
                    hint="The name of the query parameter holding the object id.", example="report_id")

        def c_attacker() -> None:
            v["attacker_id"] = self._ask_required(
                targets.FIELD_GUIDE["attacker_id"]["label"], **self._g("attacker_id"))

        def c_victim() -> None:
            v["victim_id"] = self._ask_required(
                targets.FIELD_GUIDE["victim_id"]["label"], **self._g("victim_id"))

        def c_login() -> None:
            v["auth_spec_path"] = self._ask_optional_login_file(
                targets.FIELD_GUIDE["auth_spec_path"]["label"], **self._g("auth_spec_path"))

        steps = [c_name, c_url, c_spec, c_endpoint, c_id, c_attacker, c_victim, c_login]
        for fn in steps:
            fn()

        # Review + confirm/go-back: blank = save; a number re-collects that field (so a misplaced value
        # like a URL typed into the name slot is caught and fixed BEFORE anything is created).
        while True:
            self._review_target(v)
            choice = self._ask("Save this target? Press Enter to save, or a number (1-8) to edit")
            if not choice:
                break
            if choice.isdigit() and 1 <= int(choice) <= len(steps):
                steps[int(choice) - 1]()
                continue
            self.echo(f"  ! Enter a number 1-{len(steps)} to edit a field, or leave blank to save.")

        t = targets.Target(
            name=v["name"], base_url=v["base_url"], spec_path=v.get("spec_path", ""), method=v["method"],
            path_template=v["path_template"], id_location=v["id_location"], id_param=v["id_param"],
            attacker_id=v["attacker_id"], victim_id=v["victim_id"], auth_spec_path=v.get("auth_spec_path", ""),
        )
        path = targets.save_target(t)
        self.selected = t
        self.echo(f"  saved target '{t.name}' -> {path}")
        self.echo(f"  selected '{t.name}'. Run 'verify' to confirm it, or 'scan' to auto-discover more.")

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

        # -- optional capabilities (2a): all default OFF/blank => byte-identical to before --
        assert_owner_only = self._ask_yes_no(
            "Assert this resource should be owner-private?", default=False,
            why="With it, a resource EVERY authenticated user can read (but anonymous cannot) is "
                "surfaced as [INCONCLUSIVE broken-for-all / human review] instead of suppressed.")
        accounts = self._ask_account_labels()

        if not t.auth_spec_path:
            self.echo("  You'll be asked for the Bearer tokens (input hidden; the tool confirms receipt):")
            self.echo("    - Attacker token: the ATTACKER account (the attack is sent as the attacker).")
            self.echo("    - Owner token:    the VICTIM/owner (re-read ONLY as the owner; Enter to skip).")
            self.echo("    Example value: Bearer eyJhbGciOi...")
            bystander_token = self._env_or_secret(
                "bystander", "Bystander / third-account token", optional=True,
                hint="A THIRD account that does NOT own the resource.",
                why="Lets the tool tell a public/shared resource from a real cross-user leak. Used ONLY "
                    "to re-read as the bystander, never to attack.")
        else:
            self.echo(f"  Using the login file for auto-relogin: {t.auth_spec_path}")
            bystander_token = ""   # --auth bystander comes from config (login creds), unchanged

        op = t.to_op()
        if assert_owner_only:
            op["assert_owner_only"] = True         # broken-for-all disclosure opt-in (D30)
        if accounts:
            op["accounts"] = accounts              # #7 per-role account labels (config-key selection)

        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        try:
            json.dump(op, tmp)
            tmp.close()
            kwargs = dict(
                target=t.base_url, spec_path=t.spec_path, op_path=tmp.name,
                config_path=self.config_path, prompt=self.prompt,
                prompt_secret=self._confirming_secret, echo=self.echo, err=self.echo,
                auth_spec_path=(t.auth_spec_path or None),
                bystander_token=(bystander_token or None),   # masked; routes ONLY to bystander_credential
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

    def _ask_optional_existing_file(self, label: str, *, optional_hint: Optional[str] = None, **g) -> str:
        self._guide(**g, optional=True, optional_hint=optional_hint)
        while True:
            v = self._ask(label)
            if not v:
                return ""
            if os.path.isfile(v):
                return v
            self.echo(f"  ! That file wasn't found: {v}. Leave blank to skip, or enter a valid path.")

    def _collect_id_source(self) -> tuple:
        """Optionally read a small id-hints file. Plain language, NO raw JSON in the prompt, NO tier a/b
        jargon (#5): most runs skip this and the tool sources ids itself. Returns (id_map, collections)."""
        id_map: dict = {}
        collections: dict = {}
        src = self._ask_optional_existing_file(
            "Id hints file",
            hint="Most runs: press Enter to skip - the tool finds the ids to compare itself.",
            why="Only needed if you're testing many endpoints and want to pin the exact attacker/victim "
                "ids per endpoint. (A small JSON file listing each endpoint's two ids.)")
        if src:
            try:
                with open(src, encoding="utf-8") as fh:
                    d = json.load(fh)
                id_map = dict(d.get("ids") or {})
                collections = dict(d.get("collections") or {})
            except Exception as ex:
                self.echo(f"  ! Could not read the id hints file ({type(ex).__name__}); ignoring it.")
        return id_map, collections

    def _scan_review(self, t, spec, id_map, collections, auth_spec_path, assert_owner_only,
                     has_bystander: bool) -> None:
        """#8: a pre-run REVIEW of the scan plan (mirrors target's review) so the user sees exactly what
        will run — target, catalog source, tokens received, bystander, owner-private assertion, id hints —
        before anything executes. Tokens are shown as received/absent ONLY (never a value)."""
        self.echo("")
        self.echo(self._paint("Review - the scan about to run (nothing has run yet):", "bold"))
        catalog_src = "the target's OpenAPI spec" if spec is not None else "an endpoints list (no spec)"
        n_ids = len(id_map or {}) + len(collections or {})
        self.echo(f"    target:   {t.base_url}")
        self.echo(f"    catalog:  {catalog_src}")
        self.echo("    tokens:   attacker + owner received"
                  + ("; bystander received" if has_bystander else "; no bystander (public-vs-leak check off)"))
        self.echo(f"    [1] treat resources as owner-private (broken-for-all): {'YES' if assert_owner_only else 'no'}")
        self.echo(f"    [2] id hints: " + (f"{n_ids} provided" if n_ids
                                           else "none - the tool auto-sources; an unsourced one is skipped"))
        self.echo("    [3] re-enter tokens (fix a mistyped attacker / owner / bystander token)")   # #5
        if auth_spec_path:
            self.echo(f"    login:    {auth_spec_path} (auto-relogin)")

    def do_scan(self) -> None:
        """Auto-discovery onramp: from the selected target's base URL + spec, the AI proposes BOLA
        candidates, CODE vets each, ids are sourced (id map / declared collections), and the SAME
        zero-FP confirm runs on every op. Prints one aggregated, tier-grouped report. AI never widens
        what gets confirmed — code vets every op and the engine judges each one."""
        if self.selected is None:
            self.echo("  No target selected. Use 'target' to create one (scan uses its base URL + spec), "
                      "or 'targets' to pick one.")
            return
        if not (reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY)):
            self.echo("  No API key configured - scan needs one for candidate discovery AND for the "
                      "confirm judge. Run 'config' first. Nothing was sent.")
            return
        # #4: announce up-front that a review comes at the end, so a mistyped field doesn't feel final.
        self.echo("")
        self.echo("scan finds BOLA/IDOR candidates and confirms each. A few quick questions - then you'll")
        self.echo("REVIEW the whole plan and can change a setting before anything runs.")
        t = self.selected
        # Endpoint source: the target's OpenAPI spec if it loads (BYTE-IDENTICAL to today), ELSE a
        # user-provided endpoints list (scan works WITHOUT a spec). `confirm_spec` is a spec dict fed to
        # the confirm so it gets the SAME catalog whichever source produced it.
        spec = None
        endpoints = None
        confirm_spec = None
        if t.spec_path and os.path.isfile(t.spec_path):
            try:
                spec = confirm_spec = _load_spec_file(t.spec_path)
            except Exception:
                spec = confirm_spec = None
        if spec is None:
            # #3: this is a required CHOICE (spec / traffic / endpoints), not two independent "optionals".
            # Frame it as "provide ONE source", and if the user supplies NEITHER, say exactly what's needed.
            self.echo("")
            self.echo("  This target has no OpenAPI spec. Provide ONE source for scan to discover from:")
            self.echo("    * a CAPTURED-TRAFFIC file (proxy your app via mitmproxy/Burp or a browser HAR), OR")
            self.echo("    * a plain 'METHOD /path' ENDPOINTS file.")
            from backend.app.services.endpoint_catalog import spec_from_endpoints
            tf_path = self._ask_optional_existing_file(
                "Traffic capture file (HAR or raw-HTTP)",
                optional_hint="(press Enter to use an endpoints file instead)",
                hint="A .har export (browser DevTools / Burp) or a raw-HTTP dump.",
                why="No spec? Proxy your traffic and point scan at the capture - it finds the endpoints for "
                    "you. Only requests to THIS target are used; off-target traffic is dropped.")
            if tf_path:
                from backend.app.cli.scan_traffic import endpoints_from_traffic_file
                try:
                    endpoints = endpoints_from_traffic_file(tf_path, t.base_url)
                except Exception as ex:
                    self.echo(f"  ! [NOT DATA] could not read the traffic file ({type(ex).__name__}): {ex}")
                    return
                if not endpoints:
                    self.echo("  ! [NOT DATA] no in-scope requests found in the traffic file "
                              f"(nothing matched {t.base_url}). Nothing to scan.")
                    return
                confirm_spec = spec_from_endpoints(endpoints)
                self.echo(f"  Discovered {len(endpoints)} in-scope endpoint(s) from the capture.")
            else:
                ep_path = self._ask_optional_existing_file(
                    "Endpoints file (METHOD /path list)",
                    optional_hint="(press Enter only if you have NEITHER source - scan then cannot run)",
                    hint="A JSON array of \"GET /path/{id}\" strings, OR newline-delimited METHOD /path lines.",
                    why="Lets scan discover candidates WITHOUT an OpenAPI spec; templated {id} paths detect best.")
                if not ep_path:
                    self.echo("  ! You must provide one of: a spec (on the target), a traffic capture, or "
                              "an endpoints file. Nothing to scan.")
                    return
                try:
                    from backend.app.cli.external_verify import _load_endpoints_file
                    endpoints = _load_endpoints_file(ep_path)
                    confirm_spec = spec_from_endpoints(endpoints)
                except Exception as ex:
                    self.echo(f"  ! [NOT DATA] could not read the endpoints file ({type(ex).__name__}): {ex}")
                    return

        # id hints (optional) — plain-language prompt; the tool sources ids itself when skipped (#5).
        id_map, collections = self._collect_id_source()

        # --auth (optional, 2b): a login-declaration file drives auto-relogin per candidate, so a token
        # that expires mid-scan is refreshed (per-account, incl. D28 owner-only) and the candidate
        # completes instead of dying to NOT DATA. Blank -> static tokens (today's scan, byte-identical).
        auth_spec_path = self._ask_optional_login_file(
            "Login file (optional) - auto-relogin",
            hint="OPTIONAL path to a login-declaration JSON (multi-step / OAuth). Blank = paste tokens.",
            why="With it, a token that expires mid-scan is re-obtained per-account so the candidate "
                "still completes. Without it, an expired token makes that candidate NOT DATA.")
        assert_owner_only = self._ask_yes_no(
            "Treat discovered resources as owner-private (broken-for-all disclosure)?", default=False,
            why="With it, a resource EVERY authenticated user can read (but anonymous cannot) is "
                "surfaced as [INCONCLUSIVE broken-for-all / human review] instead of suppressed.")

        # Lazy imports (avoid pulling the engine at module import; keep the console light).
        import asyncio
        from pydantic import SecretStr
        from backend.app.cli import relogin
        from backend.app.cli.external_verify import (
            _verify_external, _verify_external_relogin, _resolve_bystander_token,
            _build_relogin_providers, _identity_collision_reason,
        )
        from backend.app.services.deep_verifier import OwnerCredential, execute_deep_verification
        from backend.app.cli.scan_run import run_scan
        from backend.app.cli.scan_report import render_scan_report

        settings.AI_DEEP_VERIFY_ENABLED = True                       # runtime-only, mirrors verify
        engine = self.engine or execute_deep_verification
        model = settings.LLM_MODEL or None
        kw = {}
        if self.scan_provider_factory is not None:
            kw["provider_factory"] = self.scan_provider_factory

        if auth_spec_path:
            # RE-LOGIN scan: the THREE per-account TokenProviders are built ONCE and REUSED across every
            # candidate (option a) — a token obtained for candidate 1 is reused for candidate 2 and
            # refreshed only on 401. Each account keeps its OWN provider/session (identity isolation).
            try:
                login_spec = relogin.LoginSpec.from_file(auth_spec_path)
                attacker_cred, owner_cred = relogin.resolve_login_credentials(
                    self.config_path, self.prompt, self._confirming_secret)
                bystander_cred = relogin.resolve_bystander_login_credential(self.config_path)
            except Exception as ex:
                self.echo(f"  ! could not set up --auth re-login: {type(ex).__name__}: {ex}")
                return
            reason = _identity_collision_reason(
                attacker_cred.username, owner_cred.username,
                bystander_cred.username if bystander_cred is not None else None)
            if reason:
                self.echo(f"  ! {reason}")               # attacker == owner -> refused (fail-closed)
                return
            providers = _build_relogin_providers(
                t.base_url, login_spec, attacker_cred, owner_cred, bystander_cred)

            async def _orchestrate():
                atk_p, own_p, bys_p = providers
                atk_tok = await atk_p.token()             # login ONCE per account (primes the cache)
                own_tok = await own_p.token()
                bys_tok = await bys_p.token() if bys_p is not None else None
                r = _identity_collision_reason(atk_tok, own_tok, bys_tok)
                if r:
                    raise ValueError(r)

                async def run_op(op):
                    # the SAME single-op relogin call verify uses, REUSING the persisted providers
                    # (refresh-on-401 mid-scan, incl. D28 owner-only) — no re-login from scratch.
                    return await _verify_external_relogin(
                        t.base_url, confirm_spec, op, login_spec, attacker_cred, owner_cred, model, engine,
                        bystander_cred=bystander_cred, providers=providers)

                return await run_scan(
                    t.base_url, spec, run_op=run_op, endpoints=endpoints, id_map=id_map,
                    collections=collections,
                    harvest_attacker_cred=OwnerCredential.from_config(atk_tok),   # attacker harvest ONLY
                    harvest_owner_cred=OwnerCredential.from_config(own_tok),      # owner harvest ONLY
                    model=model, assert_owner_only=assert_owner_only, **kw)

            self.echo(f"Scanning {t.base_url} (auto-relogin) - discovering + confirming each candidate...")
            run_coro = _orchestrate()
        else:
            # STATIC-token scan: tokens come from the ENVIRONMENT (#6) when TARGET_*_TOKEN is set, else a
            # masked paste. Each becomes a SecretStr routed ONLY per account; a value is NEVER echoed.
            self.echo("")
            self.echo("Tokens - from the environment (TARGET_ATTACKER_TOKEN / _OWNER_TOKEN / _BYSTANDER_TOKEN)")
            self.echo("if set, otherwise paste them (hidden):")
            attacker = self._env_or_secret("attacker", "Attacker token")
            owner = self._env_or_secret("owner", "Owner/victim token")
            if not attacker or not owner:
                self.echo("  ! scan needs BOTH an attacker and an owner token (the confirm compares them).")
                return
            bystander = self._env_or_secret(
                "bystander", "Bystander / third-account token", optional=True,
                hint="A THIRD account that does NOT own the resource.",
                why="Lets scan tell a public/shared resource from a real cross-user leak. Used ONLY to "
                    "re-read as the bystander, never to attack.")
            attacker_tok, owner_tok = SecretStr(attacker), SecretStr(owner)
            # a bystander from env/prompt overrides the config-file one; EITHER way it routes ONLY into
            # bystander_credential (never the attack path) via _verify_external below.
            bystander_tok = SecretStr(bystander) if bystander else _resolve_bystander_token(self.config_path)
            # #7 FP NAIL (fail-closed): DISTINCT identities required — fires on ENV tokens too. attacker==
            # owner -> the D24 owner-view corroborates self-vs-self -> a false [CONFIRMED]. Refuse BEFORE
            # any candidate runs (the engine is never called on a collision).
            reason = _identity_collision_reason(
                attacker, owner, reveal_secret(bystander_tok) if bystander_tok is not None else None)
            if reason:
                self.echo(f"  ! [NOT DATA] {reason}")
                return

            # #8 pre-run REVIEW: show the whole plan; let the user change a setting or cancel before it runs.
            while True:
                self._scan_review(t, spec, id_map, collections, auth_spec_path, assert_owner_only,
                                  bystander_tok is not None)
                choice = self._ask("Press Enter to RUN, a number to change a setting, or 'q' to cancel")
                if not choice:
                    break
                if choice.lower() in ("q", "quit", "cancel"):
                    self.echo("  Scan cancelled - nothing was sent.")
                    return
                if choice == "1":
                    assert_owner_only = self._ask_yes_no(
                        "Treat discovered resources as owner-private (broken-for-all disclosure)?",
                        default=assert_owner_only,
                        why="Surfaces a resource EVERY authenticated user can read (anonymous cannot) as "
                            "[INCONCLUSIVE broken-for-all] instead of suppressing it.")
                    continue
                if choice == "2":
                    id_map, collections = self._collect_id_source()
                    continue
                if choice == "3":
                    # #5: correct a mistyped token WITHOUT restarting the whole flow. Re-collect all three
                    # (env-first, masked), re-run the fail-closed collision guard; on any problem KEEP the
                    # previous tokens (never leave the run with a half-updated / colliding identity set).
                    a2 = self._env_or_secret("attacker", "Attacker token")
                    o2 = self._env_or_secret("owner", "Owner/victim token")
                    if not a2 or not o2:
                        self.echo("  ! scan needs BOTH an attacker and an owner token; keeping the previous ones.")
                        continue
                    b2 = self._env_or_secret(
                        "bystander", "Bystander / third-account token", optional=True,
                        hint="A THIRD account that does NOT own the resource.",
                        why="Lets scan tell a public/shared resource from a real cross-user leak.")
                    r2 = _identity_collision_reason(a2, o2, b2 or None)
                    if r2:
                        self.echo(f"  ! [NOT DATA] {r2}  (keeping the previous tokens)")
                        continue
                    attacker, owner, bystander = a2, o2, b2
                    attacker_tok, owner_tok = SecretStr(a2), SecretStr(o2)
                    bystander_tok = SecretStr(b2) if b2 else _resolve_bystander_token(self.config_path)
                    self.echo("  Tokens updated.")
                    continue
                self.echo("  ! Enter a number (1-3) to change a setting, blank to run, or 'q' to cancel.")

            async def run_op(op):
                return await _verify_external(t.base_url, confirm_spec, op, attacker_tok, owner_tok,
                                              model, engine, bystander_tok=bystander_tok)

            self.echo(f"Scanning {t.base_url} - discovering BOLA candidates and confirming each...")
            run_coro = run_scan(
                t.base_url, spec, run_op=run_op, endpoints=endpoints, id_map=id_map, collections=collections,
                harvest_attacker_cred=OwnerCredential.from_config(attacker),   # attacker harvest creds ONLY
                harvest_owner_cred=OwnerCredential.from_config(owner),         # owner harvest creds ONLY
                model=model, assert_owner_only=assert_owner_only, **kw)

        try:
            result = asyncio.run(run_coro)
        except Exception as ex:
            self.echo(f"  ! scan run error against {t.base_url}: {type(ex).__name__}: {ex}")
            return
        self.echo(render_scan_report(result, t.base_url))

    def do_demo(self) -> None:
        """Zero-setup example against the built-in lab (no Docker/target/tokens). Delegates to
        run.demo (the confirm() lab path). Lazy import avoids any import cycle."""
        import run
        run.demo()
