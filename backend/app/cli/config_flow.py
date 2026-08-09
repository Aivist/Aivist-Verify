# ==============================================================================
# Interactive first-run setup for the CLI (`<brand> config`).
#
# It ASKS the user (the tool prompts; the user never edits files or exports env
# vars) for a provider, an API key (hidden input), an optional base_url (for
# OpenAI-compatible relays / gateways / local servers), and a model, then persists
# them to a per-user TOML file under ~/.<brand>/ (NOT in the repo). The file is
# created with restrictive permissions (0600 where the OS honors it).
#
# CREDENTIAL DISCIPLINE: the API key is read via getpass (masked), held only long
# enough to write the file, and is NEVER echoed, printed, or logged. The on-screen
# summary shows it as ***REDACTED***. The plaintext key lives ONLY in the 0600 file.
#
# This module WRITES config; it does not read settings. Making the written file
# actually load is the settings-source change in backend/app/core/config.py.
# ==============================================================================
from __future__ import annotations

import getpass
import os
from typing import Callable, Dict, List, Optional

from backend.app.cli import branding

_REDACTED = "***REDACTED***"

# Provider choices surfaced in the prompt. The relay/DeepSeek/Kimi/GLM/Qwen/
# Grok/Ollama ecosystem all ride the single 'openai' (OpenAI-compatible) provider
# via base_url — that capability already exists at the provider layer.
_PROVIDERS = ("gemini", "openai", "anthropic")

# Suggested default model per provider (a prompt default only; the user may override).
_DEFAULT_MODEL = {
    "gemini": "gemini-2.5-pro",
    "openai": "",                       # no universal default; relay/model-specific
    "anthropic": "claude-3-5-sonnet-latest",
}


def _toml_escape(s: str) -> str:
    """Escape a value for a TOML basic (double-quoted) string."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _to_toml(data: Dict[str, str]) -> str:
    """Serialize a flat {KEY: str} mapping to TOML. All values are strings here
    (provider / key / url / model), so a basic-string writer is sufficient and
    avoids a third-party TOML-writer dependency (stdlib tomllib is read-only)."""
    return "".join(f'{k} = "{_toml_escape(str(v))}"\n' for k, v in data.items())


def write_config(data: Dict[str, str], path: str) -> None:
    """Write the config mapping to `path` as TOML, creating ~/.<brand>/ if needed.

    The file is created with 0600 at open time (O_CREAT mode) so the API key is
    never momentarily world-readable; chmod is re-applied best-effort. On Windows
    the mode bits are largely advisory (files under the user profile are already
    user-scoped by the default ACL) — hence 'where the OS allows'.
    """
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    content = _to_toml(data)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def redacted_summary(data: Dict[str, str]) -> List[str]:
    """Human summary lines for the saved config — the API key is NEVER shown."""
    out = [f"provider: {data.get('LLM_PROVIDER')}"]
    if data.get("LLM_BASE_URL"):
        out.append(f"base_url: {data['LLM_BASE_URL']}")
    if data.get("LLM_MODEL"):
        out.append(f"model:    {data['LLM_MODEL']}")
    out.append(
        "API key:  " + (f"{_REDACTED} (stored; file permissions restricted)"
                        if data.get("LLM_API_KEY") else "(not set)")
    )
    return out


def run_config_flow(
    *,
    prompt: Callable[[str], str] = input,
    secret_prompt: Callable[[str], str] = getpass.getpass,
    echo: Callable[..., None] = print,
    path: Optional[str] = None,
) -> int:
    """Interactive setup. Returns a process exit code (0 = written).

    All I/O is injected (prompt / secret_prompt / echo / path) so the flow is fully
    offline-testable at zero API cost and with no real terminal or home directory.
    """
    path = path or branding.config_file_path()
    echo(f"{branding.product_name()} - setup")
    echo(f"This saves your provider, API key, and model to: {path}")
    echo("")

    # --- provider ---------------------------------------------------------
    raw = prompt("Provider - [gemini] / openai / anthropic: ").strip().lower()
    provider = raw or "gemini"
    if provider not in _PROVIDERS:
        echo(f"Unknown provider {provider!r}; using 'gemini'.")
        provider = "gemini"
    data: Dict[str, str] = {"LLM_PROVIDER": provider}

    # --- API key (masked) -------------------------------------------------
    key = secret_prompt("API key (input hidden): ").strip()
    if key:
        data["LLM_API_KEY"] = key
    else:
        echo("No API key entered - re-run setup later; the tool needs a key to run the engine.")

    # --- base_url (OpenAI-compatible only) --------------------------------
    if provider == "openai":
        base = prompt("Base URL for the OpenAI-compatible endpoint (e.g. https://host/v1): ").strip()
        if base:
            data["LLM_BASE_URL"] = base

    # --- model ------------------------------------------------------------
    default_model = _DEFAULT_MODEL[provider]
    label = (f"Model [{default_model}]: " if default_model
             else "Model (e.g. gpt-4o-mini / deepseek-chat / llama3.1): ")
    model = prompt(label).strip() or default_model
    if model:
        data["LLM_MODEL"] = model

    # --- persist ----------------------------------------------------------
    write_config(data, path)
    echo("")
    echo(f"Saved to {path}")
    for line in redacted_summary(data):
        echo("  " + line)
    echo("")
    echo(f"Next: {branding.verify_command()} --caseset <path> --case <id>")
    return 0
