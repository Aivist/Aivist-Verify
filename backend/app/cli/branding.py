# ==============================================================================
# BRAND — the single source of truth for every user-facing brand string.
#
# The umbrella product name is NOT finalized. Rather than sprinkle a literal name
# across the codebase (which would make renaming a repo-wide find-replace), EVERY
# place the brand appears derives from ONE constant, `BRAND_NAME`, below:
#   * the console command the user types                (command_name)
#   * the display / banner / --help name                (display_name / product_name)
#   * the per-user config directory  ~/.<brand>/        (config_dir / config_file_path)
#   * the env var that overrides the config file path   (config_file_env_var)
# Finalizing the name is therefore a ONE-LINE change here — never a scatter of edits.
# A test (test_cli_branding_and_config.py) asserts these all derive from BRAND_NAME so
# no stray hard-coded copy can silently drift.
#
# The "verify" SUFFIX is LOCKED — it is NOT a variable. The product is "<Brand> Verify",
# invoked as `<brand> verify`. Only the brand token below is provisional.
# ==============================================================================
from __future__ import annotations

import os

# TODO(naming): brand name pending director sign-off — single point of change.
BRAND_NAME = "aivist"  # PROVISIONAL — umbrella name not finalized; single point of change.

# The locked product suffix. Deliberately a plain constant, not derived/parameterized.
VERIFY_SUFFIX = "verify"


def command_name() -> str:
    """The console command a user types (also argparse `prog`), e.g. 'aivist'."""
    return BRAND_NAME


def display_name() -> str:
    """Human-readable brand, e.g. 'Aivist'."""
    return BRAND_NAME.capitalize()


def product_name() -> str:
    """The product name: '<Brand> Verify' (the verify suffix is locked)."""
    return f"{display_name()} {VERIFY_SUFFIX.capitalize()}"


def verify_command() -> str:
    """How the verify tool is invoked, e.g. 'aivist verify'."""
    return f"{command_name()} {VERIFY_SUFFIX}"


def config_dir() -> str:
    """Per-user config directory: ~/.<brand>/ ."""
    return os.path.join(os.path.expanduser("~"), "." + BRAND_NAME)


def config_file_env_var() -> str:
    """Name of the env var that overrides the config file path (tests / power users)."""
    return f"{BRAND_NAME.upper()}_CONFIG_FILE"


def config_file_path() -> str:
    """Resolved config file path: the env override if set, else ~/.<brand>/config.toml."""
    override = os.environ.get(config_file_env_var())
    if override:
        return override
    return os.path.join(config_dir(), "config.toml")
