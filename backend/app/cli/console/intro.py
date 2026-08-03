# ==============================================================================
# Calm, honest console copy — intro, command list, help. No competitor-comparison
# text, no raw-HTTP firehose, no hacker-movie styling (all explicitly rejected —
# they break the tool's honest, credential-safe posture).
# ==============================================================================
from __future__ import annotations

from typing import List

# (name, one-line description) — the single source for both the prompt completer and help.
COMMANDS = [
    ("help",    "list commands"),
    ("config",  "set up the AI provider / API key / model"),
    ("target",  "create or edit a target to confirm"),
    ("targets", "list saved targets and select one"),
    ("verify",  "run confirmation on the selected target"),
    ("status",  "show what's configured (API key redacted)"),
    ("quit",    "leave the console"),
]


def intro_lines(product_name: str) -> List[str]:
    """A few honest lines: what this is. Code adjudicates, not the model."""
    return [
        "",
        f"{product_name} - interactive console",
        "",
        "A BOLA/IDOR access-control confirmation engine. It does not merely flag a",
        "candidate: it confirms whether one user can actually reach another user's",
        "resource, and CODE adjudicates the verdict - not the model. Every confirmation",
        "carries a reproducible evidence chain.",
        "",
        "Type 'help' for commands, 'config' to set up your API key, 'quit' to leave.",
        "",
    ]


def help_lines() -> List[str]:
    out = ["", "Commands:"]
    for name, desc in COMMANDS:
        out.append(f"  {name:9} {desc}")
    out.append("")
    return out
