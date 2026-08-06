# ==============================================================================
# Calm, honest console copy — intro + a real command guide. No competitor-comparison
# text, no raw-HTTP firehose, no hacker-movie styling (all explicitly rejected —
# they break the tool's honest, credential-safe posture).
# ==============================================================================
from __future__ import annotations

from typing import List

# (name, what it does, when to use it) — the single source for the help guide AND the
# prompt completer, so they can never drift.
_HELP = [
    ("help",    "Show this guide.",
     "Anytime you're unsure what to do."),
    ("demo",    "Confirm a real BOLA on a built-in lab - no Docker, no target, no tokens.",
     "Start here to see what 'confirming a vulnerability' looks like (needs an API key: run 'config' first)."),
    ("config",  "Set the AI provider, API key, and model.",
     "Run once before verify/demo; re-run anytime to change it."),
    ("target",  "Create a reusable target: base URL, spec, endpoint, and the two ids to compare.",
     "When you have a running target and two accounts to test."),
    ("targets", "List saved targets and select one.",
     "To switch between targets you've created."),
    ("verify",  "Run the confirmation on the selected target and show the evidence chain.",
     "After selecting a target; you'll paste the two tokens (hidden). Optional prompts: a third/"
     "bystander token (public-resource discrimination), an owner-private assertion (broken-for-all), "
     "and non-default account labels (#7 - a different configured account set)."),
    ("scan",    "Auto-discover BOLA candidates from the target's spec and confirm each (aggregated report).",
     "After selecting a target; the AI proposes candidates, code vets them, the engine judges each. "
     "Optional prompts: a bystander token and an owner-private assertion (broken-for-all)."),
    ("status",  "Show what's configured (API key redacted) and the selected target.",
     "To check your setup."),
    ("quit",    "Leave the console.",
     ""),
]

# (name, short description) for the prompt completer.
COMMANDS = [(name, what) for name, what, _when in _HELP]


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
        "New here? Type 'demo' to see a confirmation with zero setup, 'help' for the",
        "full guide, or 'config' to set your API key. 'quit' to leave.",
        "",
    ]


def help_lines() -> List[str]:
    out = ["", "Commands (type the name at the prompt):", ""]
    for name, what, when in _HELP:
        out.append(f"  {name}")
        out.append(f"      {what}")
        if when:
            out.append(f"      when: {when}")
    out.append("")
    out.append("Typical flow:  config  ->  target  ->  verify     (or just  demo  to start).")
    out.append("")
    return out
