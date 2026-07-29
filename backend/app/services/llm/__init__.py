# ==============================================================================
# LLM provider abstraction — a thin seam over the model call, so the engine can
# talk to any backend (Gemini today; OpenAI-compatible relays / Anthropic later)
# WITHOUT the verdict logic ever knowing which one. It changes HOW the model is
# called, never WHAT consumes its output (`resp.text` -> the same JSON string).
#
# HARD RED LINE (Gemini): the GeminiProvider reproduces today's SDK call
# argument-for-argument. All 430/430 zero-FP evidence rides that path.
#
# The abstraction's ONLY guarantee is "you can connect and get a completion back."
# It does NOT re-validate the zero-false-positive claim on any non-Gemini model —
# that evidence is, and stays, measured on gemini-2.5-pro only.
# ==============================================================================
from __future__ import annotations

from typing import List, Dict, Optional, Protocol, runtime_checkable

from backend.app.core.config import settings


# --------------------------------------------------------------------------
# Neutral exception hierarchy. Providers map their SDK-specific errors onto
# these so the CALLER's retry / fallback logic stays provider-agnostic.
# --------------------------------------------------------------------------
class LLMError(Exception):
    """Base for any provider failure (non-transient / final)."""


class LLMTransientError(LLMError):
    """A retryable transient failure (e.g. HTTP 503 / overloaded). The caller's
    retry loop decides whether to retry; providers signal retryability via this type."""


class LLMConfigError(LLMError):
    """Provider is unusable as configured (SDK not installed, unknown provider,
    missing required config). Callers treat this as a degraded/fail-safe path."""


# --------------------------------------------------------------------------
# The interface. One async `generate` parameterized by exactly the axes the two
# call sites differ on (turns, JSON mode, temperature, model, timeout, retries).
# Roles in `messages` are neutral: "user" | "assistant". Each provider maps them
# (the Gemini provider maps "assistant" -> "model", producing the identical
# Content it builds today).
# --------------------------------------------------------------------------
@runtime_checkable
class LLMProvider(Protocol):
    #: The provider's default model when a per-call `model` override is not given.
    default_model: str

    def is_configured(self) -> bool:
        """True iff this provider has what it needs to make a call (e.g. an API key)."""
        ...

    async def generate(
        self,
        *,
        messages: List[Dict[str, str]],   # ordered [{"role": "user"|"assistant", "text": str}]
        system: str,
        json_mode: bool,
        temperature: float,
        model: str,
        timeout: float,
        max_attempts: int = 1,
    ) -> str:
        """Send `messages` (with `system` instruction) and return the completion TEXT.
        Raises LLMTransientError on a retryable failure, LLMConfigError on an unusable
        config, or LLMError otherwise. `max_attempts` bounds transient-retry (1 = no retry)."""
        ...


# --------------------------------------------------------------------------
# Factory. Selects the provider from settings.LLM_PROVIDER (default "gemini").
# Providers are imported LAZILY so the default install needs only google-genai;
# openai / anthropic are optional deps pulled in only when their provider is chosen.
# --------------------------------------------------------------------------
def get_provider(name: Optional[str] = None) -> "LLMProvider":
    resolved = (name or settings.LLM_PROVIDER or "gemini").strip().lower()
    if resolved in ("gemini", "google"):
        from backend.app.services.llm.gemini import GeminiProvider
        return GeminiProvider()
    if resolved in ("openai", "openai_compat", "openai-compatible", "compat"):
        from backend.app.services.llm.openai_compat import OpenAICompatProvider
        return OpenAICompatProvider()
    if resolved in ("anthropic", "claude"):
        from backend.app.services.llm.anthropic import AnthropicProvider
        return AnthropicProvider()
    raise LLMConfigError(
        f"Unknown LLM_PROVIDER {resolved!r}; expected 'gemini' | 'openai' | 'anthropic'."
    )
