# ==============================================================================
# Anthropic (Claude) provider — its own Messages protocol (system is a top-level
# parameter, not a message; max_tokens is required). Lazy-imports `anthropic`.
#
# Connectivity, NOT correctness. Claude has no strict JSON-mode flag; json_mode is a
# best-effort hint (the caller's system prompt already demands JSON). The zero-FP
# evidence is measured on gemini-2.5-pro only and does not transfer here.
# ==============================================================================
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from backend.app.core.config import settings, reveal_secret
from backend.app.services.llm import LLMConfigError, LLMError, LLMTransientError

_MISSING_SDK = (
    "The 'anthropic' SDK is required for LLM_PROVIDER='anthropic'. Install it with: pip install anthropic"
)
# Anthropic requires max_tokens; a generous default for a JSON verdict / analysis.
_DEFAULT_MAX_TOKENS = 4096


class AnthropicProvider:
    def __init__(self) -> None:
        self._client: Any = None

    @property
    def default_model(self) -> str:
        return settings.LLM_MODEL or ""

    def _api_key(self):
        return reveal_secret(settings.LLM_API_KEY)

    def is_configured(self) -> bool:
        return bool(self._api_key())

    def _get_client(self, AsyncAnthropic):
        if self._client is None:
            kwargs: Dict[str, Any] = {"api_key": self._api_key()}
            if settings.LLM_BASE_URL:
                kwargs["base_url"] = settings.LLM_BASE_URL
            self._client = AsyncAnthropic(**kwargs)
        return self._client

    async def generate(
        self, *, messages: List[Dict[str, str]], system: str, json_mode: bool,
        temperature: float, model: str, timeout: float, max_attempts: int = 1,
    ) -> str:
        try:
            import anthropic
            from anthropic import AsyncAnthropic
        except ImportError as e:
            raise LLMConfigError(_MISSING_SDK) from e

        client = self._get_client(AsyncAnthropic)

        # Claude: `system` is a top-level param; messages carry user/assistant turns.
        claude_messages = [
            {"role": ("assistant" if m.get("role") == "assistant" else "user"),
             "content": m.get("text", "")}
            for m in messages
        ]
        kwargs: Dict[str, Any] = {
            "model": model, "system": system, "messages": claude_messages,
            "temperature": temperature, "max_tokens": _DEFAULT_MAX_TOKENS,
        }

        transient = tuple(
            t for t in (
                getattr(anthropic, "APIConnectionError", None),
                getattr(anthropic, "APITimeoutError", None),
                getattr(anthropic, "RateLimitError", None),
            ) if t is not None
        )
        status_error = getattr(anthropic, "APIStatusError", None)
        api_error = getattr(anthropic, "APIError", Exception)

        attempts = max(1, max_attempts)
        last_exc: Any = None
        for attempt in range(attempts):
            try:
                resp = await asyncio.wait_for(
                    client.messages.create(**kwargs), timeout=timeout
                )
                # resp.content is a list of blocks; concatenate the text blocks.
                parts = [getattr(b, "text", "") for b in (resp.content or [])]
                return "".join(parts)
            except transient as e:  # type: ignore[misc]
                last_exc = e
                if attempt < attempts - 1:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                raise LLMTransientError(str(e)) from e
            except Exception as e:
                if status_error is not None and isinstance(e, status_error):
                    code = getattr(e, "status_code", 0) or 0
                    if code >= 500:
                        last_exc = e
                        if attempt < attempts - 1:
                            await asyncio.sleep(2 * (attempt + 1))
                            continue
                        raise LLMTransientError(str(e)) from e
                    raise LLMError(str(e)) from e
                if isinstance(e, api_error):
                    raise LLMError(str(e)) from e
                raise
        raise LLMTransientError(str(last_exc)) from last_exc
