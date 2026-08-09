# ==============================================================================
# OpenAI-COMPATIBLE provider — ONE implementation for the whole compatible ecosystem
# via a configurable base_url: OpenAI itself, any relay/gateway, DeepSeek,
# Kimi/Moonshot, GLM/Zhipu, Qwen, Grok/xAI, and local servers (Ollama/vLLM at /v1).
# There is deliberately no per-vendor code — if a backend speaks the OpenAI chat API,
# point LLM_BASE_URL at it. Lazy-imports `openai`; a clear install error if absent.
#
# Connectivity, NOT correctness: this gets a completion back. The zero-false-positive
# evidence is measured on gemini-2.5-pro only and does not transfer to any model here.
# ==============================================================================
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from backend.app.core.config import settings, reveal_secret
from backend.app.services.llm import LLMConfigError, LLMError, LLMTransientError

_MISSING_SDK = (
    "The 'openai' SDK is required for LLM_PROVIDER='openai'. Install it with: pip install openai"
)


class OpenAICompatProvider:
    def __init__(self) -> None:
        self._client: Any = None

    @property
    def default_model(self) -> str:
        return settings.LLM_MODEL or ""

    def _api_key(self):
        return reveal_secret(settings.LLM_API_KEY)

    def is_configured(self) -> bool:
        # A key is required (use a placeholder like 'ollama' for keyless local servers).
        return bool(self._api_key())

    def _get_client(self, AsyncOpenAI):
        if self._client is None:
            kwargs: Dict[str, Any] = {"api_key": self._api_key()}
            if settings.LLM_BASE_URL:
                kwargs["base_url"] = settings.LLM_BASE_URL
            self._client = AsyncOpenAI(**kwargs)
        return self._client

    async def generate(
        self, *, messages: List[Dict[str, str]], system: str, json_mode: bool,
        temperature: float, model: str, timeout: float, max_attempts: int = 1,
    ) -> str:
        try:
            import openai
            from openai import AsyncOpenAI
        except ImportError as e:
            raise LLMConfigError(_MISSING_SDK) from e

        client = self._get_client(AsyncOpenAI)

        # System instruction is a leading system message; roles are user/assistant.
        chat_messages: List[Dict[str, str]] = [{"role": "system", "content": system}]
        for m in messages:
            role = "assistant" if m.get("role") == "assistant" else "user"
            chat_messages.append({"role": role, "content": m.get("text", "")})

        kwargs: Dict[str, Any] = {
            "model": model, "messages": chat_messages, "temperature": temperature,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        # Transient error types (robust to minor SDK-version differences).
        transient = tuple(
            t for t in (
                getattr(openai, "APIConnectionError", None),
                getattr(openai, "APITimeoutError", None),
                getattr(openai, "RateLimitError", None),
            ) if t is not None
        )
        status_error = getattr(openai, "APIStatusError", None)
        api_error = getattr(openai, "APIError", Exception)

        attempts = max(1, max_attempts)
        last_exc: Any = None
        for attempt in range(attempts):
            try:
                resp = await asyncio.wait_for(
                    client.chat.completions.create(**kwargs), timeout=timeout
                )
                return resp.choices[0].message.content or ""
            except transient as e:  # type: ignore[misc]
                last_exc = e
                if attempt < attempts - 1:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                raise LLMTransientError(str(e)) from e
            except Exception as e:  # includes APIStatusError / other API errors
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
                raise  # unexpected (e.g. asyncio.TimeoutError) — let it propagate
        raise LLMTransientError(str(last_exc)) from last_exc
