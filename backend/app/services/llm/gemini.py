# ==============================================================================
# Gemini provider — the DEFAULT, and the byte-identity anchor.
#
# HARD RED LINE: this reproduces today's deep_verifier Gemini call
# argument-for-argument — same GenerateContentConfig (system_instruction,
# response_mime_type="application/json" when json_mode, temperature), same
# Content/Part list (neutral "assistant" role -> "model"), same 3x 503-retry with
# sleep 3*(attempt+1), same wait_for timeout, same `.text`. The logic here is moved
# verbatim from deep_verifier._build_provider_config + _gemini_generate + the inline
# Content assembly. `test_llm_provider.py` asserts the emitted generate_content
# kwargs are identical to what deep_verifier builds today.
# ==============================================================================
from __future__ import annotations

import asyncio
from typing import Any, List, Dict

from backend.app.core.config import settings
from backend.app.services.llm import LLMConfigError

# Matches the historical deep_verifier._GEMINI_503_RETRIES; the caller passes
# max_attempts explicitly (deep_verifier=3, hunter=1), this is only a floor guard.
_GEMINI_503_RETRIES = 3


class GeminiProvider:
    """Google Gemini via the official `google-genai` SDK. Client is built lazily and
    cached, so one client serves both turns of a verification (as today)."""

    def __init__(self) -> None:
        self._client: Any = None

    # -- config ------------------------------------------------------------
    @property
    def default_model(self) -> str:
        # Gemini falls back to GEMINI_PRO_MODEL (the historical default); LLM_MODEL
        # overrides it if explicitly set. Unset LLM_MODEL => GEMINI_PRO_MODEL => byte-identical.
        return settings.LLM_MODEL or settings.GEMINI_PRO_MODEL

    def _api_key(self):
        # LLM_API_KEY takes precedence; falls back to GEMINI_API_KEY (byte-compat).
        return settings.LLM_API_KEY or settings.GEMINI_API_KEY

    def is_configured(self) -> bool:
        return bool(self._api_key())

    def _get_client(self, genai):
        if self._client is None:
            self._client = genai.Client(api_key=self._api_key())
        return self._client

    # -- generation --------------------------------------------------------
    async def generate(
        self,
        *,
        messages: List[Dict[str, str]],
        system: str,
        json_mode: bool,
        temperature: float,
        model: str,
        timeout: float,
        max_attempts: int = 1,
    ) -> str:
        try:
            from google import genai
            from google.genai import types
            from google.genai import errors as genai_errors
        except ImportError as e:
            raise LLMConfigError("google-genai SDK not installed") from e

        client = self._get_client(genai)

        # --- config: verbatim _build_provider_config (JSON mode when asked) ---
        if json_mode:
            cfg = types.GenerateContentConfig(
                system_instruction=system,
                response_mime_type="application/json",
                temperature=temperature,
            )
        else:
            cfg = types.GenerateContentConfig(
                system_instruction=system,
                temperature=temperature,
            )

        # --- contents: verbatim Content/Part assembly (assistant -> model) ---
        contents = [
            types.Content(
                role=("model" if m.get("role") == "assistant" else "user"),
                parts=[types.Part(text=m.get("text", ""))],
            )
            for m in messages
        ]

        # --- generate ---------------------------------------------------------
        # Byte-identity: the SDK's NATIVE exception propagates on failure and
        # asyncio.TimeoutError from wait_for propagates unwrapped — exactly as today,
        # so the caller's degraded path (which catches broadly) is unchanged down to the
        # exception type name. (openai/anthropic map their errors onto the neutral LLM*
        # types; Gemini does not, deliberately, to preserve the 430/430 evidence path.)
        attempts = max(1, max_attempts)

        # Single-attempt path (hunter, max_attempts=1): a bare call — no retry, NO sleep,
        # error propagates immediately. Byte-identical to hunter's current single call.
        if attempts == 1:
            resp = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=model, contents=contents, config=cfg
                ),
                timeout=timeout,
            )
            return resp.text

        # Multi-attempt path (deep_verifier, max_attempts=3): VERBATIM _gemini_generate —
        # 503 -> sleep 3*(attempt+1) and continue (on every 503 including the last), then
        # raise the last exception. Reproduced argument-for-argument.
        last_exc: Any = None
        for attempt in range(attempts):
            try:
                resp = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model=model, contents=contents, config=cfg
                    ),
                    timeout=timeout,
                )
                return resp.text
            except genai_errors.ServerError as e:
                last_exc = e
                if getattr(e, "status_code", None) == 503 or "503" in str(e):
                    await asyncio.sleep(3 * (attempt + 1))
                    continue
                raise
        raise last_exc
