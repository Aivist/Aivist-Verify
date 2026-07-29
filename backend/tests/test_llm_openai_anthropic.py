# ==============================================================================
# OpenAI-compatible + Anthropic providers — offline tests. ZERO real API calls.
# The SDKs are OPTIONAL deps: we inject fake `openai` / `anthropic` modules into
# sys.modules so these tests pass whether or not the real SDKs are installed, and
# we assert factory selection, request shape, JSON mode, and exception mapping.
# ==============================================================================
import asyncio
import sys
import types as pytypes

import pytest

from backend.app.core.config import settings
from backend.app.services.llm import (
    get_provider, LLMConfigError, LLMError, LLMTransientError,
)
from backend.app.services.llm.openai_compat import OpenAICompatProvider
from backend.app.services.llm.anthropic import AnthropicProvider


# --------------------------------------------------------------------------
# Fake SDK factories
# --------------------------------------------------------------------------
def _fake_openai(monkeypatch, *, content='{"ok":1}', sink=None):
    m = pytypes.ModuleType("openai")

    class APIError(Exception): ...
    class APIConnectionError(APIError): ...
    class RateLimitError(APIError): ...
    class APIStatusError(APIError):
        def __init__(self, msg="", status_code=500):
            super().__init__(msg); self.status_code = status_code

    m.APIError = APIError
    m.APIConnectionError = APIConnectionError
    m.RateLimitError = RateLimitError
    m.APIStatusError = APIStatusError

    seq = []          # tests append error instances (built from THIS module's classes)
    m._seq = seq

    class _Msg:
        def __init__(self, c): self.content = c
    class _Choice:
        def __init__(self, c): self.message = _Msg(c)
    class _Resp:
        def __init__(self, c): self.choices = [_Choice(c)]

    class _Completions:
        def __init__(self): self._i = 0
        async def create(self, **kwargs):
            if sink is not None: sink.append(kwargs)
            exc = seq[self._i] if self._i < len(seq) else None
            self._i += 1
            if exc is not None: raise exc
            return _Resp(content)

    class _Chat:
        def __init__(self): self.completions = _Completions()

    class AsyncOpenAI:
        def __init__(self, **kw):
            if sink is not None: sink.append(("client_kwargs", kw))
            self.chat = _Chat()

    m.AsyncOpenAI = AsyncOpenAI
    monkeypatch.setitem(sys.modules, "openai", m)
    return m


def _fake_anthropic(monkeypatch, *, text='{"ok":1}', sink=None):
    m = pytypes.ModuleType("anthropic")

    class APIError(Exception): ...
    class APIConnectionError(APIError): ...
    class RateLimitError(APIError): ...
    class APIStatusError(APIError):
        def __init__(self, msg="", status_code=500):
            super().__init__(msg); self.status_code = status_code

    m.APIError = APIError
    m.APIConnectionError = APIConnectionError
    m.RateLimitError = RateLimitError
    m.APIStatusError = APIStatusError

    seq = []          # tests append error instances (built from THIS module's classes)
    m._seq = seq

    class _Block:
        def __init__(self, t): self.text = t
    class _Resp:
        def __init__(self, t): self.content = [_Block(t)]

    class _Messages:
        def __init__(self): self._i = 0
        async def create(self, **kwargs):
            if sink is not None: sink.append(kwargs)
            exc = seq[self._i] if self._i < len(seq) else None
            self._i += 1
            if exc is not None: raise exc
            return _Resp(text)

    class AsyncAnthropic:
        def __init__(self, **kw):
            if sink is not None: sink.append(("client_kwargs", kw))
            self.messages = _Messages()

    m.AsyncAnthropic = AsyncAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", m)
    return m


# ==========================================================================
# Factory selection
# ==========================================================================
@pytest.mark.parametrize("name", ["openai", "openai_compat", "openai-compatible", "compat"])
def test_factory_selects_openai(name):
    assert isinstance(get_provider(name), OpenAICompatProvider)


@pytest.mark.parametrize("name", ["anthropic", "claude"])
def test_factory_selects_anthropic(name):
    assert isinstance(get_provider(name), AnthropicProvider)


# ==========================================================================
# OpenAI-compatible
# ==========================================================================
def test_openai_generate_shapes_request_and_returns_content(monkeypatch):
    sink = []
    _fake_openai(monkeypatch, content='{"report":"x"}', sink=sink)
    monkeypatch.setattr(settings, "LLM_API_KEY", "sk-test", raising=False)
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://relay.example/v1", raising=False)

    out = asyncio.run(OpenAICompatProvider().generate(
        messages=[{"role": "user", "text": "U1"}, {"role": "assistant", "text": "A1"},
                  {"role": "user", "text": "U2"}],
        system="SYS", json_mode=True, temperature=0.4, model="gpt-x",
        timeout=30.0, max_attempts=1,
    ))
    assert out == '{"report":"x"}'
    # client got the base_url; request carries system + user/assistant turns + json mode
    assert ("client_kwargs", {"api_key": "sk-test", "base_url": "https://relay.example/v1"}) in sink
    call = sink[-1]
    assert call["model"] == "gpt-x"
    assert call["messages"][0] == {"role": "system", "content": "SYS"}
    assert call["messages"][1] == {"role": "user", "content": "U1"}
    assert call["messages"][2] == {"role": "assistant", "content": "A1"}
    assert call["response_format"] == {"type": "json_object"}


def test_openai_missing_sdk_raises_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", None)   # import openai -> ImportError
    monkeypatch.setattr(settings, "LLM_API_KEY", "sk-test", raising=False)
    with pytest.raises(LLMConfigError):
        asyncio.run(OpenAICompatProvider().generate(
            messages=[{"role": "user", "text": "x"}], system="S", json_mode=True,
            temperature=0.4, model="m", timeout=5.0, max_attempts=1,
        ))


def test_openai_transient_maps_to_transient_error(monkeypatch):
    m = _fake_openai(monkeypatch)
    m._seq.append(m.RateLimitError("rate limited"))
    monkeypatch.setattr(settings, "LLM_API_KEY", "sk-test", raising=False)
    with pytest.raises(LLMTransientError):
        asyncio.run(OpenAICompatProvider().generate(
            messages=[{"role": "user", "text": "x"}], system="S", json_mode=True,
            temperature=0.4, model="m", timeout=5.0, max_attempts=1,
        ))


def test_openai_4xx_maps_to_llm_error(monkeypatch):
    m = _fake_openai(monkeypatch)
    m._seq.append(m.APIStatusError("bad request", status_code=400))
    monkeypatch.setattr(settings, "LLM_API_KEY", "sk-test", raising=False)
    with pytest.raises(LLMError) as ei:
        asyncio.run(OpenAICompatProvider().generate(
            messages=[{"role": "user", "text": "x"}], system="S", json_mode=True,
            temperature=0.4, model="m", timeout=5.0, max_attempts=1,
        ))
    assert not isinstance(ei.value, LLMTransientError)   # 4xx is NOT transient


def test_openai_is_configured_and_default_model(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", None, raising=False)
    assert OpenAICompatProvider().is_configured() is False
    monkeypatch.setattr(settings, "LLM_API_KEY", "sk", raising=False)
    assert OpenAICompatProvider().is_configured() is True
    monkeypatch.setattr(settings, "LLM_MODEL", "gpt-4o-mini", raising=False)
    assert OpenAICompatProvider().default_model == "gpt-4o-mini"


# ==========================================================================
# Anthropic
# ==========================================================================
def test_anthropic_generate_uses_system_param_and_returns_text(monkeypatch):
    sink = []
    _fake_anthropic(monkeypatch, text="RESULT", sink=sink)
    monkeypatch.setattr(settings, "LLM_API_KEY", "ak-test", raising=False)
    monkeypatch.setattr(settings, "LLM_BASE_URL", None, raising=False)

    out = asyncio.run(AnthropicProvider().generate(
        messages=[{"role": "user", "text": "U1"}, {"role": "assistant", "text": "A1"}],
        system="SYS", json_mode=True, temperature=0.3, model="claude-x",
        timeout=30.0, max_attempts=1,
    ))
    assert out == "RESULT"
    call = sink[-1]
    assert call["model"] == "claude-x"
    assert call["system"] == "SYS"                 # system is a top-level param, not a message
    assert call["messages"][0] == {"role": "user", "content": "U1"}
    assert call["messages"][1] == {"role": "assistant", "content": "A1"}
    assert call["max_tokens"] > 0                  # required by the Anthropic API


def test_anthropic_missing_sdk_raises_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", None)
    monkeypatch.setattr(settings, "LLM_API_KEY", "ak-test", raising=False)
    with pytest.raises(LLMConfigError):
        asyncio.run(AnthropicProvider().generate(
            messages=[{"role": "user", "text": "x"}], system="S", json_mode=True,
            temperature=0.4, model="m", timeout=5.0, max_attempts=1,
        ))


def test_anthropic_5xx_maps_to_transient_error(monkeypatch):
    m = _fake_anthropic(monkeypatch)
    m._seq.append(m.APIStatusError("overloaded", status_code=529))
    monkeypatch.setattr(settings, "LLM_API_KEY", "ak-test", raising=False)
    with pytest.raises(LLMTransientError):
        asyncio.run(AnthropicProvider().generate(
            messages=[{"role": "user", "text": "x"}], system="S", json_mode=True,
            temperature=0.4, model="m", timeout=5.0, max_attempts=1,
        ))
