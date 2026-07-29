# ==============================================================================
# LLM provider abstraction — offline tests. ZERO real API calls.
#
# The load-bearing test is the BYTE-IDENTITY ANCHOR: it captures the exact
# generate_content kwargs the GeminiProvider issues for a deep_verifier-shaped call
# and asserts config + contents are identical to what deep_verifier builds today.
# The expected values are LITERALS (today's exact config), so the anchor stays a
# stable spec even after commit 2 moves _build_provider_config into the provider.
# ==============================================================================
import asyncio

import pytest

from backend.app.core.config import settings
from backend.app.services.llm import get_provider, LLMConfigError, LLMProvider
from backend.app.services.llm.gemini import GeminiProvider

pytest.importorskip("google.genai")   # google-genai is a hard project dependency

from google.genai import types                     # noqa: E402
from google.genai import errors as genai_errors    # noqa: E402
from backend.app.services import deep_verifier as dv  # noqa: E402


# --------------------------------------------------------------------------
# A fake google-genai client whose aio.models.generate_content records kwargs.
# --------------------------------------------------------------------------
def _install_fake_genai(monkeypatch, *, sink, text='{"decision":"verdict","verdict":"failed","confidence":1.0,"reasoning":"x"}',
                        raises_seq=None):
    """raises_seq: optional list of exceptions/None to raise/return per call."""
    import google.genai as g
    state = {"n": 0}

    class _Resp:
        def __init__(self, t): self.text = t

    class _Models:
        async def generate_content(self, **kwargs):
            sink.append(kwargs)
            i = state["n"]; state["n"] += 1
            if raises_seq and i < len(raises_seq) and raises_seq[i] is not None:
                raise raises_seq[i]
            return _Resp(text)

    class _Aio:
        models = _Models()

    class _FakeClient:
        def __init__(self, **kw): self.aio = _Aio()

    monkeypatch.setattr(g, "Client", _FakeClient)
    return state


class _Fake503(genai_errors.ServerError):
    """A ServerError subclass constructible with no args (the real __init__ needs an
    httpx Response). Matches the retry predicate via str() containing '503', exactly
    like a real Gemini 503 (`ServerError: 503 UNAVAILABLE ...`)."""
    status_code = 503

    def __init__(self):  # deliberately skip APIError.__init__
        pass

    def __str__(self):
        return "503 UNAVAILABLE"


def _make_503():
    return _Fake503()


def _gemini_key(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", None, raising=False)
    monkeypatch.setattr(settings, "LLM_MODEL", None, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-key", raising=False)


# ==========================================================================
# BYTE-IDENTITY ANCHOR
# ==========================================================================
def test_byte_identity_single_turn_config_and_contents(monkeypatch):
    _gemini_key(monkeypatch)
    sink = []
    _install_fake_genai(monkeypatch, sink=sink)

    text = asyncio.run(GeminiProvider().generate(
        messages=[{"role": "user", "text": "PROMPT1"}],
        system=dv.SYSTEM_PROMPT, json_mode=True, temperature=0.4,
        model="gemini-2.5-pro", timeout=60.0, max_attempts=3,
    ))

    assert len(sink) == 1
    kw = sink[0]
    assert kw["model"] == "gemini-2.5-pro"
    # config: today's exact GenerateContentConfig (system_instruction, JSON mode, temp 0.4)
    expected_cfg = types.GenerateContentConfig(
        system_instruction=dv.SYSTEM_PROMPT,
        response_mime_type="application/json",
        temperature=0.4,
    )
    assert kw["config"] == expected_cfg
    # contents: today's exact Content/Part list
    assert kw["contents"] == [types.Content(role="user", parts=[types.Part(text="PROMPT1")])]
    assert text.startswith("{")


def test_byte_identity_multi_turn_assistant_maps_to_model(monkeypatch):
    _gemini_key(monkeypatch)
    sink = []
    _install_fake_genai(monkeypatch, sink=sink)

    asyncio.run(GeminiProvider().generate(
        messages=[
            {"role": "user", "text": "T1"},
            {"role": "assistant", "text": "MODEL_TURN"},
            {"role": "user", "text": "T2"},
        ],
        system=dv.SYSTEM_PROMPT, json_mode=True, temperature=0.4,
        model="gemini-2.5-pro", timeout=60.0, max_attempts=3,
    ))
    assert sink[-1]["contents"] == [
        types.Content(role="user", parts=[types.Part(text="T1")]),
        types.Content(role="model", parts=[types.Part(text="MODEL_TURN")]),
        types.Content(role="user", parts=[types.Part(text="T2")]),
    ]


def test_byte_identity_non_json_mode_omits_response_mime_type(monkeypatch):
    _gemini_key(monkeypatch)
    sink = []
    _install_fake_genai(monkeypatch, sink=sink, text="plain markdown")
    asyncio.run(GeminiProvider().generate(
        messages=[{"role": "user", "text": "x"}], system="S", json_mode=False,
        temperature=0.2, model="m", timeout=60.0, max_attempts=1,
    ))
    assert sink[0]["config"] == types.GenerateContentConfig(system_instruction="S", temperature=0.2)


# ==========================================================================
# RETRY behavior (byte-identical to _gemini_generate for deep_verifier)
# ==========================================================================
def test_503_retry_then_success_sleeps_3_then_6(monkeypatch):
    _gemini_key(monkeypatch)
    sink = []
    _install_fake_genai(monkeypatch, sink=sink, raises_seq=[_make_503(), _make_503(), None])
    sleeps = []
    import backend.app.services.llm.gemini as gem

    async def _fake_sleep(s): sleeps.append(s)
    monkeypatch.setattr(gem.asyncio, "sleep", _fake_sleep)

    out = asyncio.run(GeminiProvider().generate(
        messages=[{"role": "user", "text": "x"}], system="S", json_mode=True,
        temperature=0.4, model="m", timeout=5.0, max_attempts=3,
    ))
    assert out.startswith("{")
    assert len(sink) == 3           # two 503s + one success
    assert sleeps == [3, 6]         # 3*(0+1), 3*(1+1)


def test_max_attempts_1_does_not_retry_and_does_not_sleep(monkeypatch):
    # hunter's contract: a single call, no retry, no sleep — 503 propagates immediately.
    _gemini_key(monkeypatch)
    sink = []
    _install_fake_genai(monkeypatch, sink=sink, raises_seq=[_make_503()])
    sleeps = []
    import backend.app.services.llm.gemini as gem

    async def _fake_sleep(s): sleeps.append(s)
    monkeypatch.setattr(gem.asyncio, "sleep", _fake_sleep)

    with pytest.raises(genai_errors.ServerError):
        asyncio.run(GeminiProvider().generate(
            messages=[{"role": "user", "text": "x"}], system="S", json_mode=True,
            temperature=0.4, model="m", timeout=5.0, max_attempts=1,
        ))
    assert len(sink) == 1           # exactly one attempt
    assert sleeps == []             # no sleep


# ==========================================================================
# Factory + config resolution
# ==========================================================================
def test_factory_default_is_gemini(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "gemini", raising=False)
    assert isinstance(get_provider(), GeminiProvider)
    assert isinstance(get_provider("gemini"), GeminiProvider)


def test_factory_unknown_provider_raises_config_error():
    with pytest.raises(LLMConfigError):
        get_provider("does-not-exist")


def test_gemini_default_model_prefers_llm_model_then_gemini_pro(monkeypatch):
    monkeypatch.setattr(settings, "LLM_MODEL", None, raising=False)
    monkeypatch.setattr(settings, "GEMINI_PRO_MODEL", "gemini-2.5-flash", raising=False)
    assert GeminiProvider().default_model == "gemini-2.5-flash"    # byte-compat fallback
    monkeypatch.setattr(settings, "LLM_MODEL", "some-other-model", raising=False)
    assert GeminiProvider().default_model == "some-other-model"


def test_gemini_is_configured_uses_key_fallback(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", None, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", None, raising=False)
    assert GeminiProvider().is_configured() is False
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "k", raising=False)
    assert GeminiProvider().is_configured() is True
    monkeypatch.setattr(settings, "GEMINI_API_KEY", None, raising=False)
    monkeypatch.setattr(settings, "LLM_API_KEY", "explicit", raising=False)
    assert GeminiProvider().is_configured() is True


def test_provider_satisfies_protocol():
    assert isinstance(GeminiProvider(), LLMProvider)
