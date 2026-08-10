# LLM Providers — bring your own model / gateway

The AI calls (the deep verifier, and scan's candidate proposal) go through a small provider seam
(`backend/app/services/llm/`) so you can point the engine at any backend. **Default is
Gemini, and with every `LLM_*` unset the behavior is byte-identical to before this seam
existed.**

> **Connectivity, NOT correctness.** The seam guarantees you can connect and get a
> completion back. The **zero-false-positive evidence is measured on `gemini-2.5-pro`
> only** and does **not** transfer to any other model. A non-Gemini backend gets provider
> freedom, not a correctness / zero-FP guarantee.

## Configuration (`backend/.env` or environment)

| Var | Meaning |
|---|---|
| `LLM_PROVIDER` | `gemini` (default) · `openai` · `anthropic` |
| `LLM_API_KEY` | key for the selected provider (gemini falls back to `GEMINI_API_KEY`) |
| `LLM_BASE_URL` | OpenAI-compatible endpoint (relay/gateway/local); used by `openai`, ignored by `gemini` |
| `LLM_MODEL` | model id (gemini falls back to `GEMINI_PRO_MODEL`) |

Unset everything ⇒ Gemini via `GEMINI_API_KEY` / `GEMINI_PRO_MODEL`.

## The three backends

### 1. Gemini (default)
The `google-genai` SDK (already a dependency). Uses `GEMINI_API_KEY` / `GEMINI_PRO_MODEL`
unless overridden by `LLM_API_KEY` / `LLM_MODEL`. This is the byte-identical,
zero-FP-measured path.

### 2. OpenAI-compatible (`LLM_PROVIDER=openai`)
**ONE** implementation covers the whole compatible ecosystem via `LLM_BASE_URL`: OpenAI
itself, relays, DeepSeek, Kimi/Moonshot, GLM/Zhipu, Qwen, Grok/xAI, and local
servers (Ollama / vLLM at `/v1`). Requires `pip install openai`.

```bash
# A relay / gateway
LLM_PROVIDER=openai
LLM_BASE_URL=https://your-relay.example/v1
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4o-mini

# DeepSeek
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_API_KEY=sk-...
LLM_MODEL=deepseek-chat

# Local Ollama (any placeholder key works)
LLM_PROVIDER=openai
LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=llama3.1
```

### 3. Anthropic / Claude (`LLM_PROVIDER=anthropic`)
The Claude Messages API. Requires `pip install anthropic`.

```bash
LLM_PROVIDER=anthropic
LLM_API_KEY=sk-ant-...
LLM_MODEL=claude-3-5-sonnet-latest
```

## Notes
- **Optional SDKs.** `openai` / `anthropic` are **not** in `requirements.txt`. Install the
  ones you need with `pip install -r backend/requirements-llm.txt` (or individually); the
  provider raises a clear `pip install X` error (`LLMConfigError`) if the SDK is missing.
- **JSON mode.** Gemini and OpenAI enforce JSON at the API layer
  (`response_mime_type` / `response_format`); Claude has no strict flag, so JSON relies on
  the system prompt (best-effort).
- **Failure is graceful.** A provider error degrades to an `inconclusive` / degraded
  verdict (deep verifier) — it never crashes a batch.
- **Design.** `services/llm/` = the `LLMProvider` protocol + `get_provider()` factory +
  `gemini.py` / `openai_compat.py` / `anthropic.py`. Only the model *call* sits behind it;
  the verdict logic (the four channels, the cross-resource guard, every anchor, the D24
  owner-view gate, and the D19 promotion path) is untouched. The Gemini path is proven
  byte-identical by `test_llm_provider.py`'s request-capture anchor.
