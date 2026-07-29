# Provider Abstraction — Handoff & Future-Work Register

Where the LLM provider work stands, plus scoped future items and explicitly-rejected
proposals recorded so they are **not re-litigated**. Code is the source of truth; verify
against it before acting on anything here.

## Current state (landed, `services/llm/`)
The AI model call is behind the `LLMProvider` interface: `get_provider()` factory +
`gemini.py` / `openai_compat.py` / `anthropic.py`. Two call sites route through it —
`deep_verifier.execute_deep_verification` (multi-turn, JSON, 3× 503-retry) and
`hunter._invoke_gemini_logic_hunt` (single-turn, JSON). The verdict logic — the four
exemption channels, the cross-resource guard, every anchor (M1.1–M1.4), the D24 owner-view
gate, and the D19 promotion path — is **untouched**. See [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md).

- **Default `LLM_PROVIDER=gemini` is byte-identical** to before the seam (proven by
  `test_llm_provider.py`'s request-capture anchor + `test_d18_b1_shadow_integration`).
- **Optional SDKs:** `openai` / `anthropic` are not in `requirements.txt` —
  `pip install -r backend/requirements-llm.txt`; a clear `LLMConfigError` fires if absent.
- **Verified live (DeepSeek, OpenAI-compatible):** direct provider 10/10; the hunter analyze
  path (real report + payloads); and the core verifier (0 degraded — verified a silent-write via
  the state-jump channel; hedged to `inconclusive` on the read-semantic shape). This is
  **connectivity, not correctness** — the zero-FP evidence stays measured on **gemini-2.5-pro
  only**. Non-Gemini SAFE-case (false-positive) behavior is **unvalidated**.

---

## FUTURE milestone — Chinese → English removal (NOT started)
The repo mixes Chinese and English. Anglicizing it is a **large, judgment-heavy milestone for a
fresh session**, not a tail task. The next agent MUST keep three DISTINCT categories separate:

1. **Docs** (`STATUS` / `ROADMAP` / `PROJECT_OVERVIEW` / etc.) — translatable, pure
   documentation. A normal docs pass; no code impact.
2. **Code comments** — translatable, but as their **own commit(s) with zero logic change**, kept
   separate from docs so review stays clean.
3. **Functional Chinese prompts — ⚠️ NOT documentation.** The hunter system prompt
   (`hunter._SYSTEM_PROMPT`) is in Chinese — that is *why DeepSeek replied in Chinese* during
   provider testing. **A prompt is runtime behavior.** Changing it is a **FUNCTIONAL change** that
   alters model output and **requires re-validation**; it must **never** be folded into a "clean up
   Chinese" pass. Whether to anglicize the hunter prompt is a **separate decision**: (a) keep as-is
   (Chinese output acceptable/intended for the operator), or (b) treat it as a validated functional
   change with its own before/after evidence. **Do NOT change any prompt as part of Chinese-removal.**

**Git history:** Chinese commit messages stay as-is. **No history rewriting.**

---

## Future / rejected — "remediation" ideas (recorded so they are not re-proposed)
- **Code-patch generator — PERMANENTLY REJECTED.** The engine is black-box (no target source);
  BOLA/IDOR fixes are business-architecture, not syntax; and a wrong patch would destroy the
  verifiability moat — unverifiable AI output is the exact risk the whole discipline exists to
  avoid. Already a ROADMAP Non-Goal ("Not a fix-code generator"). **Do not revive.**
- **Generic remediation guidance / defense checklist / CWE–OWASP mapping — DEFERRED (scope-creep).**
  Evaluated: it piles commodity components *outward* without deepening the zero-FP moat. Not now.
- **"One-click re-check" — OPTIONAL future merit (not built).** Re-run the **existing** verification
  on a finding and report **Fixed / Still-Vulnerable**. A natural extension of the confirmation the
  engine already performs (no new AI-generation surface) — the only remediation-adjacent fragment
  worth keeping on the radar. Recorded as optional; **not built now.**
