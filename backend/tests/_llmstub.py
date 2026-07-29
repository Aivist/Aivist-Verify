# Shared test helper for the LLM-provider seam.
#
# The engine now calls `get_provider().generate(...)` instead of `_gemini_generate(...)`.
# `as_provider` adapts an existing old-style async model stub — `gen()` returning an
# object with a `.text` attribute (the shape the `_fake_gemini` / `_always_verified` /
# `_fake_gemini_verdict` helpers already produce) — into a `get_provider()` replacement:
# a stub provider whose `generate()` returns that `.text`. This keeps every test's canned
# turn-1/turn-2 responses and ASSERTIONS unchanged; only the mock POINT moves.
def as_provider(gen):
    class _StubProvider:
        default_model = "test-model"

        def is_configured(self):
            return True

        async def generate(self, **kwargs):
            resp = await gen()
            return resp.text

    return lambda: _StubProvider()
