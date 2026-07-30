# ==============================================================================
# Secret hygiene (scope-lock 5) — the verifiable no-leak proof: a wrapped secret
# (API key, owner-auth credential, proxy ingest token) must NEVER appear in an
# object's repr / str / JSON serialization, yet must still be retrievable at point
# of use. This is the check that makes "no leak" measurable, not just asserted.
# ==============================================================================
from pydantic import SecretStr

from backend.app.core.config import Settings, reveal_secret

_SECRETS = {
    "GEMINI_API_KEY": "gemini-super-secret-KKK",
    "LLM_API_KEY": "llm-super-secret-LLL",
    "AI_DEEP_VERIFY_OWNER_AUTH": "Bearer owner-super-secret-OOO",
}


def test_secrets_never_appear_in_serialization():
    s = Settings(**_SECRETS)
    blobs = [repr(s), str(s), s.model_dump_json()]
    # Both the whole value and (for the bearer form) the token payload must be absent.
    sensitive = list(_SECRETS.values()) + [v.split()[-1] for v in _SECRETS.values()]
    for raw in sensitive:
        for blob in blobs:
            assert raw not in blob, f"secret {raw!r} leaked into a serialization blob"


def test_secrets_retrievable_at_point_of_use():
    s = Settings(**_SECRETS)
    assert reveal_secret(s.GEMINI_API_KEY) == _SECRETS["GEMINI_API_KEY"]
    assert reveal_secret(s.LLM_API_KEY) == _SECRETS["LLM_API_KEY"]
    assert reveal_secret(s.AI_DEEP_VERIFY_OWNER_AUTH) == _SECRETS["AI_DEEP_VERIFY_OWNER_AUTH"]


def test_unset_secret_is_none_byte_identical():
    s = Settings(GEMINI_API_KEY=None, LLM_API_KEY=None, AI_DEEP_VERIFY_OWNER_AUTH=None)
    assert s.GEMINI_API_KEY is None
    assert reveal_secret(s.GEMINI_API_KEY) is None


def test_reveal_secret_handles_all_forms():
    assert reveal_secret(None) is None
    assert reveal_secret(SecretStr("x")) == "x"
    # test-double passthrough: a plain string set by a test still works (many tests do
    # monkeypatch settings.GEMINI_API_KEY = "test-key").
    assert reveal_secret("plain-test-double") == "plain-test-double"


def test_ingest_token_wrapped_and_not_leaked():
    from backend.app.services.proxy_manager import ProxyManager
    m = ProxyManager()
    m._ingest_token = SecretStr("ingest-super-secret-III")
    assert "ingest-super-secret-III" not in repr(m._ingest_token)
    assert "ingest-super-secret-III" not in str(m._ingest_token)
    # revealed only at point of use (constant-time verify + child env)
    assert reveal_secret(m._ingest_token) == "ingest-super-secret-III"
    assert m.verify_ingest_token("ingest-super-secret-III") is True
    assert m.verify_ingest_token("wrong") is False
