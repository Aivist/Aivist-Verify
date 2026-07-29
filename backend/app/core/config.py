# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Core Module: Configuration and Settings Manager
# ==============================================================================

import os
import sys
from typing import Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Settings Management Class.
    Loads variables dynamically from system environment variables or a local .env file.
    Performs rigorous validations on startup to guarantee system stability and security.
    """

    # --------------------------------------------------------------------------
    # 1. API Server Settings
    # --------------------------------------------------------------------------
    API_PORT: int = Field(
        default=8000,
        description="The network port for the FastAPI backend service to listen on."
    )

    # SECURITY NOTE (N5 + D2): the server binds to this interface. Default
    # "0.0.0.0" listens on ALL network interfaces, so anyone on the same
    # LAN/Wi-Fi (or the public internet if the host is port-forwarded) can
    # reach the API. Because there is currently NO authentication (see D2),
    # an exposed instance can be abused to launch scans/fuzzing against
    # arbitrary targets from your machine. Keep this on a trusted network and
    # shut the server down when not in use. Set API_HOST=127.0.0.1 to restrict
    # access to this machine only.
    API_HOST: str = Field(
        default="0.0.0.0",
        description="Network interface the FastAPI server binds to. Use 127.0.0.1 to restrict to localhost."
    )

    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level for standard application outputs."
    )

    # --------------------------------------------------------------------------
    # CORS Cross-Origin Resource Sharing Configurations
    # --------------------------------------------------------------------------
    CORS_ALLOWED_ORIGINS: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        description="Comma-separated list of allowed origin URLs for CORS security configurations."
    )

    # --------------------------------------------------------------------------
    # 3. AI Orchestration Settings (Future Extensibility)
    # --------------------------------------------------------------------------
    GEMINI_API_KEY: Optional[str] = Field(
        default=None,
        description="API Key for the Google Gemini Orchestration Layer."
    )

    GEMINI_PRO_MODEL: str = Field(
        default="gemini-2.5-flash",
        description="Google Gemini model identifier used for all AI calls (logic-hunt analysis + remediation patches)."
    )

    # --------------------------------------------------------------------------
    # LLM provider abstraction (services/llm/). Lets a deployment bring its own
    # model/gateway WITHOUT changing verdict logic. Default 'gemini' + all LLM_*
    # unset => resolves to GEMINI_API_KEY / GEMINI_PRO_MODEL, i.e. behavior is
    # byte-identical to before this seam existed. The zero-FP evidence is, and stays,
    # measured on gemini-2.5-pro only; non-Gemini backends get CONNECTIVITY, not a
    # correctness guarantee.
    # --------------------------------------------------------------------------
    LLM_PROVIDER: str = Field(
        default="gemini",
        description="Which LLM backend to use: 'gemini' (default) | 'openai' (OpenAI-compatible, incl. relays/DeepSeek/Kimi/GLM/Qwen/Grok/Ollama via LLM_BASE_URL) | 'anthropic'."
    )
    LLM_API_KEY: Optional[str] = Field(
        default=None,
        description="API key for the selected provider. For 'gemini', falls back to GEMINI_API_KEY when unset (byte-compat)."
    )
    LLM_BASE_URL: Optional[str] = Field(
        default=None,
        description="OpenAI-compatible base_url (relay/gateway/local, e.g. https://host/v1 or http://localhost:11434/v1). Used by the 'openai' provider; ignored by 'gemini'."
    )
    LLM_MODEL: Optional[str] = Field(
        default=None,
        description="Model identifier for the selected provider. For 'gemini', falls back to GEMINI_PRO_MODEL when unset (byte-compat)."
    )

    # Feature flag for the NEW, isolated AI-in-the-loop deep verification component
    # (services/deep_verifier.py). Default False so existing behavior is unchanged:
    # nothing calls the deep verifier unless this is explicitly enabled. This gate
    # does NOT affect the parallel fuzzing engine or any of the existing endpoints.
    AI_DEEP_VERIFY_ENABLED: bool = Field(
        default=False,
        description="Enable the isolated AI-in-the-loop write-then-read deep verifier (off by default; not wired into any endpoint yet)."
    )

    # Phase 7 SHADOW MODE flag — separate from AI_DEEP_VERIFY_ENABLED. When True,
    # the parallel fuzzing engine runs the deep verifier as a READ-ONLY second
    # opinion on "suspicious" records AFTER the normal batch completes, logging the
    # AI verdict WITHOUT changing verification_status/diff_details or what the user
    # sees. Default False => behavior is byte-identical to today. NOTE: to actually
    # invoke Gemini, AI_DEEP_VERIFY_ENABLED must ALSO be True (the verifier itself
    # respects that gate); the shadow flag only controls whether the fuzzer calls it.
    AI_DEEP_VERIFY_SHADOW: bool = Field(
        default=False,
        description="Run the deep verifier in read-only shadow mode after a fuzzing batch (observes 'suspicious' records; never changes verdicts). Off by default."
    )

    # Optional real endpoint-surface source for the shadow deep verifier's
    # `available_endpoints` (D18/D21). A FILESYSTEM PATH to an OpenAPI/Swagger JSON
    # document, settable from .env / the environment exactly like the two flags above
    # (e.g. AI_DEEP_VERIFY_OPENAPI_SPEC=/abs/path/to/openapi.json). Default None => the
    # shadow pass uses its byte-identical placeholder catalog (ZERO REGRESSION). This
    # field ONLY widens the endpoint list shown to the model; it never touches a verdict
    # or the verdict gate. The consumer (fuzzer._resolve_openapi_catalog_source) reads +
    # parses the file and FAILS SAFE back to the placeholder on any missing-file / parse /
    # type error; for in-process measurement drivers it also accepts an already-parsed
    # spec dict injected directly onto `settings`. JSON only (no declared YAML dep).
    AI_DEEP_VERIFY_OPENAPI_SPEC: Optional[str] = Field(
        default=None,
        description="Path to an OpenAPI/Swagger JSON file feeding the shadow deep verifier's endpoint catalog (D18/D21). Empty => byte-identical placeholder catalog. Observe-only; never affects a verdict."
    )

    # The OWNER/VICTIM's credential — the second identity of the two-account ownership
    # baseline (ROADMAP.md:281; prerequisite for the D24 read-semantic gate). Everything
    # the engine sends today goes out as the ATTACKER; this is the only way for code to
    # obtain an object's AUTHENTIC owner view.
    #
    # Format: "Header-Name: value" (e.g. "X-Token: abc"), or a bare credential which is
    # sent as "Authorization: Bearer <value>". For the two local labs:
    #   vulnerable_target -> "Bearer bob-token-bbbb"
    #   depot_target      -> "Bearer bob-depot-token-bbbb"
    #
    # KNOWN LIMITATION (deliberate, documented): this is ONE owner credential per
    # DEPLOYMENT, not per finding. That is sufficient for both local labs and for proving
    # the D24 gate, but a real target whose findings are owned by DIFFERENT accounts would
    # need per-finding credentials. Per-finding support does NOT exist — do not let any
    # later claim imply that it does.
    #
    # Default None => the second identity is simply absent and behavior is byte-identical
    # to before. Nothing consumes this yet: it is a credential CHANNEL only, with no
    # verdict logic attached. Fail-safe direction is BLOCK — a missing or failed owner
    # view may only ever REDUCE downstream confidence, never increase it.
    AI_DEEP_VERIFY_OWNER_AUTH: Optional[str] = Field(
        default=None,
        description="Owner/victim credential for owner-scoped reads by the deep verifier (two-account baseline). 'Header: value' or a bare bearer token. Empty => absent, byte-identical behavior. One credential per deployment, NOT per finding. Never used for attack requests."
    )

    # D19 — PROMOTE the shadow deep-verify verdict from observe-only to AUTHORITATIVE.
    # This is the ONLY flag that lets the deep verifier change a user-visible verdict, and it
    # does so CONSERVATIVELY and STRUCTURALLY: when True, the Phase-7 shadow pass may upgrade a
    # rule-oracle 'suspicious' record to 'verified' — but ONLY when a DETERMINISTIC code channel
    # authorizes it (one of the four exemption channels fired, or the D24 owner-view gate
    # corroborated). The model's raw opinion ALONE can never produce a promoted 'verified'; with
    # no authorizer the record keeps its rule verdict untouched. D19 only ever touches the
    # 'suspicious' band — the rule oracle's own 'verified'/'failed' are never overridden.
    #
    # Composition: promotion requires ALL THREE — AI_DEEP_VERIFY_ENABLED (verifier runs) AND
    # AI_DEEP_VERIFY_SHADOW (fuzzer invokes Phase 7) AND AI_DEEP_VERIFY_PROMOTE (Phase 7 writes).
    # PROMOTE is a no-op unless SHADOW is on. For read-semantic promotion, AI_DEEP_VERIFY_OWNER_AUTH
    # must ALSO be set (else the D24 gate cannot corroborate -> read-semantic will not promote —
    # conservative). Default False => behavior is byte-identical to today (shadow observes, never
    # writes). Any deep-verify error/timeout/disable falls back to the rule verdict — an AI-layer
    # failure may never upgrade a verdict and never crash the batch.
    AI_DEEP_VERIFY_PROMOTE: bool = Field(
        default=False,
        description="Let the Phase-7 shadow deep verifier PROMOTE a rule-oracle 'suspicious' record to 'verified', but ONLY when a deterministic code channel authorizes it (four exemption channels, or the D24 owner-view corroboration). Model opinion alone never promotes. Off by default => shadow stays observe-only."
    )

    # --------------------------------------------------------------------------
    # 4. Scan & Fuzzing Engine Settings
    # --------------------------------------------------------------------------
    GEMINI_BATCH_COOLDOWN_SECONDS: int = Field(
        default=3,
        description="Rate-limit cooldown (seconds) between sequential Gemini API calls during batch enrichment."
    )

    GEMINI_REQUEST_TIMEOUT_SECONDS: float = Field(
        default=60.0,
        description="Hard wall-clock budget (seconds) for a single Gemini API call before it is abandoned and a degraded fallback is returned (D3)."
    )

    FUZZER_HTTP_TIMEOUT_CONNECT: float = Field(
        default=10.0,
        description="HTTP connect timeout (seconds) for the fuzzing engine's outbound requests."
    )

    FUZZER_HTTP_TIMEOUT_READ: float = Field(
        default=20.0,
        description="HTTP read timeout (seconds) for the fuzzing engine's outbound requests."
    )

    FUZZER_RESPONSE_BODY_MAX_LENGTH: int = Field(
        default=5000,
        description="Maximum characters to retain from HTTP response body in fuzzing records."
    )

    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./security_platform.db",
        description="The asynchronous database connection URL for SQLAlchemy dynamic connection."
    )

    # --------------------------------------------------------------------------
    # 5. Step 9 — Passive Traffic Ingestion Proxy Radar
    # --------------------------------------------------------------------------
    # Absolute path to the 'mitmdump' executable. Left empty by default: the
    # ProxyManager falls back to a PATH lookup (shutil.which). Set this only if
    # mitmdump is not on PATH. Validated as an absolute path to
    # avoid relative-path execution hijacks.
    MITMDUMP_PATH: Optional[str] = Field(
        default=None,
        description="Absolute path to the mitmdump binary. Empty => discover on PATH."
    )

    # Network port the intercepting proxy listens on (distinct from API_PORT).
    PROXY_LISTEN_PORT: int = Field(
        default=8888,
        description="Listen port for the mitmdump intercepting proxy. Must differ from API_PORT."
    )

    # Backpressure: max buffered flows awaiting the DB writer before the ingest
    # endpoint returns 503 (signals the addon to slow down).
    PROXY_INGEST_QUEUE_MAX: int = Field(
        default=1000,
        description="Bounded size of the in-memory proxy ingest queue (backpressure threshold)."
    )

    # Hard ceiling on concurrent SSE radar subscribers (resource-exhaustion guard).
    PROXY_SSE_MAX_CLIENTS: int = Field(
        default=32,
        description="Maximum simultaneous Server-Sent-Events clients on the proxy stream."
    )

    # Per-SSE-client bounded fan-out queue; oldest events dropped on overflow so a
    # slow browser tab cannot grow memory unbounded.
    PROXY_SSE_CLIENT_QUEUE_MAX: int = Field(
        default=500,
        description="Per-client SSE fan-out queue capacity (latest-wins on overflow)."
    )

    # Max characters retained per captured request/response body.
    PROXY_BODY_CAP: int = Field(
        default=65536,
        description="Maximum characters retained from each captured request/response body."
    )

    # Hard cap on a single internal-ingest POST body (defense against abuse).
    PROXY_INGEST_MAX_BYTES: int = Field(
        default=262144,
        description="Maximum byte size of a single /proxy/internal-ingest POST body (else 413)."
    )

    # --------------------------------------------------------------------------
    # 4. Pydantic Settings Configurations
    # --------------------------------------------------------------------------
    # Dynamically locate the absolute path to the parent directory containing '.env'
    model_config = SettingsConfigDict(
        env_file=os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            ".env"
        ),
        env_file_encoding="utf-8",
        extra="ignore"  # Gracefully drop unrelated system environment variables
    )

    # ==========================================================================
    # Strict Property Validators (Security & Integrity Checks)
    # ==========================================================================

    @field_validator("API_PORT")
    @classmethod
    def validate_api_port(cls, port: int) -> int:
        """
        Validates that the port number is within the acceptable RFC range.
        """
        if not (1 <= port <= 65535):
            raise ValueError(f"API_PORT must be in the valid network port range [1, 65535]. Got: {port}")
        return port

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, level: str) -> str:
        """
        Validates that the log level is an accepted standard logging level in uppercase.
        """
        upper_level = level.upper()
        allowed_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if upper_level not in allowed_levels:
            raise ValueError(f"LOG_LEVEL must be one of {allowed_levels}. Got: {level}")
        return upper_level

    @field_validator("MITMDUMP_PATH")
    @classmethod
    def validate_mitmdump_path(cls, path: Optional[str]) -> Optional[str]:
        """
        MITMDUMP_PATH is optional. When empty/None, the ProxyManager discovers
        mitmdump on PATH at runtime. When explicitly set, enforce an absolute,
        normalized absolute path to prevent relative-path
        execution hijacks. Existence is verified at radar-start, not here.
        """
        if path is None or not str(path).strip():
            return None
        if not os.path.isabs(path):
            raise ValueError(
                f"MITMDUMP_PATH MUST be an absolute path (or empty to use PATH lookup). Got: '{path}'"
            )
        return os.path.normpath(path)

    @field_validator("PROXY_LISTEN_PORT")
    @classmethod
    def validate_proxy_port(cls, port: int) -> int:
        """Validate the proxy listen port is within the RFC range."""
        if not (1 <= port <= 65535):
            raise ValueError(f"PROXY_LISTEN_PORT must be in [1, 65535]. Got: {port}")
        return port


# ==============================================================================
# Instantiation - Load config immediately on import to validate settings
# ==============================================================================
try:
    settings = Settings()
except Exception as e:
    sys.stderr.write(f"[CRITICAL CONFIG ERROR] Settings initialization failed: {e}\n")
    sys.stderr.write("Ensure that environment variables are defined either in system environment variables or in your local '.env' file.\n")
    # In a real startup, we want to fail fast if config is invalid
    raise e
