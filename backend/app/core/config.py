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
    # 2. External Penetration Testing Binary Paths
    # --------------------------------------------------------------------------
    NUCLEI_BINARY_PATH: str = Field(
        ...,
        description="The absolute filesystem path to the local Nuclei security scanner."
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
    # 4. Scan & Fuzzing Engine Settings
    # --------------------------------------------------------------------------
    NUCLEI_DEFAULT_SEVERITY: str = Field(
        default="critical,high",
        description="Comma-separated severity levels to filter Nuclei scan results."
    )

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

    @field_validator("NUCLEI_BINARY_PATH")
    @classmethod
    def validate_nuclei_path(cls, path: str) -> str:
        """
        Deep Validation for Nuclei Path:
        1. Guarantees that the path is specified as an absolute path to mitigate path-traversal/relative hijacks.
        2. Normalizes path formatting to match the underlying operating system (Windows/Linux).
        """
        # Ensure path is absolute
        if not os.path.isabs(path):
            raise ValueError(
                f"NUCLEI_BINARY_PATH MUST be an absolute path to prevent traversal or path execution hijacks. Got: '{path}'"
            )

        # Normalize paths for Windows/Unix compatibility
        normalized_path = os.path.normpath(path)

        # Soft Verification: In production, we log if the file does not exist,
        # but do not necessarily crash at build-time to allow developers to configure their environments.
        # We will do a check to verify if the file exists when the app starts.
        return normalized_path

# ==============================================================================
# Instantiation - Load config immediately on import to validate settings
# ==============================================================================
try:
    settings = Settings()
except Exception as e:
    sys.stderr.write(f"[CRITICAL CONFIG ERROR] Settings initialization failed: {e}\n")
    sys.stderr.write("Ensure that all mandatory environment variables (e.g., NUCLEI_BINARY_PATH) are defined either in system environment variables or in your local '.env' file.\n")
    # In a real startup, we want to fail fast if config is invalid
    raise e
