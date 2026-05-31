# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Request and Response Schema Validation
# ==============================================================================

from typing import Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator

class ScanRequest(BaseModel):
    """
    ScanRequest defines the contract for initiating an asynchronous vulnerability scan.
    Leverages Pydantic V2 metadata and type validation to guarantee that all input 
    conforms to secure API specifications.
    """
    target_url: HttpUrl = Field(
        ...,
        description="The target web server URL to perform vulnerability scanning on. Must be a valid HTTP/HTTPS endpoint.",
        examples=["https://example.com"]
    )
    
    cookie: Optional[str] = Field(
        default=None,
        description="Optional session cookie header value to pass with the scan requests for authenticated vulnerability testing.",
        examples=["PHPSESSID=abcdef123456; security=low"]
    )

    @field_validator("cookie")
    @classmethod
    def sanitize_cookie(cls, v: Optional[str]) -> Optional[str]:
        """
        Input Sanitization: Basic validation on Cookie contents to avoid any potential header injection.
        """
        if v is None:
            return v
        
        # Strip leading/trailing whitespaces and filter out control characters that could break headers
        sanitized = v.strip()
        if "\n" in sanitized or "\r" in sanitized:
            raise ValueError("Session cookie string contains illegal control characters (CRLF).")
            
        return sanitized

class ScanResponse(BaseModel):
    """
    ScanResponse standardizes API response payload formats.
    Provides tracking identity and execution state directly back to the API client.
    """
    scan_id: str = Field(
        ...,
        description="Unique UUID tracking identifier for the asynchronous scan."
    )
    
    status: str = Field(
        ...,
        description="Current execution state of the scan. (e.g. 'pending', 'started', 'failed')"
    )
    
    message: str = Field(
        ...,
        description="User-friendly notification text detailing the result of the invocation."
    )

class ScanTaskState(BaseModel):
    """
    Schema validating returned states when polling ScanTask.
    """
    scan_id: str
    target_url: str
    status: str
    updated_at: str

    class Config:
        from_attributes = True

class FindingDetails(BaseModel):
    """
    Schema validating detailed vulnerability findings structures.
    """
    id: int
    # D4 fix: Hunter findings have scan_id=NULL (Step D). Keeping this non-optional
    # was a latent crash for any endpoint that serializes a Hunter row. Now nullable.
    scan_id: Optional[str] = None
    # Discriminator: "nuclei" (default) or "hunter".
    source: Optional[str] = None
    template_id: str
    severity: str
    matched_at: str
    poc_request: Optional[str]
    poc_response: Optional[str]
    ai_patch: Optional[str]
    created_at: str

    class Config:
        from_attributes = True

