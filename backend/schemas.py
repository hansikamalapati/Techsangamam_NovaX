from pydantic import BaseModel, Field
from typing import List, Optional


# ============================================================
# URL SCAN REQUEST
# ============================================================

class URLScanRequest(BaseModel):
    """
    Data received when the user wants to analyze a URL.
    """

    url: str = Field(
        ...,
        min_length=3,
        description="URL to analyze"
    )


# ============================================================
# MESSAGE SCAN REQUEST
# ============================================================

class MessageScanRequest(BaseModel):
    """
    Data received when the user wants to analyze
    a suspicious message or email.
    """

    message: str = Field(
        ...,
        min_length=3,
        description="Message or email text to analyze"
    )


# ============================================================
# INDICATOR
# ============================================================

class Indicator(BaseModel):
    """
    A reason why the system considers an input suspicious.
    """

    indicator: str
    explanation: str
    severity: str


# ============================================================
# SCAN RESPONSE
# ============================================================

class ScanResponse(BaseModel):
    """
    Final result returned by CyberSentinel
    after analyzing an input.
    """

    scan_id: Optional[int] = None

    input_type: str

    risk_score: float

    risk_level: str

    threat_type: str

    ml_probability: Optional[float] = None

    threat_intelligence: Optional[str] = None

    indicators: List[Indicator] = []

    recommendation: str