from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class LeakageFinding(BaseModel):
    finding_type: str = Field(..., description="CREDIT_CARD, IBAN, SSN, API_KEY_STRIPE, API_KEY_AWS, PRIVATE_KEY")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM")
    raw_match: str
    masked_value: str
    start_index: int
    end_index: int
    validation_rule: str
    confidence: float = 1.0


class InspectRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text payload or financial logs to inspect")
    context_metadata: Optional[Dict[str, Any]] = None


class InspectResponse(BaseModel):
    is_leaked: bool
    total_findings: int
    findings: List[LeakageFinding] = Field(default_factory=list)
    execution_time_ms: float


class RedactRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Payload to sanitize")
    mode: str = Field(default="PARTIAL_MASK", description="PARTIAL_MASK, FULL_MASK, HASH_TOKEN")
    mask_char: str = Field(default="X", min_length=1, max_length=1)


class RedactResponse(BaseModel):
    original_length: int
    redacted_text: str
    findings_count: int
    findings: List[LeakageFinding] = Field(default_factory=list)
    execution_time_ms: float


class StreamMonitorRequest(BaseModel):
    sample_count: int = Field(default=10, ge=1, le=50)


class StreamMonitorResult(BaseModel):
    events_scanned: int
    payload_bytes_scanned: int
    leakages_detected: int
    findings: List[LeakageFinding] = Field(default_factory=list)
    duration_seconds: float


class HealthResponse(BaseModel):
    status: str
    active_rules: List[str]
    total_violations_recorded: int
