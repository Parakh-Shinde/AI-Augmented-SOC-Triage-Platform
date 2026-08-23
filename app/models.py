from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field

class Alert(BaseModel):
    alert_id: str = Field(
        default_factory=lambda: f"ALT-{uuid4().hex[:12].upper()}"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    detection_name: str
    source_system: str = "Splunk"
    log_source: str
    host: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    raw_event: str
    status: str = "new"

class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str

class TriageResult(BaseModel):
    severity: str
    verdict: str
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    mitre_techniques: list[MitreTechnique]
    evidence: list[str]
    false_positive_indicators: list[str]
    recommended_actions: list[str]
    requires_human_review: bool = True
