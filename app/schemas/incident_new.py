from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from app.schemas.ai_pipeline import AIPipelineMeta


class IncidentEvidenceNew(BaseModel):
    window_start: str
    window_end: str
    counts: Dict[str, int]
    timeline: List[Dict[str, Any]]
    events: List[Dict[str, Any]]


class IncidentSubjectNew(BaseModel):
    source_ip: str
    username: str
    host: Optional[str] = None


class IncidentExplanationNew(BaseModel):
    threshold: int       # configured detection threshold
    observed: int        # actual observed count that crossed the threshold
    window: str          # window duration, e.g. "60s"
    trigger_field: str   # field driving detection grouping, e.g. "username" or "source_ip"


class IncidentMitreMappingNew(BaseModel):
    tactic: str
    technique: str
    technique_name: str


class InvestigationPivotQuery(BaseModel):
    name: str
    description: str
    query: str


class IncidentInvestigationNew(BaseModel):
    questions: List[str]
    pivot_queries: List[InvestigationPivotQuery]
    false_positives: List[str]
    escalation_conditions: List[str]


def _default_mitre_mapping(incident_type: str, mitre_technique: str) -> IncidentMitreMappingNew:
    if incident_type == "credential_abuse":
        return IncidentMitreMappingNew(
            tactic="Credential Access",
            technique="T1110.003",
            technique_name="Password Spraying",
        )
    if incident_type == "possible_compromise":
        return IncidentMitreMappingNew(
            tactic="Execution",
            technique="T1059",
            technique_name="Command and Scripting Interpreter",
        )
    return IncidentMitreMappingNew(
        tactic="Credential Access",
        technique=mitre_technique or "T1110",
        technique_name="Brute Force",
    )


class IncidentNew(BaseModel):
    incident_id: str
    type: str  # "brute_force" | "credential_abuse"
    mitre_technique: str = "T1110"
    mitre: Optional[IncidentMitreMappingNew] = None
    playbook_id: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    dest: Optional[str] = None
    detection_id: Optional[str] = None
    severity: str  # low | medium | high | critical
    confidence: float  # 0.0-1.0 scale
    first_seen: str  # ISO 8601 UTC - earliest event in detection window
    last_seen: str  # ISO 8601 UTC - latest event in detection window
    affected_entities: List[str]  # sorted list of IPs and usernames involved
    evidence_count: int  # number of evidence events
    source_count: int  # distinct log source systems in evidence
    summary: str
    recommended_actions: List[str]
    explanation: IncidentExplanationNew
    subject: IncidentSubjectNew
    evidence: IncidentEvidenceNew
    investigation: Optional[IncidentInvestigationNew] = None
    correlation_flags: List[str] = Field(default_factory=list)
    chain_confidence: Optional[float] = None
    status: Literal["open", "acknowledged", "escalated", "closed"] = "open"
    assignee: Optional[str] = None
    source: Literal["auth", "ai_pipeline"] = "auth"
    ai_pipeline_data: Optional[AIPipelineMeta] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    resolution_reason: Optional[str] = None

    @model_validator(mode="after")
    def _populate_mitre_mapping(self):
        if self.mitre is None:
            self.mitre = _default_mitre_mapping(self.type, self.mitre_technique)
        if self.mitre_technique != self.mitre.technique:
            self.mitre_technique = self.mitre.technique
        return self
