from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.event_models_new import NormalizedEventNew
from app.schemas.incident_new import IncidentNew


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LifecycleIncidentResponse(IncidentNew):
    is_stale: bool
    time_since_alert_seconds: int
    time_in_state_seconds: int
    sla_deadline_minutes: int
    sla_breached: bool
    sla_action_required: bool
    effective_priority: str
    valid_next_statuses: List[str]


class IngestResponse(_ContractModel):
    run_id: str
    event_count: int
    normalization_status: Literal["pending", "success", "failed"]
    detection_status: Literal["pending", "success", "failed"]
    incident_count: int
    incidents: List[LifecycleIncidentResponse]


class RunsMetaResponse(_ContractModel):
    created_at: str
    event_count: int
    envelope_source: Optional[str] = None
    schema_version: Optional[str] = None


class RunsNormalizedResponse(_ContractModel):
    event_count: int
    events: List[NormalizedEventNew]
    message: Optional[str] = None


class RunsIncidentsResponse(_ContractModel):
    incident_count: int
    incidents: List[IncidentNew]
    message: Optional[str] = None


class IncidentListResponse(_ContractModel):
    incident_count: int
    incidents: List[LifecycleIncidentResponse]


class IncidentPatchRequest(_ContractModel):
    status: Optional[Literal["open", "acknowledged", "escalated", "closed"]] = None
    assignee: Optional[str] = None
    user: str = "analyst_1"
    resolution_reason: Optional[str] = None
    reopen: bool = False


class IncidentBulkPatchRequest(_ContractModel):
    incident_ids: List[str]
    status: Optional[Literal["open", "acknowledged", "escalated", "closed"]] = None
    assignee: Optional[str] = None
    user: str = "analyst_1"
    resolution_reason: Optional[str] = None
    reopen: bool = False


class IncidentAuditEvent(_ContractModel):
    incident_id: str
    action: str
    user: str
    timestamp: str
    before_status: Optional[str] = None
    after_status: Optional[str] = None
    assignee: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)


class IncidentAuditResponse(_ContractModel):
    events: List[IncidentAuditEvent]


class IncidentBulkPatchResponse(_ContractModel):
    updated_count: int
    incidents: List[LifecycleIncidentResponse]
    errors: List[Dict[str, str]]


class SiemPivotQuery(_ContractModel):
    name: str
    description: str
    query: str


class IncidentSplResponse(_ContractModel):
    siem: Literal["splunk"]
    mapping_version: str
    detection_type: str
    query: str
    detection_query: str
    confidence: float
    notes: List[str]
    pivot_queries: List[SiemPivotQuery]
    cache_hit: bool
    cache_key: str
    generated_at: str
    last_used_at: str
    used_count: int


class IncidentInvestigationResponse(_ContractModel):
    questions: List[str]
    triage: List[str] = Field(default_factory=list)
    pivot_queries: List[SiemPivotQuery]
    false_positives: List[str]
    escalation_conditions: List[str]
    playbook_id: Optional[str] = None
    playbook_name: Optional[str] = None


class PlaybookDetections(_ContractModel):
    primary: str
    variants: List[str]


class PlaybookEscalation(_ContractModel):
    condition: str
    sla: str


class PlaybookRisk(_ContractModel):
    fields: List[str]


class PlaybookResponse(_ContractModel):
    id: str
    technique_id: str
    name: str
    deployment_context: Dict[str, str] = Field(default_factory=dict)
    detections: PlaybookDetections
    detection_logic: Dict[str, str] = Field(default_factory=dict)
    correlation: str = ""
    false_positive_logic: str = ""
    triage: List[str]
    false_positives: List[str]
    escalation: PlaybookEscalation
    escalation_criteria: List[str] = Field(default_factory=list)
    risk: Optional[PlaybookRisk] = None
    chain: List[str] = Field(default_factory=list)
    chain_steps: List[str] = Field(default_factory=list)
    chain_context: str = ""


class PlaybookListResponse(_ContractModel):
    playbook_count: int
    playbooks: List[PlaybookResponse]


class EntityRiskItem(_ContractModel):
    entity_type: Literal["username", "source_ip"]
    entity_id: str
    risk_score: float
    total_incidents: int
    open_incidents: int
    highest_confidence: float
    last_seen: Optional[str] = None


class EntityRiskResponse(_ContractModel):
    generated_at: str
    decay_half_life_hours: float
    increment_weights: Dict[str, float]
    entities: List[EntityRiskItem]


class EntityDetailResponse(_ContractModel):
    generated_at: str
    entity_type: Literal["username", "source_ip"]
    entity_id: str
    risk_score: float
    total_incidents: int
    open_incidents: int
    highest_confidence: float
    last_seen: Optional[str] = None
    incidents: List[LifecycleIncidentResponse]
    mitre_techniques: List[str]
    playbooks: List[PlaybookResponse]
    investigation_pivots: List[SiemPivotQuery]


class MetricsResponse(_ContractModel):
    events_ingested_total: int
    normalized_success_total: int
    telemetry_rejected_total: int
    missing_required_total: int
    events_by_source: Dict[str, int]
    incidents_total: Dict[str, int]
    runs_total: int
    incidents_created_total: int
    incidents_updated_total: int
    incidents_reopened_total: int
    incidents_closed_total: int
