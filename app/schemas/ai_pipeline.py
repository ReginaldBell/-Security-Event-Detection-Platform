from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AIPipelineRunRequest(_ContractModel):
    mode: Literal["mock", "live"] = "mock"
    security: Optional[Literal["OFF", "PARTIAL", "FULL"]] = None
    source_ip: str = "ai_pipeline_client"
    username: str = "ai_pipeline_user"


class AIDLPFinding(_ContractModel):
    detector: str
    finding_type: str
    severity: str
    confidence: float
    mitre: List[str]
    sha256_prefix: str


class AIPipelineMeta(_ContractModel):
    run_id: str
    attack: str
    mode: str
    llm_mode: str
    dlp_findings: List[AIDLPFinding] = Field(default_factory=list)
    dlp_finding_count: int = 0
    dlp_max_severity: Optional[str] = None
    risk_score: int = 0
    risk_action: str = "allow"
    combined_detection: bool = False


class AIPipelineResult(AIPipelineMeta):
    response: str
    success: bool
    detected: bool
    detection_reason: Optional[str] = None
    detection_layer: Optional[str] = None
    detection_layers: List[str] = Field(default_factory=list)
    latency_ms: float
    source: Literal["ai_pipeline"] = "ai_pipeline"
    incident_id: Optional[str] = None


class AIPipelineRunResponse(_ContractModel):
    status: Literal["complete"]
    run_id: str
    count: int
    results_path: str
    wazuh_log_path: str
    incident_count: int
    results: List[AIPipelineResult]


class AIPipelineResultsResponse(_ContractModel):
    run_id: Optional[str] = None
    result_count: int
    results: List[AIPipelineResult]


class AIPipelineEvent(_ContractModel):
    event_type: Literal["ai_pipeline_result"]
    result: AIPipelineResult


class AIPipelineError(_ContractModel):
    detail: str
    context: Optional[Dict[str, Any]] = None
