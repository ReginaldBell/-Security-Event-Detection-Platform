from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class ValidationResult(BaseModel):
    scenario_id: str
    expected: Optional[str] = None
    detected: bool
    detection_time: Optional[str] = None
    false_positive: bool = False
    matched_incident_id: Optional[str] = None
    unexpected_incident_ids: list[Optional[str]] = []
    assertion_failures: list[str] = []


class ScoreResult(BaseModel):
    score: int
    status: str  # "pass" | "fail" | "false_positive"
    latency_seconds: Optional[float] = None


class ValidationResponse(BaseModel):
    scenario: str
    scenario_name: Optional[str] = None
    validation: ValidationResult
    score: ScoreResult
    latency_seconds: float
    run_at: str
