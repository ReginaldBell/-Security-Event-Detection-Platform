from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.schemas.incident_new import IncidentNew

logger = logging.getLogger(__name__)

_ENV_WEIGHT = {
    "production": 1.0,
    "prod": 1.0,
    "staging": 0.7,
    "dev": 0.4,
    "development": 0.4,
    "test": 0.3,
}

_ACTOR_WEIGHT = {
    "privileged": 1.0,
    "service_account": 0.85,
    "standard": 0.5,
    "unknown": 0.6,
}

_EVENT_WEIGHT = {
    "auth_failure": 1.0,
    "auth_success_after_failure": 0.95,
    "lateral_movement": 0.9,
    "privilege_escalation": 0.9,
    "data_access": 0.7,
    "network_scan": 0.6,
    "normal": 0.1,
}

_SEVERITY_BASE = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
}


def compute_risk(detection: Dict[str, Any], normalized: Any) -> int:
    t = detection["technique_id"]
    e = detection.get("evidence", {})

    if t in {"T1110", "T1110.003"}:
        score = 40
        if e.get("success"):
            score += 25
        if e.get("unique_ips", 0) > 2:
            score += 15
        return score

    if t == "T1003":
        return 90

    if t == "T1021":
        return 70

    if t == "T1059":
        return 75 if e.get("encoded") else 50

    return 30


def risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _env_weight(events: List[Dict]) -> float:
    for e in events:
        env = (e.get("environment") or e.get("env") or "").lower()
        if env in _ENV_WEIGHT:
            return _ENV_WEIGHT[env]
    return 0.6


def _actor_weight(events: List[Dict]) -> float:
    for e in events:
        if e.get("is_privileged"):
            return _ACTOR_WEIGHT["privileged"]
        role = (e.get("role") or "").lower()
        if "service" in role or "svc" in role:
            return _ACTOR_WEIGHT["service_account"]
    return _ACTOR_WEIGHT["standard"]


def _event_type_weight(incident_type: str) -> float:
    mapping = {
        "brute_force": "auth_failure",
        "credential_abuse": "auth_failure",
        "lateral_movement": "lateral_movement",
        "privilege_escalation": "privilege_escalation",
        "data_exfiltration": "data_access",
    }
    event_key = mapping.get(incident_type, "normal")
    return _EVENT_WEIGHT.get(event_key, 0.5)


def compute_risk_score(
    incident: IncidentNew,
    events: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    if events is None:
        events = []
        try:
            for e in incident.evidence.events:
                if isinstance(e, dict):
                    events.append(e)
        except Exception:
            pass

    base = _SEVERITY_BASE.get(incident.severity, 45)
    env_w = _env_weight(events)
    actor_w = _actor_weight(events)
    event_w = _event_type_weight(incident.type)
    confidence_w = (incident.confidence or 50) / 100.0

    raw = base * env_w * actor_w * event_w * confidence_w
    score = min(int(round(raw)), 100)

    return {
        "risk_score": score,
        "risk_level": _risk_level(score),
        "factors": {
            "env_weight": round(env_w, 2),
            "actor_weight": round(actor_w, 2),
            "event_type_weight": round(event_w, 2),
            "confidence_weight": round(confidence_w, 2),
            "severity_base": base,
        },
    }


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def compute_risk_for_run(run_id: str, runs_root: Path) -> Optional[Dict[str, Any]]:
    run_dir = runs_root / run_id
    incidents_path = run_dir / "incidents.json"
    events_path = run_dir / "sanitized.json"
    if not incidents_path.exists():
        return None

    try:
        incidents_raw = json.loads(incidents_path.read_text(encoding="utf-8"))
        events = json.loads(events_path.read_text(encoding="utf-8")) if events_path.exists() else []
    except Exception as exc:
        logger.warning(f"[RISK] Failed loading run {run_id}: {exc}")
        return None

    results = {}
    for raw in incidents_raw:
        try:
            incident = IncidentNew.model_validate(raw)
            results[incident.incident_id] = compute_risk_score(incident, events)
        except Exception as exc:
            logger.warning(f"[RISK] Skipping incident in {run_id}: {exc}")

    return results
