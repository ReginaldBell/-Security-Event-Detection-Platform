from __future__ import annotations

from typing import Any, Dict

from app.services.playbook_registry import get_playbook_by_technique
from app.services.risk_engine import compute_risk, risk_level


def build_incident(detection: Dict[str, Any], normalized: Any) -> Dict[str, Any]:
    playbook = get_playbook_by_technique(detection["technique_id"])

    score = compute_risk(detection, normalized)

    return {
        "mitre_technique": detection["technique_id"],
        "playbook_id": playbook["id"],
        "risk_score": score,
        "risk_level": risk_level(score),
        "subject": {
            "username": normalized.user,
            "source_ip": normalized.src,
            "host": normalized.dest,
        },
        "dest": normalized.dest,
        "summary": detection.get("summary"),
        "evidence": detection.get("evidence", {}),
    }
