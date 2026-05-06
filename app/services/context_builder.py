from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.schemas.incident_new import IncidentNew
from app.services import sla as sla_service
from app.services import correlation as correlation_service
from app.services.security_contracts import (
    SECURE_CONTEXT_ALLOWED_FIELDS,
    SECURE_CONTEXT_GUARANTEES,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _extract_mitre(incident: IncidentNew) -> dict:
    mitre = getattr(incident, "mitre", None)
    if mitre and isinstance(mitre, dict):
        return {"technique": mitre.get("technique"), "tactic": mitre.get("tactic")}
    return {}


def _signal_summary(incident: IncidentNew) -> dict:
    counts = {}
    try:
        counts = dict(incident.evidence.counts or {})
    except Exception:
        pass
    return {
        "evidence_count": incident.evidence_count,
        "source_count": incident.source_count,
        "affected_entity_count": len(incident.affected_entities),
        "counts": counts,
    }


def _timeline_summary(incident: IncidentNew) -> List[dict]:
    try:
        timeline = list(incident.evidence.timeline or [])
        return timeline[:10]
    except Exception:
        return []


def build_dce_context(
    incident: IncidentNew,
    risk: Optional[Dict[str, Any]] = None,
    corr: Optional[dict] = None,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    sla_block = sla_service.build_sla_block(incident, now)

    if corr is None:
        corr = correlation_service.get_incident_correlation(incident.incident_id) or {}

    context: Dict[str, Any] = {
        "incident_id": incident.incident_id,
        "type": incident.type,
        "status": incident.status,
        "assignee": incident.assignee,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "mitre": _extract_mitre(incident),
        "summary": incident.summary,
        "recommended_actions": incident.recommended_actions,
        "signal_summary": _signal_summary(incident),
        "timeline_summary": _timeline_summary(incident),
        "chain_correlation": {
            "chain_stage": corr.get("chain_stage", 0),
            "stages_observed": corr.get("stages_observed", []),
            "chain_complete": corr.get("chain_complete", False),
            "peer_incidents": corr.get("peer_incidents", []),
        },
        **sla_block,
    }

    if risk:
        context["risk_score"] = risk.get("risk_score")
        context["risk_level"] = risk.get("risk_level")
        context["risk_factors"] = risk.get("factors", {})
        context["effective_priority"] = risk.get("risk_level") or incident.severity

    context["_meta"] = {
        "generated_at": _utcnow(),
        "dce_version": "1.0",
        "guarantees": SECURE_CONTEXT_GUARANTEES,
        "allowed_fields": SECURE_CONTEXT_ALLOWED_FIELDS,
    }

    return context
