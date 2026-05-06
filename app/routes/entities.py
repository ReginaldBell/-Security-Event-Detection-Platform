from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException

from app.schemas.api_contract import EntityDetailResponse
from app.schemas.incident_new import IncidentNew
from app.services import entity_risk as entity_risk_service
from app.services import incident_store
from app.services.playbook_registry import get_playbook_by_technique

router = APIRouter(prefix="/entities", tags=["entities"])

EntityType = Literal["username", "source_ip"]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _matches_entity(incident: IncidentNew, entity_type: EntityType, entity_id: str) -> bool:
    if entity_type == "username":
        return (
            incident.subject.username == entity_id
            or entity_id in set(incident.affected_entities)
        )
    return (
        incident.subject.source_ip == entity_id
        or entity_id in set(incident.affected_entities)
    )


def _entity_pivots(entity_type: EntityType, entity_id: str) -> list[dict[str, str]]:
    if entity_type == "username":
        return [
            {
                "name": "User Activity Timeline",
                "description": "Authentication and security activity for this user.",
                "query": f'index=auth_logs user="{entity_id}" | sort - _time',
            },
            {
                "name": "User Failure Breakdown",
                "description": "Failure reasons and source IPs tied to this user.",
                "query": f'index=auth_logs user="{entity_id}" result=failure | stats count by src_ip, reason',
            },
            {
                "name": "User Follow-on Execution",
                "description": "EDR process activity after authentication for this user.",
                "query": f'index=auth_logs OR index=edr user="{entity_id}" | sort - _time',
            },
        ]
    return [
        {
            "name": "Source IP Activity",
            "description": "All authentication events tied to this source IP.",
            "query": f'index=auth_logs src_ip="{entity_id}" | sort - _time',
        },
        {
            "name": "Source IP User Spread",
            "description": "Accounts targeted or used from this source IP.",
            "query": f'index=auth_logs src_ip="{entity_id}" | stats count by user, result',
        },
        {
            "name": "Source IP Follow-on Activity",
            "description": "Network or EDR activity associated with this source IP.",
            "query": f'index=network OR index=edr src_ip="{entity_id}" | sort - _time',
        },
    ]


def _build_entity_detail(entity_type: EntityType, entity_id: str) -> dict:
    incidents = incident_store.list_incidents()
    matching = [
        incident
        for incident in incidents
        if _matches_entity(incident, entity_type, entity_id)
    ]
    if not matching:
        raise HTTPException(status_code=404, detail="Entity not found")

    risk_rows = entity_risk_service.build_entity_risk_rows(incidents)
    risk_row = next(
        (
            row
            for row in risk_rows
            if row["entity_type"] == entity_type and row["entity_id"] == entity_id
        ),
        None,
    )

    response_incidents = [
        incident_store.incident_to_response(incident)
        for incident in sorted(matching, key=lambda inc: inc.last_seen, reverse=True)
    ]
    mitre_techniques = sorted(
        {
            incident.mitre_technique
            for incident in matching
            if isinstance(incident.mitre_technique, str) and incident.mitre_technique
        }
    )

    playbooks_by_id = {}
    for technique in mitre_techniques:
        playbook = get_playbook_by_technique(technique)
        playbooks_by_id[playbook["id"]] = playbook

    confidence_values = [float(incident.confidence) for incident in matching]
    last_seen = max((incident.last_seen for incident in matching), default=None)

    return {
        "generated_at": _utcnow(),
        "entity_type": entity_type,
        "entity_id": entity_id,
        "risk_score": float(risk_row["risk_score"]) if risk_row else 0.0,
        "total_incidents": int(risk_row["total_incidents"]) if risk_row else len(matching),
        "open_incidents": int(risk_row["open_incidents"]) if risk_row else sum(1 for incident in matching if incident.status == "open"),
        "highest_confidence": float(risk_row["highest_confidence"]) if risk_row else max(confidence_values, default=0.0),
        "last_seen": str(risk_row["last_seen"]) if risk_row and risk_row.get("last_seen") else last_seen,
        "incidents": response_incidents,
        "mitre_techniques": mitre_techniques,
        "playbooks": list(playbooks_by_id.values()),
        "investigation_pivots": _entity_pivots(entity_type, entity_id),
    }


@router.get("/{entity_type}/{entity_id}", response_model=EntityDetailResponse)
def get_entity_detail(entity_type: EntityType, entity_id: str):
    return _build_entity_detail(entity_type, entity_id)


@router.get("/{entity_id}", response_model=EntityDetailResponse)
def get_username_entity_detail(entity_id: str):
    return _build_entity_detail("username", entity_id)
