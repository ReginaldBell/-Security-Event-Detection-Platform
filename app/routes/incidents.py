from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException

from app.services import incident_store
from app.services.demo_data import demo_incidents
from app.services.investigation_playbooks import get_investigation_playbook
from app.services.playbook_registry import get_playbook_by_technique
from app.services.siem_translation import incident_spl_bundle
from app.ai_pipeline.secure_context import (
    build_incident_context,
    list_ai_context_audit,
    record_ai_context_audit,
)
from app.schemas.api_contract import (
    IncidentAuditResponse,
    IncidentBulkPatchRequest,
    IncidentBulkPatchResponse,
    IncidentInvestigationResponse,
    IncidentListResponse,
    IncidentPatchRequest,
    IncidentSplResponse,
    LifecycleIncidentResponse,
    PlaybookResponse,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])
logger = logging.getLogger(__name__)


@router.get("/", response_model=IncidentListResponse)
def list_incidents():
    incidents = incident_store.list_incidents()
    return {
        "incident_count": len(incidents),
        "incidents": [incident_store.incident_to_response(inc) for inc in incidents],
    }


@router.get("/{incident_id}", response_model=LifecycleIncidentResponse)
def get_incident(incident_id: str):
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_store.incident_to_response(incident)


@router.get("/{incident_id}/spl", response_model=IncidentSplResponse)
def get_incident_spl(incident_id: str):
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_spl_bundle(incident)


@router.get("/{incident_id}/investigation", response_model=IncidentInvestigationResponse)
def get_incident_investigation(incident_id: str):
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.investigation is not None:
        return incident.investigation.model_dump(mode="json")
    return get_investigation_playbook(incident)


@router.get("/{incident_id}/playbook", response_model=PlaybookResponse)
def get_incident_playbook(incident_id: str):
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return get_playbook_by_technique(incident.mitre_technique)


@router.patch("/bulk", response_model=IncidentBulkPatchResponse)
def bulk_patch_incidents(payload: IncidentBulkPatchRequest):
    updated = []
    errors = []
    for incident_id in payload.incident_ids:
        try:
            incident = incident_store.transition_incident(
                incident_id=incident_id,
                status=payload.status,
                assignee=payload.assignee,
                resolution_reason=payload.resolution_reason,
                user=payload.user,
                reopen=payload.reopen,
            )
            updated.append(incident_store.incident_to_response(incident))
        except (KeyError, ValueError) as exc:
            errors.append({"incident_id": incident_id, "error": str(exc)})

    return {
        "updated_count": len(updated),
        "incidents": updated,
        "errors": errors,
    }


@router.post("/demo-seed", response_model=IncidentListResponse)
def seed_demo_incidents():
    for incident in demo_incidents():
        incident_store.upsert_incident(incident)
    incidents = incident_store.list_incidents()
    return {
        "incident_count": len(incidents),
        "incidents": [incident_store.incident_to_response(inc) for inc in incidents],
    }


@router.patch("/{incident_id}", response_model=LifecycleIncidentResponse)
def patch_incident(incident_id: str, payload: IncidentPatchRequest):
    try:
        incident = incident_store.transition_incident(
            incident_id=incident_id,
            status=payload.status,
            assignee=payload.assignee,
            resolution_reason=payload.resolution_reason,
            user=payload.user,
            reopen=payload.reopen,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Incident not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return incident_store.incident_to_response(incident)


@router.get("/{incident_id}/audit", response_model=IncidentAuditResponse)
def get_incident_audit(incident_id: str):
    if incident_store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"events": incident_store.list_audit_events(incident_id)}


@router.get("/{incident_id}/secure-context")
def get_secure_context(incident_id: str, user: str = "analyst_1"):
    started = time.perf_counter()
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    record_ai_context_audit(incident_id, user=user)
    context = build_incident_context(incident)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    logger.info(f"[SCB] context built in {elapsed_ms}ms incident_id={incident_id}")
    return context


@router.get("/{incident_id}/secure-context/audit")
def get_secure_context_audit(incident_id: str):
    if incident_store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"events": list_ai_context_audit(incident_id)}
