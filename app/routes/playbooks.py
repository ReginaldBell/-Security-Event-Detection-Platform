from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas.api_contract import PlaybookListResponse, PlaybookResponse
from app.services import incident_store
from app.services.playbook_registry import (
    get_playbook_by_id,
    get_playbook_by_technique,
    has_playbook_id,
    list_playbooks,
)

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


@router.get("/", response_model=PlaybookListResponse)
def get_playbooks():
    playbooks = list_playbooks()
    return {
        "playbook_count": len(playbooks),
        "playbooks": playbooks,
    }


@router.get("/technique/{technique_id}", response_model=PlaybookResponse)
def get_playbook_for_technique(technique_id: str):
    return get_playbook_by_technique(technique_id)


@router.get("/incident/{incident_id}", response_model=PlaybookResponse)
def get_playbook_for_incident(incident_id: str):
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return get_playbook_by_technique(incident.mitre_technique)


@router.get("/{playbook_id}", response_model=PlaybookResponse)
def get_playbook(playbook_id: str):
    if not has_playbook_id(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return get_playbook_by_id(playbook_id)
