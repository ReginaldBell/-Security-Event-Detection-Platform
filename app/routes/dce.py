from __future__ import annotations

from fastapi import APIRouter, HTTPException
from typing import Any, Dict, List, Optional

from app.services import correlation as correlation_service
from app.services import incident_store
from app.services import risk_engine
from app.services.context_builder import build_dce_context

router = APIRouter(prefix="/dce", tags=["dce"])


@router.get("/chains", response_model=List[Dict[str, Any]])
def list_chains():
    return correlation_service.list_chains()


@router.get("/chains/{chain_id}", response_model=Dict[str, Any])
def get_chain(chain_id: str):
    chain = correlation_service.get_chain(chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail=f"Chain '{chain_id}' not found")
    return chain


@router.get("/audit", response_model=List[Dict[str, Any]])
def list_audit(incident_id: Optional[str] = None):
    return incident_store.list_audit_events(incident_id=incident_id)


@router.get("/risk/{incident_id}", response_model=Dict[str, Any])
def get_risk(incident_id: str):
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    result = risk_engine.compute_risk_score(incident)
    result["incident_id"] = incident_id
    return result


@router.get("/context/{incident_id}", response_model=Dict[str, Any])
def get_dce_context(incident_id: str):
    incident = incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    risk = risk_engine.compute_risk_score(incident)
    corr = correlation_service.get_incident_correlation(incident_id)
    return build_dce_context(incident, risk=risk, corr=corr)
