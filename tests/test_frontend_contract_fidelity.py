from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from app.routes import incidents as incidents_route
from app.schemas.api_contract import IncidentPatchRequest
from app.schemas.incident_new import IncidentNew
from app.services import incident_store


def _ts() -> str:
    return datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _incident() -> IncidentNew:
    ts = _ts()
    return IncidentNew(
        incident_id="inc_frontend_001",
        type="brute_force",
        mitre_technique="T1110",
        severity="high",
        confidence=0.90,
        first_seen=ts,
        last_seen=ts,
        affected_entities=["203.0.113.10", "alice", "svc-account"],
        evidence_count=8,
        source_count=1,
        summary="frontend contract incident",
        recommended_actions=["investigate", "contain"],
        explanation={
            "threshold": 5,
            "observed": 5,
            "window": "60s",
            "trigger_field": "username",
        },
        subject={"source_ip": "203.0.113.10", "username": "alice"},
        evidence={
            "window_start": ts,
            "window_end": ts,
            "counts": {"failures": 8},
            "timeline": [],
            "events": [],
        },
    )


def _reset_store(tmp_path: Path) -> None:
    incident_store._STORE_PATH = tmp_path / "runs" / "incidents.json"
    incident_store._incidents_by_id = {}
    incident_store._loaded = False
    incident_store.load_store()


def test_frontend_contract_explanation_and_confidence_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)
    incident_store.upsert_incident(_incident())

    response = incidents_route.list_incidents()
    assert response["incident_count"] == 1
    incident = response["incidents"][0]

    explanation = incident["explanation"]
    assert set(explanation.keys()) == {"threshold", "observed", "window", "trigger_field"}
    assert explanation["threshold"] == 5
    assert explanation["observed"] == 5
    assert explanation["window"] == "60s"
    assert explanation["trigger_field"] == "username"
    assert incident["mitre"]["tactic"] == "Credential Access"
    assert incident["mitre"]["technique"] == "T1110"
    assert incident["mitre"]["technique_name"] == "Brute Force"
    assert incident["playbook_id"] == "bruteforce_investigation"
    assert isinstance(incident["confidence"], float)
    assert 0.0 <= incident["confidence"] <= 1.0
    assert json.loads(json.dumps(explanation)) == explanation


def test_frontend_contract_lifecycle_transitions_are_reflected(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)
    incident_store.upsert_incident(_incident())

    acknowledged = incidents_route.patch_incident(
        "inc_frontend_001",
        IncidentPatchRequest(status="acknowledged"),
    )
    assert acknowledged["status"] == "acknowledged"
    assert acknowledged["updated_at"] is not None

    escalated = incidents_route.patch_incident(
        "inc_frontend_001",
        IncidentPatchRequest(status="escalated"),
    )
    assert escalated["status"] == "escalated"

    closed = incidents_route.patch_incident(
        "inc_frontend_001",
        IncidentPatchRequest(status="closed", resolution_reason="closed_from_ui"),
    )
    assert closed["status"] == "closed"
    assert closed["resolution_reason"] == "closed_from_ui"
    assert closed["created_at"] is not None
    assert closed["updated_at"] is not None

    fetched = incidents_route.get_incident("inc_frontend_001")
    assert fetched["status"] == "closed"
    assert fetched["resolution_reason"] == "closed_from_ui"


def test_frontend_contract_entity_list_is_renderable(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store.metrics_service, "increment_counter", lambda *_a, **_k: None)
    _reset_store(tmp_path)
    incident_store.upsert_incident(_incident())

    response = incidents_route.list_incidents()
    incident = response["incidents"][0]
    entities = incident["affected_entities"]

    assert isinstance(entities, list)
    assert len(entities) >= 2
    assert all(isinstance(item, str) and item for item in entities)


def test_frontend_incident_panel_uses_incident_playbook_endpoint():
    source = Path("dashboard/src/SecurityWorkflow.jsx").read_text(encoding="utf-8")

    assert "/incidents/${sidePanelInc.id}/playbook" in source
    assert "Loaded from this incident, not manual playbook selection." in source
    assert "IncidentPlaybookPanel" in source
    assert "View Full Playbook" in source
    assert "buildPlaybookDashboardHref" in source
    assert "view: 'playbooks'" in source
    assert "params.get('technique')" in source
    assert "Run Pivot" in source
    assert "/incidents/${sidePanelInc.id}/spl" not in source
    assert "/playbooks/${" not in source


def test_frontend_entity_drilldown_contract_is_clickable():
    source = Path("dashboard/src/SecurityWorkflow.jsx").read_text(encoding="utf-8")

    assert "goToEntityView(entityView, row.entity)" in source
    assert "goToEntityView('username', sidePanelInc.user)" in source
    assert "goToEntityView('source_ip', sidePanelInc.sourceIp)" in source
    assert "/entities/${selectedEntity.entity_type}/${encodeURIComponent(selectedEntity.entity_id)}" in source
    assert "setDashboardRoute({ view: 'entities', entity_type: entityType, entity_id: value })" in source
    assert "Entity Drilldown" in source
    assert "Linked Playbooks" in source
    assert "Investigation Pivots" in source
    assert "Related Incidents" in source
    assert "goToPlaybook(playbook)" in source
